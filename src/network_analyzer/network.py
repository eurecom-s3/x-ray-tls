"""
See NetworkAnalyzer docstring
"""

import logging
import multiprocessing
import os
import pathlib
import struct
from datetime import datetime
from typing import Dict, Optional

import pyshark
from scapy.all import bind_layers, load_layer
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.layers.tls.extensions import TLS_Ext_SupportedVersion_SH
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.record import TLS, TLSApplicationData
from scapy.utils import PcapWriter
from src.models import TLSSession

LOGGER = logging.getLogger(__name__)


# scapy TLS layer must be loaded
load_layer("tls")

# Expect any TCP packet to be a TLS packet
bind_layers(TCP, TLS)

# TLS versions
TLS_VERSIONS = {
    0x0301: "1.0",
    0x0302: "1.1",
    0x0303: "1.2",
    0x0304: "1.3"
}


class NetworkAnalyzer():
    """
    Wrapper around pyshark
    """
    def __init__(
            self,
            interface: str,
            tls_sessions: Dict[int, TLSSession],
            manager: multiprocessing.Manager,
            dump_directory: Optional[str]):
        """
        interface: interface to sniff (-i of tshark)
        dump_directory: directory to save pcap files
        """

        self.interface = interface
        self.tls_sessions = tls_sessions
        self.manager = manager
        self.dump_directory = dump_directory
        if self.dump_directory:
            pathlib.Path(self.dump_directory).mkdir(parents=True, exist_ok=True)
            LOGGER.info("Traffic dumps will be saved to %s", self.dump_directory)
        else:
            LOGGER.warning("Traffic dumps will not be saved")

        # Key is TCP stream id
        # TODO: cleanup old writers
        self.pcap_writers: Dict[int, PcapWriter] = {}

        # TODO : Ensure packets are not truncated
        self.capture = pyshark.LiveCapture(
            interface=interface,
            display_filter="tcp",
            include_raw=True,
            use_json=True,
            tshark_path=os.path.join(
                os.environ.get("CUSTOM_WIRESHARK_BIN_PATH", "/opt/wireshark-custom/bin"),
                "tshark"
            )
        )
        if logging.getLogger().level <= logging.DEBUG:  # Take level from root logger
            self.capture.set_debug()  # Print tshark command

    def sniff(self):
        """
        Sniff packets on self.interface and store TLS sessions in self.tls_sessions
        This function does not return, you may want to run it in a thread
        """
        LOGGER.debug("Ready")
        for packet in self.capture.sniff_continuously():
            # All packets have a TCP layer as display_filter is tcp
            try:
                self.process_packet(packet)
            except Exception:
                LOGGER.exception("Fail to process packet")
                LOGGER.debug("packet: %s", packet.__dict__)
                # For now fail on error
                exit(1)

    def close(self) -> None:
        """
        Close fd
        """
        for _, pcap_writer in self.pcap_writers.items():
            pcap_writer.close()

    def process_packet(self, pyshark_packet: pyshark.packet.packet) -> bool:
        """
        Process one packet
        Return True if the packet was processed
        False if the packet was ignored (e.g., already started session)
        """
        try:
            stream_index = int(pyshark_packet["TCP"].stream)
        except KeyError:
            # Should not happen as tcp is in display_filter but...
            LOGGER.exception("No TCP layer")
            LOGGER.debug("pkg: %s", pyshark_packet)
            return None

        if hasattr(pyshark_packet, "eth"):
            linktype = 1 # LINKTYPE_ETHERNET
        else:
            # For tun interfaces
            linktype = 228 # LINKTYPE_IPV4

        if linktype == 1:
            pkg = Ether(pyshark_packet.get_raw_packet())
        else:
            pkg = IP(pyshark_packet.get_raw_packet())

        if not 'TCP' in pkg:
            LOGGER.error("Fail to parse packet with scapy")
            return None

        try:
            tls_records = pkg[TLS].msg
        except IndexError:
            # LOGGER.debug("No TLS layer")
            tls_records = []

        for record in tls_records:
            # Add TLSSession to self.tls_sessions on ClientHello
            # Adding already existing sessions are not relevant as keys cannot be guessed

            if isinstance(record, TLSClientHello):
                if self.dump_directory:
                    traffic_dump_filepath = os.path.join(
                        self.dump_directory,
                        f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_"
                        f"{pkg['IP'].dst}_{pkg['TCP'].dport}_"
                        f"{pkg['IP'].src}_{pkg['TCP'].sport}.pcap"
                    )
                    self.pcap_writers[stream_index] = PcapWriter(
                        traffic_dump_filepath,
                        linktype=linktype,
                        append=True,
                        sync=True
                    )
                else:
                    traffic_dump_filepath = None

                tls_session_dictkey = f"{pkg['IP'].dst}_{pkg['TCP'].dport}_{pkg['IP'].src}_{pkg['TCP'].sport}"

                self.tls_sessions[tls_session_dictkey] = self.manager.TLSSession(
                    tcp_stream_id=stream_index,
                    tls_client_random=(struct.pack('!I', record.gmt_unix_time) + record.random_bytes).hex(),
                    tls_client_session_id=record.sid.hex(),
                    source_ip=pkg['IP'].src,  # ClientHello is from client to server
                    source_port=pkg['TCP'].sport,
                    destination_ip=pkg['IP'].dst,
                    destination_port=pkg['TCP'].dport,
                    traffic_dump_filepath=traffic_dump_filepath
                )

                LOGGER.debug(
                    "ClientHello received",
                    extra={"tls_session_id": tls_session_dictkey}
                )

                break
                # Do no return here as a TLS packet may have multiple records (even for ClientHello?)

        # Match by stream id and not by dict key as src/dst may be swapped
        tls_session_dictkey, tls_session = next(
            (
                (key, tls_session)
                for key, tls_session in self.tls_sessions.items()
                if tls_session.tcp_stream_id == stream_index),
            (None, None)
        )
        if not tls_session:
            # Packet cannot be attached to an existing TLS session
            return False

        # Save packet to pcap file
        pcap_writer = self.pcap_writers.get(stream_index)
        if pcap_writer:
            pcap_writer.write(pyshark_packet.get_raw_packet())

        for record in tls_records:
            # LOGGER.debug("record: %s", record)

            if isinstance(record, TLSServerHello):
                LOGGER.debug(
                    "ServerHello received",
                    extra={"tls_session_id": tls_session_dictkey}
                )

                # Note: record.version is 0x0303 even in TLS 1.3: TLS 1.3 is defined in extensions
                tls_session.tls_version = TLS_VERSIONS.get(record.version, "Unknown")
                tls_session.tls_server_random = (struct.pack('!I', record.gmt_unix_time) + record.random_bytes).hex()
                tls_session.tls_server_session_id = record.sid.hex()
                tls_session.tls_cipher_suite = record.cipher

                supported_version_ext = [
                    ext for ext in record.ext
                    if isinstance(ext, TLS_Ext_SupportedVersion_SH)
                ]
                if supported_version_ext and supported_version_ext[0].version == 772:  # 0x0304:
                    tls_session.tls_version = "1.3"
                
                LOGGER.debug(
                    "TLS version: %s", tls_session.tls_version,
                    extra={"tls_session_id": tls_session_dictkey}
                )

            if not tls_session.key_search_ready and isinstance(record, TLSApplicationData):
                LOGGER.debug("ApplicationData received")
                tls_session.key_search_ready = True

            # TODO: cleanup self.pcap_writers when the TCP connection is closed and
            # close PcapWriter (instead of sync=True)


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <interface> [<dump_directory>]")
        exit(2)
    interface = sys.argv[1]
    dump_directory = sys.argv[2] if len(sys.argv) > 2 else None
    LOGGER.info(
        "interface: %s, dump_directory: %s",
        interface, dump_directory
    )
    network_analyzer = NetworkAnalyzer(
        interface=interface,
        tls_sessions={},
        dump_directory=dump_directory
    )
    try:
        network_analyzer.sniff()
    except KeyboardInterrupt:
        LOGGER.info("Exiting...")
        network_analyzer.close()
        exit(0)
