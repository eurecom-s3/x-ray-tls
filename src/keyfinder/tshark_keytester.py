"""
See TsharkKeyTester docstring
"""

import logging
import os
import subprocess
from tempfile import NamedTemporaryFile
from typing import List, Optional, Tuple

LOGGER = logging.getLogger(__name__)


class TsharkKeyTester():
    """
    This module implements a TLS session key brute force based on a custom version of tshark
    TODO: use another user than nobody else keys and traffic dump
    are accessible to every process running as nobody
    """
    def __init__(
            self,
            dump_file: str,
            tls_version: str,
            tls_ports: str = "443,8443"
        ) -> None:
        """
        Tshark will only try to decrypt TLS for packets with dport in tls_ports
        tls_version: "TLS12", "TLS13" or "QUIC"
        """
        self.original_dump_file = dump_file
        assert tls_version in ("TLS12", "TLS13", "QUIC"), f"Bad TLS version '{tls_version}'"
        self.tls_version = tls_version
        self.tls_ports = tls_ports

        self.tshark = os.path.join(
            os.environ.get("CUSTOM_WIRESHARK_BIN_PATH", "/opt/wireshark-custom/bin"),
            "tshark"
        )

        self.dump_file = NamedTemporaryFile(buffering=0, mode="wb")
        with open(self.original_dump_file, "rb") as fd:
            self.dump_file.write(fd.read())
        os.chown(self.dump_file.name, 65534, 65534)

    def close(self):
        """
        Delete temporary files
        """
        self.dump_file.close()

    def find_key(
            self,
            client_random: str,
            key_candidates_hex: List[str],
            tls_debug: bool = False) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        Find TLS key
        Return None if not found
        raise Exception on error
        """
        LOGGER.debug(
            "Checking %d keys (client random '%s') for %s",
            len(key_candidates_hex), client_random, self.original_dump_file
        )
        with NamedTemporaryFile(buffering=0) as keylog, \
                NamedTemporaryFile(mode="wb", buffering=0) as keys_fd:

            # Write a dummy keylog file to enable TLS decrypter in tshark
            os.chown(keylog.name, 65534, 65534)
            if self.tls_version == "TLS13" or self.tls_version == "QUIC":
                keylog.write(
                    (f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {client_random} " + "0"*96 + "\n").encode("ascii")
                )
                keylog.write(
                    (f"SERVER_HANDSHAKE_TRAFFIC_SECRET {client_random} " + "0"*96 + "\n").encode("ascii")
                )
                keylog.write(
                    (f"CLIENT_TRAFFIC_SECRET_0 {client_random} " + "0"*96 + "\n").encode("ascii")
                )
                keylog.write(
                    (f"SERVER_TRAFFIC_SECRET_0 {client_random} " + "0"*96 + "\n").encode("ascii")
                )
            else:  # self.tls_version == "TLS12"
                keylog.write(
                    (f"CLIENT_RANDOM {client_random} " + "0"*96 + "\n").encode("ascii")
                )

            # Write key candidates
            os.chown(keys_fd.name, 65534, 65534)
            for key in key_candidates_hex:
                keys_fd.write(bytes.fromhex(key))

            args = [
                self.tshark,
                "-r", self.dump_file.name,
                "-o", f"tls.keylog_file:{keylog.name}",
                "-o", f"http.tls.port:{self.tls_ports}"
            ]
            if tls_debug:
                args.extend(["-o", "tls.debug_file:-"])
            p = subprocess.run(
                args=args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=self.set_user,
                env={
                    **os.environ,
                    f"BRUTEFORCE_{self.tls_version}_FILE": keys_fd.name,
                    "HOME": "/nonexistent",
                    "USER": "nobody"
                }
            )

            if p.returncode != 0:
                LOGGER.error("tshark exited with code %s", p.returncode)
                LOGGER.debug("tshark stdout: %s", p.stdout.decode("utf-8"))
                LOGGER.debug("tshark stderr: %s", p.stderr.decode("utf-8"))
                raise Exception(f"tshark exited with code {p.returncode}")

            last_line = p.stdout.decode("utf-8").split("\n")[-1]
            if not last_line.startswith("bruteforce_result"):
                LOGGER.error(
                    "No brute force result in last line: "
                    "Keys not found? Is '%s' the custom version of tshark? Or traffic dump is incomplete?",
                    self.tshark
                )
                LOGGER.debug("tshark stdout: %s", p.stdout.decode("utf-8"))
                LOGGER.debug("tshark stderr: %s", p.stderr.decode("utf-8"))
                return {
                    "success": False
                }
            
            if self.tls_version == "TLS13" or self.tls_version == "QUIC":
                client_key_position, client_secret_key, \
                    server_key_position, server_secret_key = last_line.split("=")[1].split(";")
                return {
                    "success": True,
                    "client_key_position": int(client_key_position),
                    "client_secret_key": client_secret_key,
                    "server_key_position": int(server_key_position),
                    "server_secret_key": server_secret_key
                }
            elif self.tls_version == "TLS12":
                key_position, master_key = last_line.split("=")[1].split(";")
                return {
                    "success": True,
                    "key_position": int(key_position),
                    "master_key": master_key
                }


    @staticmethod
    def set_user():
        """
        It's bad to run complex code like TLS decryption as root
        """
        os.setgid(65534)
        os.setuid(65534)


if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)

    keytester = TsharkKeyTester(
        dump_file="tests/resources/quic/dump1.pcap",
        tls_version="QUIC"
    )
    try:
        good = keytester.find_key(
            client_random="A5CE1B7E49B77BDA031957DB29E0F114903E72B0FB772562543B5CFAD95A9E46",
            key_candidates_hex=[
                "ba144282d26290ab8fcbce3651bc016c7e29e2a8922c9ca26e00e5eca3c05e1d",
                "9C5D43DCAE9E03E775CBDB808C6254BAF453D593EA4C4AEF676335421ADD336E",  # Client traffic secret
                "ba144282d26290ab8fcbce3651bc016c7e29e2a8922c9ca26e00e5eca3c05e1d",
                "FFE4E6AFF7886386F812EED79E84F472BE81F7905DC6CA012F90A45C2086E05C",  # Server traffic secret
                "ca144282d26290ab8fcbce3651bc016c7e29e2a8922c9ca26e00e5eca3c05e1d"
            ]
        )
        print(json.dumps(good, indent=4))

        bad = keytester.find_key(
            client_random="A5CE1B7E49B77BDA031957DB29E0F114903E72B0FB772562543B5CFAD95A9E46",
            key_candidates_hex=[
                "ba144282d26290ab8fcbce3651bc016c7e29e2a8922c9ca26e00e5eca3c05e1d",
                "ca144282d26290ab8fcbce3651bc016c7e29e2a8922c9ca26e00e5eca3c05e1d",
                "ea144282d26290ab8fcbce3651bc016c7e29e2a8922c9ca26e00e5eca3c05e1d"
            ]
        )
        print(json.dumps(bad, indent=4))

    finally:
        keytester.close()

    exit(0)

    keytester = TsharkKeyTester(
        dump_file="tests/resources/tls1.2/dump1.pcap",
        tls_version="TLS12"
    )
    try:
        # 4f325... is the good key
        good = keytester.find_key(
            client_random="af687dbf4004cea24074bb94fa93da4e1e8b3dbf6826ed5ba898ee7cc393d1dd",
            key_candidates_hex=[
                "3f325075443842be887367b14b464642117ca7555c6aa5af85b3f2f2f920e2e67da8225d329c611c3fe4c18d8c9f9777",
                "4f325075443842be887367b14b464642117ca7555c6aa5af85b3f2f2f920e2e67da8225d329c611c3fe4c18d8c9f9777",
                "5f325075443842be887367b14b464642117ca7555c6aa5af85b3f2f2f920e2e67da8225d329c611c3fe4c18d8c9f9777"
            ]
        )
        print(json.dumps(good, indent=4))

        bad = keytester.find_key(
            client_random="af687dbf4004cea24074bb94fa93da4e1e8b3dbf6826ed5ba898ee7cc393d1dd",
            key_candidates_hex=[
                "7f325075443842be887367b14b464642117ca7555c6aa5af85b3f2f2f920e2e67da8225d329c611c3fe4c18d8c9f9777",
                "8f325075443842be887367b14b464642117ca7555c6aa5af85b3f2f2f920e2e67da8225d329c611c3fe4c18d8c9f9777",
                "9f325075443842be887367b14b464642117ca7555c6aa5af85b3f2f2f920e2e67da8225d329c611c3fe4c18d8c9f9777"
            ]
        )
        print(json.dumps(bad, indent=4))

    finally:
        keytester.close()
    
    keytester = TsharkKeyTester(
        dump_file="tests/resources/tls1.3/dump1.pcap",
        tls_version="TLS13"
    )
    try:
        good = keytester.find_key(
            client_random="d0172e9899b148b747dc9245c8ba9b89087a8d6d0a474c9c8eae055467200d65",
            key_candidates_hex=[
                "edd575a81aa914e526ace817d0f2600ae2d3e70c5347df78b7c69abb678bf62b9d074ea0b04585e226f31dd00fb4b200",
                "edd575a813a914e526ace817d0f2600ae2d3e70c5347df78b7c69abb678bf62b9d074ea0b04585e226f31dd00fb4b200",
                "e7655813d7f5580dcf2e6e51c0c68fe93246b83b5bc30a4ac2a2e69e2da1ec2195a7e992c4a23847f329aa37da09df08",
                "e7655d13d7f5580dcf2e6e51c0c68fe93246b83b5bc30a4ac2a2e69e2da1ec2195a7e992c4a23847f329aa37da09df08"
            ]
        )
        print(json.dumps(good, indent=4))

        bad = keytester.find_key(
            client_random="d0172e9899b148b747dc9245c8ba9b89087a8d6d0a474c9c8eae055467200d65",
            key_candidates_hex=[
                "5ddffa100ccc33b752f543954a3567b0a9df0932de20700c9565a67db10f818ea25d47ee843b24f48fb14f9c58b41d1b",
                "5ddffa100cdc33b752f543954a3567b0a9df0932de20700c9565a67db10f818ea25d47ee843b24f48fb14f9c58b41d1b",
                "5ddffa100ccc33b75df543954a3567b0a9df0932de20700c9565a67db10f818ea25d47ee843b24f48fb14f9c58b41d1b"
            ]
        )
        print(json.dumps(bad, indent=4))

    finally:
        keytester.close()
