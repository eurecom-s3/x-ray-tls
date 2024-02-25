"""
Measure T_stop
"""

import ctypes as ct
import logging
import multiprocessing
import os
import socket
import ssl
import time
from ipaddress import ip_address
from typing import Dict, Union

from src.dumper.bpf import QuicEvent, TlsEvent, setup_bpf

logging.basicConfig(level=logging.INFO)

LOGGER = logging.getLogger()


# Share a dict betwwen processes
MANAGER = multiprocessing.Manager()
SESSIONS: Dict[int, int] = MANAGER.dict()  # PID: perf_counter_ns() on ClientHello

OUTPUT_FILE = "tools/T_stop_estimation/results.csv"


def process_tls_event(type: str, event: Union[TlsEvent, QuicEvent], sessions: Dict[int, int]) -> None:
    """
    Process BPF event
    """
    cmd = event.comm.decode('ascii')

    EVENT_TYPES = {
        "tls": {
            0: "HTTPS-start",
            1: "HTTPS-end"  # TLS 1.2 or TLS 1.3 with midlebox compatibility
        },
        "quic": {
            0: "QUIC-start",
            1: "QUIC-end"
        }
    }

    LOGGER.debug(
        f"[{event.ts_ns/1000000}ms] {type}Event: command={cmd} pid={event.pid} type={EVENT_TYPES[type][event.type]} "
        f"endpoints={ip_address(event.saddr)}:{event.sport}->{ip_address(event.daddr)}:{event.dport}"
    )

    if event.type != 0:  # We care only about *-start events
        return

    perf_counter_ns = time.perf_counter_ns()
    clock_monotonic = time.clock_gettime_ns(time.CLOCK_MONOTONIC)

    # We care only about ClientHello initiated by this program
    if not sessions.get(event.pid):
        return

    init_to_stop_ms = (perf_counter_ns - sessions[event.pid])/1000000
    ebpf_to_userspace_ms = (clock_monotonic - event.ts_ns)/1000000
    load_avg_1m = os.getloadavg()[0]

    LOGGER.info(
        "PID %d: load_avg_1m=%0.2f, init_to_stop=%0.3fms, ebpf_to_userspace=%0.3fms",
        event.pid, load_avg_1m, init_to_stop_ms, ebpf_to_userspace_ms
    )

    with open(OUTPUT_FILE, "at") as fd:
        fd.write("%0.3f,%0.3f,%0.3f\n" % (load_avg_1m, init_to_stop_ms, ebpf_to_userspace_ms))


def consume_ebpf_events(interface: str, sessions: Dict[int, int]) -> None:
    """
    Fetch eBPF events
    """
    bpf = setup_bpf(interface)

    # Use a 2-steps callback as used in the real program
    def bpf_callback_tls_events(_, data, __):
        process_tls_event("tls", ct.cast(data, ct.POINTER(TlsEvent)).contents, sessions)
    def bpf_callback_quic_events(_, data, __):
        process_tls_event("quic", ct.cast(data, ct.POINTER(QuicEvent)).contents, sessions)

    # loop forever on events
    bpf["tls_events"].open_ring_buffer(bpf_callback_tls_events)
    bpf["quic_events"].open_ring_buffer(bpf_callback_quic_events)
    LOGGER.debug("Ready")
    while 1:
        try:
            bpf.ring_buffer_consume()
            # bpf.trace_print()  # To print bpf_trace_printk messages
        except KeyboardInterrupt:
            LOGGER.debug("eBPF buffer consumer stopped")
            exit(0)


def send_client_hello(hostname: str, sessions: Dict[int, int]):
    """
    Send a ClientHello packet after opening a TCP socket
    Send time is taken on TLS handshark start (not TCP start)
    """
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=2) as sock:
        LOGGER.debug("Socket open")
        sessions[os.getpid()] = time.perf_counter_ns()
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            LOGGER.info("%s established to %s", ssock.version(), hostname)


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    LOGGER.info("Binding socket to %s", interface)

    # Test server (should support TLS)
    hostname = "www.google.fr"

    # Write CSV headers
    with open(OUTPUT_FILE, "wt") as fd:
        fd.write("load_average_1m,init_to_stop_ms,ebpf_to_userspace_ms\n")

    try:
        ebpf_process = multiprocessing.Process(target=consume_ebpf_events, args=(interface, SESSIONS))
        ebpf_process.start()
        time.sleep(2)  # Wait for eBPF to be ready      
        while True:
            p = multiprocessing.Process(target=send_client_hello, args=(hostname, SESSIONS))
            p.start()
            p.join()
            time.sleep(2)
    except KeyboardInterrupt:
        LOGGER.info("Exiting...")
        ebpf_process.terminate()
        p.terminate()
        exit(0)
