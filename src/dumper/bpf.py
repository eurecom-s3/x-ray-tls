"""
BPF related functions
"""

import ctypes as ct

from bcc import BPF


class TlsEvent(ct.Structure):
    _fields_ = [
        ("type", ct.c_uint8),
        ("ts_ns", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16)
    ]

class QuicEvent(ct.Structure):
    _fields_ = [
        ("type", ct.c_uint8),
        ("ts_ns", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("cid_server", ct.c_char * 16),
        ("cid_client", ct.c_char * 16)
    ]

def setup_bpf(interface: str) -> BPF:
    """
    Setup BPF
    """
    bpf = BPF(src_file="src/dumper/handshake_detector.c", debug=False)

    function_tls_handshake_detector = bpf.load_func("tls_handshake_detector", BPF.SOCKET_FILTER)
    BPF.attach_raw_socket(function_tls_handshake_detector, interface)
    # No packets will be forwarded using function_tls_handshake_detector.sock (on purpose)

    # Attach kernel events to functions
    bpf.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_entry")
    bpf.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
    bpf.attach_kprobe(event="ip4_datagram_connect", fn_name="trace_ip4_datagram_connect")

    return bpf
