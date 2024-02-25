"""
This module leverages Linux Traffic Control (tc) and eBPF
to delay ClientHello packets

TODO
- Check if clsact does not already exist
- Merge client_hello_detector.c with handshake_detector.c?
- Some programs will try IPv6 if IPv4 is delayed
"""

import logging

from bcc import BPF

logging.basicConfig(level=logging.DEBUG)

LOGGER = logging.getLogger(__name__)


bpf = BPF(src_file="server_hello_detector.c", debug=False)
fn = bpf.load_func("server_hello_detector", BPF.XDP)

bpf.attach_xdp("enx98e743da6832", fn)



try:
    while True:
        bpf.trace_print()
except KeyboardInterrupt:
    exit(0)
