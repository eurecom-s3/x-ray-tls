"""
Models
"""

import dataclasses
from datetime import datetime
import io


@dataclasses.dataclass
class TLSSession():
    """
    This class represents a TLS session
    """

    # Store creation date to allow cleaning of old sessions
    creation_date: datetime = dataclasses.field(default_factory=datetime.now)

    # Fixed by tcpdump (1 for first flow seen by tcpdump, etc.)
    tcp_stream_id: int = None

    # IP/port src/dst
    source_ip: str = None
    source_port: int = None
    destination_ip: str = None
    destination_port: int = None

    # TLS version
    tls_version: str = None

    # TLS random
    tls_client_random: str = None
    tls_server_random: str = None

    # TLS session id
    # If they are the same, a previous session is reused, else it's a new session
    tls_client_session_id: str = None
    tls_server_session_id: str = None

    # Cipher suite
    tls_cipher_suite: str = None

    # True is keys are found (master key for TLS 1.2, client/server app traffic keys for TLS 1.3)
    tls_keys_found: bool = False

    # Prevent multiple key searches if not found the first time
    # (brute force is deterministic...)
    key_search_done: bool = False

    # Set to true when traffic dump contains enough data for keyfinder to work#
    # i.e., at least 1 Application Data packet
    key_search_ready: bool = False

    # Traffic dump
    traffic_dump_filepath: str = None

    # Process related variables
    pid: int = None
    cmd: str = None
    memory_diff: io.BytesIO = None

    # Durations
    freeze_duration_ms: float = 0
    diff_duration_ms: float = 0

    # Baseline
    baseline = None

    def get_diff_size_kB(self):
        return round(
            sum(
                (len(region["diff"]) for region in self.memory_diff.values())
            )/1024
        )

    def __repr__(self):
        """
        Represent only some fields to avoid filling the console
        """
        return f"""<TLSSession
{self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}
TLS {self.tls_version} - Cipher suite {self.tls_cipher_suite}
Client/Server randoms: {self.tls_client_random} / {self.tls_server_random}
Client/Server session IDs: {self.tls_client_session_id} / {self.tls_server_session_id}
PID: {self.pid} ({self.cmd})
Key search ready: {'yes' if self.key_search_ready else 'no'}
Key search done: {'yes' if self.key_search_done else 'no'}
Key found: {'yes' if self.tls_keys_found else 'no'}
Memory diff size: {self.get_diff_size_kB() if self.memory_diff else "(No diff)"}kB
Total stopped time: {round(self.freeze_duration_ms, 2)}ms
Traffic dump filepath: {self.traffic_dump_filepath}
Creation date: {self.creation_date}>
---"""
