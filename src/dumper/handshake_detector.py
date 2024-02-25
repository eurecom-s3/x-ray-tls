"""
Memory dumper
"""

import concurrent.futures
import ctypes as ct
import logging
import multiprocessing
import os
import signal
import time
from collections import deque
from ipaddress import ip_address
from typing import Dict, Tuple, Union

from src.baseline.entropy_filter import baseline_entropy_filter
from src.dumper.bpf import QuicEvent, TlsEvent, setup_bpf
from src.memdiff.memdiffer import MemoryDiffer
from src.models import TLSSession

LOGGER = logging.getLogger(__name__)


class MemoryDumper():
    """
    Memory dumper
    """
    def __init__(
            self,
            interface: str,
            tls_sessions: Dict[str, TLSSession],
            max_workers: int = 5,
            allowed_commands: Tuple[str] = None) -> None:
        """
        interface: (str) Interface to listen on
        tls_sessions: (dict) fork-safe dict to store TLS sessions
        max_workers: (int) Number of processes or threads to use for async processing
        A same packet can be seen 2 times if server is on localhost (client -> lo and lo -> local server)
        """
        self.interface = interface
        self.tls_sessions = tls_sessions

        # Use ThreadPoolExecutor or ProcessPoolExecutor indiferently (same API)
        # FIXME: ProcessPoolExecutor raises TypeError: cannot pickle 'weakref' object
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)

        # Use manager for shared objets (mandatory for process pool)
        self.manager = multiprocessing.Manager()

        # Allowed commands
        # If not None, only process events with these commands
        self.allowed_commands = allowed_commands if allowed_commands != "*" else None

        # key is pid, value is a MemoryDiffer
        self.memdiffers: Dict[int, MemoryDiffer] = self.manager.dict()

        # Keep trace of stopped processes
        # key is pid, value is a counter representing the number of memory dumps ongoing
        self.stopped_pid: Dict[int, int] = self.manager.dict()

        # Keep trace when process was stopped
        # key is pid, value is a counter returned by time.perf_counter_ns()
        self.stop_ts: Dict[int, int] = self.manager.dict()

        # Per PID lock for memory operations
        self.locks: Dict[int, self.manager.Lock] = self.manager.dict()

        # Prevent duplicate events
        self.events = deque(maxlen=100)

    def run(self) -> None:
        """
        Wait for eBPF events and process them
        """
        bpf = setup_bpf(self.interface)

        # Use a 2-steps callback to allow process_tls_event to have self as argument
        def bpf_callback_tls_events(_, data, __):
            self.process_tls_event("tls", ct.cast(data, ct.POINTER(TlsEvent)).contents)
        def bpf_callback_quic_events(_, data, __):
            self.process_tls_event("quic", ct.cast(data, ct.POINTER(QuicEvent)).contents)
 
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
                raise KeyboardInterrupt


    def close(self):
        """
        Shutdown pool
        """
        self.pool.shutdown(wait=True)

        # Release all stopped programs, if any
        for pid, counter in self.stopped_pid.items():
            if counter > 0:
                LOGGER.info("Sending SIGCONT to pid %d because of shutdown", pid)
                os.kill(pid, signal.SIGCONT)


    def process_tls_event(self, event_type: str, event: Union[TlsEvent, QuicEvent]) -> None:
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
            f"[{event.ts_ns/1000000}ms] {event_type}Event: command={cmd} pid={event.pid} type={EVENT_TYPES[event_type][event.type]} "
            f"endpoints={ip_address(event.saddr)}:{event.sport}->{ip_address(event.daddr)}:{event.dport}"
        )

        if event.pid == 0:  # PID not found
            return

        # Sanity check: we expect only client to server packets
        # if not ip_address(event.saddr).is_private:
        #     LOGGER.error("%s is not a private IP: that should not happen", ip_address(event.saddr))
        #     return

        # Detect duplicate events
        event_id = f"{cmd}_{event.pid}_{event.type}_{event.saddr}_{event.sport}_{event.daddr}_{event.dport}"
        if event_id in self.events:
            LOGGER.warning("%s is a duplicate event: ignoring")
            return
        self.events.append(event_id)

        # Check if we are allowed to process this event
        # It is more efficient to test if an item is in the list than the opposite
        if self.allowed_commands:
            if cmd in self.allowed_commands:
                pass
            else:
                LOGGER.debug("Command '%s' not in allowed commands", cmd)
                return

        # Note: f"{event.pid}-{event.type}" is not unique
        # as a program can start multiple TLS sessions in parallel
        # So don't use that for packet duplicate detection

        #  TODO: Don't freeze on RST only
        if self.stopped_pid.get(event.pid, 0) == 0:
            LOGGER.debug("Sending SIGSTOP to pid %d (%s)", event.pid, cmd)
            os.kill(event.pid, signal.SIGSTOP)
            self.stop_ts[event.pid] = time.perf_counter_ns()
            self.stopped_pid[event.pid] = 0
        else:
            LOGGER.debug("pid %d (%s) already stopped", event.pid, cmd)
        self.stopped_pid[event.pid] += 1

        # Dump process memory and do the diff asynchronously to avoid blocking the main thread
        self.pool.submit(self.async_processing, event, cmd)
        #print(f.result())  # Comment this line to be really async else we wait for future to finish


    def async_processing(self, event: TlsEvent, cmd: str) -> None:
        """
        Process longer tasks asynchronously to avoid blocking the main thread
        """
        pid = event.pid
        tls_session_id = f"{ip_address(event.daddr)}_{event.dport}_{ip_address(event.saddr)}_{event.sport}"
        if event.type == 0:  # Don't compute which dump method should be used if it's not required
            dump_method = os.environ.get("DUMP_METHOD", "full-full")
            # Docker does not allow update of env vars of running containers
            # Therefore we allow to overwrite dump method with a custom file
            # This is used by benchmarking test suite
            dump_method_file = os.environ.get("DUMP_METHOD_FILE", "/tmp/dump_method")
            if os.path.isfile(dump_method_file):
                with open(dump_method_file, "rt") as fd:
                    dump_method = fd.read().strip()
            LOGGER.debug("Dump method: %s", dump_method)

        try:
            lock = self.locks.get(pid)
            if not lock:
                lock = self.manager.Lock()
                self.locks[pid] = lock

            with lock:
                if event.type == 0:  # Beginning of HS
                    memdiffer = self.memdiffers.get(pid)  # Can already exists if connections were made by same PID in the past
                    if not memdiffer:
                        memdiffer = MemoryDiffer(pid, dump_method)
                    memdiffer.snap(f"{tls_session_id}_begin", first=True)
                    self.memdiffers[pid] = memdiffer
                else:  # End of HS
                    try:
                        memdiffer = self.memdiffers.get(pid)
                        memdiffer.snap(f"{tls_session_id}_end", first=False)
                        self.memdiffers[pid] = memdiffer
                    except KeyError as pid_not_found:
                        LOGGER.exception("MemoryDiffer not found for PID %d", pid)
                        raise pid_not_found
                    except ValueError:
                        LOGGER.exception("Event ID already exists")

        except Exception:
            LOGGER.exception("Fail to run MemoryDiffer")

        finally:
            if self.stopped_pid[event.pid] == 1:
                LOGGER.debug("Sending SIGCONT to pid %d (%s)", event.pid, cmd)
                os.kill(event.pid, signal.SIGCONT)
                stop_duration_ms = (time.perf_counter_ns() - self.stop_ts[event.pid]) / 10**6
                LOGGER.debug("Process was stopped for %0.2f ms", stop_duration_ms)
            self.stopped_pid[event.pid] -= 1

        if event.type == 0:
            return  # Nothing to do more than above for a begin event

        # Compute the diff after the release of the process
        diff_start_time = time.time()
        diff = self.memdiffers[pid].diff(f"{tls_session_id}_begin", f"{tls_session_id}_end")
        diff_duration_ms = (time.time() - diff_start_time) * 1000

        baseline = {}
        if os.environ.get("ENABLE_BASELINE", "false") == "true":
            end_snapshot = memdiffer.get_snapshot(f"{tls_session_id}_end")
            if end_snapshot.dump_type == "full":
                try:
                    baseline = baseline_entropy_filter(
                        memdiffer.get_snapshot(f"{tls_session_id}_end")
                    )
                    LOGGER.debug("baseline: %s", baseline)
                except Exception:
                    LOGGER.exception("Fail to run baseline method")   

        # tls_sessions[tls_session_id] will be created by NetworkAnalyzer
        # If it's not yet populated, wait a bit and retry
        counter = 0
        while (tls_session := self.tls_sessions.get(tls_session_id)) is None:
            if counter > 1000:  # 10s
                LOGGER.error("Fail to find TLS session '%s'", tls_session_id)
                return
            if counter % 100 == 0:  # every second
                LOGGER.debug("Waiting for TLS session '%s'...", tls_session_id)
            time.sleep(0.01)
            counter += 1

        tls_session.pid = pid
        tls_session.cmd = event.comm.decode('ascii')
        tls_session.memory_diff = diff
        tls_session.diff_duration_ms = diff_duration_ms
        tls_session.baseline = baseline
        try:
            tls_session.freeze_duration_ms += stop_duration_ms
        except NameError:
            # stop_duration_ms may not be defined (if the process was stopped/unstopped by another thread)
            pass
        LOGGER.info("Length of the diff: %d kB", tls_session.get_diff_size_kB())


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    print(f"binding socket to '{interface}'")

    manager = multiprocessing.Manager()
    tls_sessions = manager.dict()

    memory_dumper = MemoryDumper(
        interface=interface,
        tls_sessions=tls_sessions,
    )
    try:
        memory_dumper.run()
    except KeyboardInterrupt:
        LOGGER.info("Exiting...")
        memory_dumper.close()
        exit(0)
