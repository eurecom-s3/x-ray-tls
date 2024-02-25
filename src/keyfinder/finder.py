"""
See KeyFinder
"""

import difflib
import hashlib
import json
import logging
import math
import os
import platform
import shutil
import subprocess
import time
from tempfile import NamedTemporaryFile
from typing import Dict, List, Tuple, Union

from src.keyfinder.tshark_keytester import TsharkKeyTester
from src.models import TLSSession
from tqdm import tqdm

LOGGER = logging.getLogger(__name__)


MIN_DIFF_LENGTH_BYTES = int(os.environ.get("MIN_DIFF_LENGTH_BYTES")) if os.environ.get("MIN_DIFF_LENGTH_BYTES") else None


class KeyFinder():
    """
    Brute force TLS keys from memory dump
    """
    def __init__(self, tls_sessions: Dict[str, TLSSession], dump_directory: str) -> None:
        self.tls_sessions = tls_sessions
        self.dump_directory = dump_directory

        # Cache for SHA256 hashes of commands (e.g. SHA256 of /usr/bin/curl)
        self.command_hashes: Dict[str, str] = {}
    
    def close(self) -> None:
        pass
    
    def run(self) -> None:
        LOGGER.debug("Ready")
        while True:
            for key, tls_session in self.tls_sessions.items():
                if not tls_session.key_search_done and \
                        tls_session.key_search_ready and \
                        tls_session.memory_diff and \
                        tls_session.traffic_dump_filepath and \
                        tls_session.tls_version:

                    LOGGER.debug("Processing %s...", key)
                    tls_session.key_search_done = True

                    if tls_session.tls_version in ("1.2", "1.3"):
                        ssl_key_log_file_content = self.find_key(tls_session)

                        if ssl_key_log_file_content:
                            # Save TLS in pcap file
                            self.edit_pcap(
                                tls_session.traffic_dump_filepath,
                                ssl_key_log_file_content,
                                capture_comment=f"{tls_session.cmd} (pid {tls_session.pid})"
                            )

                            tls_session.tls_keys_found = True
                    else:
                        LOGGER.warning("TLS %s is not supported by KeyFinder", tls_session.tls_version)

            time.sleep(1)

    def find_key(self, tls_session: TLSSession) -> Union[str, None]:
        """
        Return keys in SSLKEYLOGFILE format (string) or None if not found
        """
        # Build a diff by concatenating all diffs from regions
        # Start with the heap as the key is often stored here
        diff_hex = "".join(
            region["diff"].hex()
            for region in tls_session.memory_diff.values()
            if region["path"] != "[heap]"
        )
        heap_region_hex = next(
            (
                region["diff"].hex()
                for region in tls_session.memory_diff.values()
                if region["path"] == "[heap]"
            ),
            None
        )
        if heap_region_hex:
            LOGGER.debug("Adding [heap] region first")
            diff_hex = heap_region_hex + diff_hex

        start_time = time.time()
        key_candidates = self.get_key_candidates(diff_hex, tls_session.cmd)
        entropy_filter_duration_ms = (time.time() - start_time) * 1000
        LOGGER.debug("get_key_candidates() took %0.2fs", entropy_filter_duration_ms/1000)

        keytester = TsharkKeyTester(
            tls_session.traffic_dump_filepath,
            tls_version="TLS13" if tls_session.tls_version == "1.3" else "TLS12",
            tls_ports=f"{tls_session.destination_port}"
        )
        try:
            start_time = time.time()
            keytester_results = keytester.find_key(
                tls_session.tls_client_random,
                key_candidates
            )
            keytester_results["brute_force_duration_ms"] = (time.time() - start_time) * 1000
            keytester_results["entropy_filter_duration_ms"] = entropy_filter_duration_ms

            LOGGER.debug("keytester results: %s", keytester_results)
            if keytester_results["success"]:
                LOGGER.info(
                    "Keys found in %0.2f seconds for %s",
                    keytester_results["brute_force_duration_ms"]/1000, tls_session.traffic_dump_filepath
                )
                self.store_stats(
                    diff_hex,
                    tls_session,
                    keytester_results,
                    len(key_candidates)
                )
                if tls_session.tls_version == "1.3":
                    # *_HANDSHAKE_TRAFFIC_SECRET must be present for tshark decryption to work
                    return f"SERVER_TRAFFIC_SECRET_0 {tls_session.tls_client_random} {keytester_results['server_secret_key']}\n" \
                    f"CLIENT_TRAFFIC_SECRET_0 {tls_session.tls_client_random} {keytester_results['client_secret_key']}\n" \
                    f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {tls_session.tls_client_random} {'0'*96}\n" \
                    f"SERVER_HANDSHAKE_TRAFFIC_SECRET {tls_session.tls_client_random} {'0'*96}\n"

                else: # TLS1.2
                    return f"CLIENT_RANDOM {tls_session.tls_client_random} {keytester_results['master_key']}\n"

            LOGGER.warning(
                "Keys not found for %s (%d / %s)",
                tls_session.traffic_dump_filepath,
                tls_session.pid, tls_session.cmd
            )
            self.store_stats(
                diff_hex,
                tls_session,
                keytester_results,
                len(key_candidates)
            )
            return None

        except Exception:
            LOGGER.exception("Fail to run keytester")

        finally:
            keytester.close()


    def get_key_candidates(self, diff_hex: str, cmd: str, entropy_threshold: float = 3.5) -> List[str]:
        """
        Return list of key candidates ordered from most likely to less likely
        """
        LOGGER.debug("Fiding key candidates...")
        key_candidates = [
            diff_hex[i:i + 96]
            for i in tqdm(range(0, len(diff_hex) - 96), leave=False)
            if self.entropy(diff_hex[i:i + 96]) >= entropy_threshold
        ]
        key_candidates.sort(key=self.entropy, reverse=True)
        LOGGER.debug("%d key candidates", len(key_candidates))
        return key_candidates


    def store_stats(
            self,
            diff_hex: str,
            tls_session: TLSSession,
            keytester_results: Dict[str, Union[bool, str, int]],
            key_candidates_length: int) -> None:
        """
        Store stats
        """

        stats = {
            "traffic_dump_filepath": tls_session.traffic_dump_filepath,
            "tls_client_random": tls_session.tls_client_random,
            "pid": tls_session.pid,
            "command": tls_session.cmd,
            "command_sha256": self.get_command_sha256(tls_session.cmd),
            "diff_size_kB": tls_session.get_diff_size_kB(),
            "platform": platform.platform(),
            "system": platform.system(),
            "machine": platform.machine(),
            "version": platform.version(),
            "timestamp": tls_session.creation_date.timestamp(),
            "key_candidates_length": key_candidates_length,
            "freeze_duration_ms": tls_session.freeze_duration_ms,
            "diff_duration_ms": tls_session.diff_duration_ms,
            "entropy_filter_duration_ms": keytester_results["entropy_filter_duration_ms"],
            "brute_force_duration_ms": keytester_results["brute_force_duration_ms"],
            "modified_region_paths": [
                region["path"]
                for region in tls_session.memory_diff.values()
                if region["path"]
            ],
            "baseline": tls_session.baseline
        }

        if tls_session.tls_version == "1.3":
            if keytester_results["success"]:
                client_start_key_index, client_pre_key, client_post_key = \
                    self.get_context(diff_hex, keytester_results["client_secret_key"])
                server_start_key_index, server_pre_key, server_post_key = \
                    self.get_context(diff_hex, keytester_results["server_secret_key"])
                
                stats.update(
                    {
                        "tls1.3": {
                            "client_key_position": keytester_results["client_key_position"],
                            "client_secret_key": keytester_results["client_secret_key"],
                            "server_key_position": keytester_results["server_key_position"],
                            "server_secret_key": keytester_results["server_secret_key"],
                            "client_start_key_index": client_start_key_index,
                            "client_pre_key": client_pre_key,
                            "client_post_key": client_post_key,
                            "server_start_key_index": server_start_key_index,
                            "server_pre_key": server_pre_key,
                            "server_post_key": server_post_key,
                            "client_secret_key_mem_path": self.get_memory_region_path(
                                keytester_results["client_secret_key"], tls_session
                            ),
                            "server_secret_key_mem_path": self.get_memory_region_path(
                                keytester_results["server_secret_key"], tls_session
                            )
                        },
                    }
                )
            else:
                stats.update({"tls1.3": {}})

        elif tls_session.tls_version == "1.2":
            master_key = keytester_results.get("master_key")
            if master_key:
                start_key_index, pre_key, post_key = self.get_context(diff_hex, master_key)

                stats.update(
                    {
                        "tls1.2": {
                            "master_key": master_key,
                            "start_key_index": start_key_index,
                            "pre_key": pre_key,
                            "post_key": post_key,
                            "key_position": keytester_results.get("key_position"),
                            "master_secret_mem_path": self.get_memory_region_path(master_key, tls_session)
                        },
                    }
                )
            else:
                stats.update({"tls1.2": {}})
        
        else:
            # This should never happen as this function should be called only with valid tls_session
            raise ValueError(f"Invalid TLS version '{tls_session.tls_version}'")

        with open(os.path.join(self.dump_directory, os.environ.get("STATS_FILENAME", "stats.json")), "at") as fd:
            fd.write(json.dumps(stats) + "\n")

    @staticmethod
    def get_context(diff_hex: str, key: str, context_size: int = 100) -> Tuple[int, str, str]:
        """
        Get pre/post key content
        """
        key_size = len(key)

        match = difflib.SequenceMatcher(
            None,
            diff_hex,
            key
        ).find_longest_match(
            0, len(diff_hex), 0, len(key)
        )
        assert match, "Key not found in diff: this should not happen here"

        start_key_index = match.a
        pre_key = diff_hex[match.a-context_size:match.a]
        post_key = diff_hex[match.a+key_size:match.a+key_size+context_size]

        return start_key_index, pre_key, post_key
    
    @staticmethod
    def get_memory_region_path(key_hex: str, tls_session: TLSSession) -> Union[str, None]:
        """
        Return the path of the region where the key was stored or None if not found
        """
        for diff in tls_session.memory_diff.values():
            if key_hex in diff["diff"].hex():
                return diff["path"]      
        return None

    @staticmethod
    def entropy(string: str) -> float:
        """
        Calculates the Shannon entropy of a string
        """
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

    def get_command_sha256(self, command: str) -> Union[str, None]:
        """
        Return the SHA256 hash of the binary of command
        """
        full_path = shutil.which(command)

        # If the command is not in PATH, which returns None
        if not full_path:
            LOGGER.warning("Command '%s' not found in PATH, unable to compute SHA256", command)
            return None

        binary_hash = self.command_hashes.get(full_path)
        if binary_hash:
            return binary_hash

        with open(full_path, "rb") as fd:
            binary_hash = hashlib.sha256(fd.read()).hexdigest()
        self.command_hashes[full_path] = binary_hash

        return binary_hash

    @staticmethod
    def edit_pcap(
        dump_file: str,
        ssl_key_log_file_content: str,
        capture_comment: str) -> None:
        """
        Insert TLS keys and comment into dump_file
        """
        editcap_path = os.path.join(
            os.environ.get("CUSTOM_WIRESHARK_BIN_PATH", "/opt/wireshark-custom/bin"),
            "editcap"
        )
        with NamedTemporaryFile(buffering=0) as keylog: 
            keylog.write(ssl_key_log_file_content.encode("ascii"))
            try:
                subprocess.run(
                    [
                        editcap_path,
                        "--inject-secrets", f"tls,{keylog.name}",
                        "--capture-comment", capture_comment,
                        dump_file, f"{dump_file}.new.pcapng"
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    check=True
                )
                os.rename(f"{dump_file}.new.pcapng", dump_file)
                LOGGER.info("TLS keys inserted into %s", dump_file)
            except subprocess.CalledProcessError as process_exception:
                LOGGER.exception(
                    "Fail to run editcap (%s): %s",
                    process_exception.args, process_exception.stderr
                )
