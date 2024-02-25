"""
Shared functions
"""

import json
import logging
import os
from typing import Dict, List

import docker

LOGGER = logging.getLogger()


DOCKER_CLIENT = docker.from_env()

try:
    TLS_TRAFFIC_ANALYZER_CONTAINER = DOCKER_CLIENT.containers.get("tls-traffic-analyzer")
    TLS_CLIENTS_CONTAINER = DOCKER_CLIENT.containers.get("my-tls-clients")
except docker.errors.NotFound:
    pass  # Containers don't exist yet for selenium tests

DUMP_METHODS = ["full-full", "rst-partial", "rst-partial-rst", "full-partial", "full-partial-rst"]

URL_TLS_12_ONLY = "https://tls-v1-2.badssl.com:1012"
URL_TLS_13_ONLY = "https://tls13.akamai.io:443"


def tls_decryption_success(n_sessions: int = 1, timeout: int = 180, stats_file: str = "/dumps/stats.json") -> bool:
    """
    Wait for at least n_sessions
    Return True if n_sessions TLS sessions were decrypted before timeout
    Return False if no TLS session was decrypted or at least one decryption fails
    """
    TLS_TRAFFIC_ANALYZER_CONTAINER = DOCKER_CLIENT.containers.get("tls-traffic-analyzer")

    # Read and delete stats.json
    _, output = TLS_TRAFFIC_ANALYZER_CONTAINER.exec_run(
        [
            "bash",
            "-c",
            f"for i in {{1..{timeout}}}; do [ -e '{stats_file}' ] && [ $(cat {stats_file} | wc -l) -ge {n_sessions} ] && break || sleep 1; done "
            f"&& sleep 1 && cat {stats_file} && rm {stats_file}"
        ],
        stdout=True
    )

    success_count = 0
    sessions = []
    for line in output.decode("ascii").split("\n"):
        if not line:
            continue
        try:
            stats_session = json.loads(line)
        except json.decoder.JSONDecodeError as e:
            if "No such file or directory" in line:
                LOGGER.error("No session was decrypted (no stats file)")
                return False, None
            LOGGER.exception("Fail to parse stats.json: line='%s'", line)
            raise e

        key_found = stats_session.get("tls1.2", {}).get("master_key") or \
            (stats_session.get("tls1.3", {}).get("client_secret_key") and stats_session.get("tls1.3", {}).get("server_secret_key"))

        if key_found:
            sessions.append(stats_session)
            success_count += 1
        else:
            return False, None
    
    if n_sessions and n_sessions != success_count:  # Ensure that no sessions have been missed
        LOGGER.error("Expecting %d sessions, got %d sessions", n_sessions, success_count)
        return False, None
    if not success_count:
        LOGGER.error("No successful session")
        return False, None

    return True, sessions


def save_benchmark_results(test_case: str, dump_method: str, sessions: List[Dict[str, any]]):
    """
    Store benchmark results
    """
    results_file = os.environ.get("BENCHMARK_RESULTS_FILE")
    if not results_file:
        return

    with open(results_file, "at") as fd:
        for session_idx, session in enumerate(sessions, start=1):
            doc = {
                "test_case": test_case,
                "dump_method": dump_method,
                "session_idx": session_idx,
                "session_idx_max": len(sessions),
                **session
            }
            fd.write(json.dumps(doc) + "\n")

    LOGGER.debug("Results saved in %s", results_file)
