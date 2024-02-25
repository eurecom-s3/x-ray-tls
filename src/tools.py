"""
Helper functions
"""

import ctypes
import ctypes.util
import logging
import os
import pathlib
import time
from datetime import datetime
from typing import Dict

import docker

from src.models import TLSSession

LOGGER = logging.getLogger(__name__)


def fix_permissions_traffic_dumps(dump_directory: str, uid: int):
    """
    Change ownership of all traffic dumps to the given user
    """
    if dump_directory and uid:
        os.chown(dump_directory, uid, 0)
        os.chmod(dump_directory, 0o700)
        for dump_file in pathlib.Path(dump_directory).glob("*"):
            os.chown(dump_file, uid, 0)
            os.chmod(dump_file, 0o600)


def cleanup_old_tls_sessions(tls_sessions: Dict[str, TLSSession]):
    """
    Remove TLS sessions that are older than max_age or without associated PID
    """
    now = datetime.now()
    for key, tls_session in tls_sessions.items():
        # For session without PID after 300s (e.g., ignored commands)
        if tls_session.pid is None and (now - tls_session.creation_date).total_seconds() > 300:
            if os.path.isfile(tls_session.traffic_dump_filepath):
                os.remove(tls_session.traffic_dump_filepath)
            tls_sessions.pop(key)
            continue

        # Delete session with key found
        if tls_session.tls_keys_found:
            tls_sessions.pop(key)


def shutdown_cleanup(tls_sessions: Dict[str, TLSSession]):
    """
    Remove TLS sessions and associated dump files where TLS keys are not found
    """
    for _, tls_session in tls_sessions.items():
        if not tls_session.tls_keys_found and os.path.isfile(tls_session.traffic_dump_filepath):
            os.remove(tls_session.traffic_dump_filepath)


def setns(pid: int) -> None:
    """
    Enter in network ns of given pid
    """
    libc = ctypes.CDLL(ctypes.util.find_library('c'))
    fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    libc.setns(fd, 0)


def get_pid_container(container_id: str) -> int:
    """
    Get pid of init process of a docker container given its name or ID
    """
    client = docker.from_env()
    container = client.containers.get(container_id)
    return container.attrs["State"]["Pid"]


def nsenter_docker(container_id: str, timeout: int = 10) -> None:
    """
    Enter in network namespace of container_id (container name or ID)
    If the container does not exist yet, wait up to timeout seconds
    """
    pid = None
    for _ in range(timeout):
        try:
            pid = get_pid_container(container_id)
        except docker.errors.NotFound:
            LOGGER.warning("Docker container '%s' does not exist yet", container_id)
            time.sleep(1)
    if not pid:
        LOGGER.error("Fail to attach to Docker container '%s' after %ds", container_id, timeout)
        raise ValueError(f"Docker container '{container_id}' not found")
    
    setns(pid)
    LOGGER.debug("Binded to network namespace of Docker container '%s'", container_id)
