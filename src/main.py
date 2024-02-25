"""
Main script
"""

import argparse
import logging
import multiprocessing
import os
import sys
import time
from multiprocessing.managers import BaseManager, DictProxy, NamespaceProxy
from tempfile import TemporaryDirectory
from typing import Dict

import src.dumper.handshake_detector
import src.keyfinder.finder
import src.network_analyzer.network
from src.models import TLSSession
from src.tools import (cleanup_old_tls_sessions, fix_permissions_traffic_dumps,
                       nsenter_docker, shutdown_cleanup)

logging.basicConfig(
    format="%(asctime)s %(processName)s %(filename)20s:%(funcName)s %(levelname)10s %(message)s",
    level=logging.DEBUG  # Will be ajusted based on CLI args
)

LOGGER = logging.getLogger(__name__)

parser = argparse.ArgumentParser(
    description="TLS Traffic Analyzer",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter  # Add default values to help
)
parser.add_argument(
    "-v", "--verbose",
    help="-v for INFO, -vv for DEBUG (default to WARNING)",
    action="count",
    default=0
)
parser.add_argument(
    "-i", "--interface",
    type=str,
    help="Network interface to sniff on",
    default="eth0"
)
parser.add_argument(
    "-o", "--dump-directory",
    type=str,
    help="Directory to store traffic dumps (None creates a temporary directory)",
    default=None
)
parser.add_argument(
    "--commands",
    type=str,
    help="Limit TLS traffic analysis to these commands (comma separated). '*' for all commands",
    default="*"
)
parser.add_argument(
    "-u", "--chown-traffic-dumps",
    type=int,
    help="Chown traffic dumps to the given user (disabled on None)",
    default=None
)
parser.add_argument(
    "-c", "--container",
    type=str,
    help="Limit TLS traffic analysis to given Docker container (name or ID). Target processes running on host if None.",
    default=None
)

args = parser.parse_args()
logging.getLogger().setLevel(30 - (10*args.verbose))

# Prevent running on all processes on the host system by default
if args.commands == "*" and not args.container and os.environ.get("ALLOW_ALL_COMMANDS_ON_HOST") != "true":
    LOGGER.error(
        "Analyzing all processes on the host system is probably not what you want. "
        "Use --commands or --container. See the README for more information."
    )
    sys.exit(2)

if args.container:
    nsenter_docker(args.container)

# Traffic dumps are required by keyfinder
if args.dump_directory:
    dump_directory = args.dump_directory
else:
    dump_directory_ctx = TemporaryDirectory()
    dump_directory = dump_directory_ctx.name
LOGGER.info(
    "interface: %s, dump_directory: %s",
    args.interface, dump_directory
)


# Shared objects between processes
class MyManager(BaseManager):
    # You must subclass BaseManager to use register()
    pass
class TLSSessionProxy(NamespaceProxy):
    # Expose attributes (by default only methods are exposed)
    _exposed_ = tuple(
        ['__getattribute__', '__setattr__', '__delattr__'] + \
        [attr for attr in dir(TLSSession) if not attr.startswith("_")]
    )
manager = MyManager()
manager.register("dict", dict, DictProxy)
manager.register("TLSSession", TLSSession, TLSSessionProxy)
manager.start()
TLS_SESSIONS: Dict[str, TLSSession] = manager.dict()


network_analyzer = src.network_analyzer.network.NetworkAnalyzer(
    interface=args.interface,
    tls_sessions=TLS_SESSIONS,
    manager=manager,
    dump_directory=dump_directory
)
# src.network.LOGGER.setLevel(logging.INFO)

p_network_analyzer = multiprocessing.Process(
    target=network_analyzer.sniff
)
p_network_analyzer.name = "NetworkAnalyzer"
p_network_analyzer.start()


memory_dumper = src.dumper.handshake_detector.MemoryDumper(
    interface=args.interface,
    tls_sessions=TLS_SESSIONS,
    allowed_commands=args.commands.split(",") if args.commands != "*" else None
)
p_memory_dumper = multiprocessing.Process(
    target=memory_dumper.run,
    daemon=False  # Allow this process to create child processes
)
p_memory_dumper.name = "MemoryDumper"
p_memory_dumper.start()


key_finder = src.keyfinder.finder.KeyFinder(
    tls_sessions=TLS_SESSIONS,
    dump_directory=dump_directory
)
p_key_finder = multiprocessing.Process(
    target=key_finder.run
)
p_key_finder.name = "KeyFinder"
p_key_finder.start()


try:
    while True:
        status_file = os.environ.get("STATUS_FILE")
        if status_file:
            with open(status_file, "wt") as fd:
                for tls_session in TLS_SESSIONS.values():
                    # If target is a container, print all sessions, else only sessions with pid 
            # If target is a container, print all sessions, else only sessions with pid 
                    # If target is a container, print all sessions, else only sessions with pid 
                    # (i.e., only programs targeted with --commands) to avoid flooding the status file
                    if args.container:
                        fd.write(str(tls_session))
                    else:
                        if tls_session.pid:
                            fd.write(str(tls_session))

        for process in (p_network_analyzer, p_memory_dumper, p_key_finder):
            if not process.is_alive():
                LOGGER.error("%s died", process.name)
                raise KeyboardInterrupt
        
        fix_permissions_traffic_dumps(dump_directory, args.chown_traffic_dumps)

        cleanup_old_tls_sessions(TLS_SESSIONS)

        time.sleep(5)

except KeyboardInterrupt:
        print("Exiting...")
        network_analyzer.close()
        memory_dumper.close()
        key_finder.close()
        if p_network_analyzer.is_alive():
            p_network_analyzer.terminate()
        if p_memory_dumper.is_alive():
            p_memory_dumper.terminate()
        if p_key_finder.is_alive():
            p_key_finder.terminate()
        fix_permissions_traffic_dumps(dump_directory, args.chown_traffic_dumps)
        cleanup_old_tls_sessions(TLS_SESSIONS)
        shutdown_cleanup(TLS_SESSIONS)
        manager.shutdown()
        if not args.dump_directory:
            dump_directory_ctx.cleanup()  # Delete temporary directory for dumps
        sys.exit(0)
