"""
This script helps to compare sessions stored in dump/ directory with sessions stored in file produced by
SSLKEYLOGFILE to detect if the target program is dumping keys for *all* TLS sessions.
Session matching is done using Client Random value.
(!) Validity of keys are not checked
"""

import argparse
import json
import logging

logging.basicConfig(format="%(levelname)s:%(message)s")
LOGGER = logging.getLogger(__name__)

# CLI args
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
    "-s", "--stats-file",
    type=str,
    help="Path to stats.json file",
    required=True
)
parser.add_argument(
    "-f", "--ssl-key-log-file",
    type=str,
    help="Path to SSLKEYLOGFILE file",
    required=True
)
args = parser.parse_args()
logging.getLogger().setLevel(30 - (10*args.verbose))

# Get all sessions from SSLKEYLOGFILE file
sslkeylogfile_client_randoms = set()
with open(args.ssl_key_log_file, "rt") as sslkeylog_fd:
    for line in sslkeylog_fd.readlines():
        if not line or line[0] == "#":
            continue
        label, client_random, secret = line.split(" ")
        if secret:  # naive way to check if secret is stored... (but it could be wrong)
            sslkeylogfile_client_randoms.add(client_random)
LOGGER.info("%d sessions found in SSLKEYLOGFILE file", len(sslkeylogfile_client_randoms))

hidden_sessions = 0
stats_sessions = []
with open(args.stats_file, "rt") as stats_fd:
    for line in stats_fd.readlines():
        session = json.loads(line)
        stats_sessions.append(session)
        if session["tls_client_random"] in sslkeylogfile_client_randoms:
            LOGGER.debug("Session '%s' found in SSLKEYLOGFILE file", session["tls_client_random"])
        else:
            LOGGER.info(
                "Session '%s' not found in SSLKEYLOGFILE (%s)",
                session["tls_client_random"], session["traffic_dump_filepath"]
            )
            hidden_sessions += 1

LOGGER.info(
    "SSLKEYLOGFILE: %d session(s), stats.json: %d",
    len(sslkeylogfile_client_randoms),
    len(stats_sessions)
)
LOGGER.info("%d session(s) were not present in SSLKEYLOGFILE", hidden_sessions)
