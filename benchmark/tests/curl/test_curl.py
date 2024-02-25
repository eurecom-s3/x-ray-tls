"""
Tests for curl flavors
"""

import itertools
import logging

import pytest
from conftest import (DUMP_METHODS, TLS_CLIENTS_CONTAINER,
                      TLS_TRAFFIC_ANALYZER_CONTAINER, URL_TLS_12_ONLY,
                      URL_TLS_13_ONLY, save_benchmark_results,
                      tls_decryption_success)

LOGGER = logging.getLogger()


CURL_FLAVORS = ["openssl", "gnutls", "mbedtls", "wolfssl", "nss", "bearssl"]


@pytest.mark.parametrize(
    "flavor,dump_method,url",
    [
        (flavor, dump_method, url)
        for flavor, dump_method, url in itertools.product(
            CURL_FLAVORS, DUMP_METHODS, (URL_TLS_12_ONLY, URL_TLS_13_ONLY)
        )
    ]
)
def test_curl(flavor, dump_method, url):
    bin_path = f"/opt/curl-{flavor}/bin/curl"

    TLS_TRAFFIC_ANALYZER_CONTAINER.exec_run(
        ["bash", "-c", f"echo {dump_method} > /tmp/dump_method"]
    )

    exit_code, output = TLS_CLIENTS_CONTAINER.exec_run(
        [bin_path, "-v", "--retry", "12", "--retry-all-errors", "-o", "/dev/null", url]
    )

    assert exit_code == 0, f"TLS client failed to run: {output}"
    success, sessions = tls_decryption_success()
    assert success, f"TLS client logs: {output}\n"
    save_benchmark_results(f"curl-{flavor}", dump_method, sessions)


@pytest.mark.parametrize(
    "flavor,dump_method",
    [
        (flavor, dump_method)
        for flavor, dump_method in itertools.product(
            CURL_FLAVORS, DUMP_METHODS
        )
    ]
)
def test_curl_3_sessions(flavor, dump_method):
    bin_path = f"/opt/curl-{flavor}/bin/curl"

    TLS_TRAFFIC_ANALYZER_CONTAINER.exec_run(
        ["bash", "-c", f"echo {dump_method} > /tmp/dump_method"]
    )

    # Use 3 different domains to ensure 3 TLS sessions will be started
    exit_code, output = TLS_CLIENTS_CONTAINER.exec_run(
        [
            bin_path, "-v", "--retry", "12", "--retry-all-errors", "-o", "/dev/null",
            "https://www.google.fr", "https://www.google.com", "https://www.google.co.uk"
        ]
    )

    assert exit_code == 0, f"TLS client failed to run: {output}"
    success, sessions = tls_decryption_success(n_sessions=3)
    assert success, f"TLS client logs: {output}\n"
    save_benchmark_results(f"curl-{flavor}", dump_method, sessions)
