"""
Tests for python
"""

import itertools
import logging

import pytest
from conftest import (DUMP_METHODS, TLS_CLIENTS_CONTAINER,
                      TLS_TRAFFIC_ANALYZER_CONTAINER, URL_TLS_12_ONLY,
                      URL_TLS_13_ONLY, save_benchmark_results,
                      tls_decryption_success)

LOGGER = logging.getLogger()


@pytest.mark.parametrize(
    "dump_method,url",
    [
        (dump_method, url)
        for dump_method, url in itertools.product(
            DUMP_METHODS, (URL_TLS_12_ONLY, URL_TLS_13_ONLY)
        )
    ]
)
def test_python_requests(dump_method, url):
    TLS_TRAFFIC_ANALYZER_CONTAINER.exec_run(
        ["bash", "-c", f"echo {dump_method} > /tmp/dump_method"]
    )
    exit_code, output = TLS_CLIENTS_CONTAINER.exec_run(
        ["python3", "/home/tlsuser/scripts/python/python_requests.py", url]
    )
    assert exit_code == 0, f"TLS client failed to run: {output}"
    success, sessions = tls_decryption_success()
    assert success, f"TLS client logs: {output}\n"
    save_benchmark_results("python_requests", dump_method, sessions)


@pytest.mark.parametrize(
    "dump_method,url",
    [
        (dump_method, url)
        for dump_method, url in itertools.product(
            DUMP_METHODS, (URL_TLS_12_ONLY, URL_TLS_13_ONLY)
        )
    ]
)
def test_python_requests_series_5_sessions(dump_method, url):
    TLS_TRAFFIC_ANALYZER_CONTAINER.exec_run(
        ["bash", "-c", f"echo {dump_method} > /tmp/dump_method"]
    )
    exit_code, output = TLS_CLIENTS_CONTAINER.exec_run(
        ["python3", "/home/tlsuser/scripts/python/multiple_sessions_series.py", "5", url]
    )
    assert exit_code == 0, f"TLS client failed to run: {output}"
    success, sessions = tls_decryption_success(n_sessions=5)
    assert success, f"TLS client logs: {output}\n"
    save_benchmark_results("python_requests_series_5_sessions", dump_method, sessions)


@pytest.mark.parametrize(
    "dump_method,url",
    [
        (dump_method, url)
        for dump_method, url in itertools.product(
            DUMP_METHODS, (URL_TLS_12_ONLY, URL_TLS_13_ONLY)
        )
    ]
)
def test_python_requests_series_10_sessions(dump_method, url):
    TLS_TRAFFIC_ANALYZER_CONTAINER.exec_run(
        ["bash", "-c", f"echo {dump_method} > /tmp/dump_method"]
    )
    exit_code, output = TLS_CLIENTS_CONTAINER.exec_run(
        ["python3", "/home/tlsuser/scripts/python/multiple_sessions_series.py", "10", url]
    )
    assert exit_code == 0, f"TLS client failed to run: {output}"
    success, sessions = tls_decryption_success(n_sessions=10)
    assert success, f"TLS client logs: {output}\n"
    save_benchmark_results("python_requests_series_10_sessions", dump_method, sessions)

@pytest.mark.parametrize(
    "dump_method",
    [dump_method for dump_method in DUMP_METHODS]
)
def test_python_pip(dump_method):
    TLS_TRAFFIC_ANALYZER_CONTAINER.exec_run(
        ["bash", "-c", f"echo {dump_method} > /tmp/dump_method"]
    )
    exit_code, output = TLS_CLIENTS_CONTAINER.exec_run(
        ["python3", "-m", "pip", "install", "--force-reinstall", "--no-cache", "--target", "/tmp", "tqdm"]
    )
    assert exit_code == 0, f"TLS client failed to run: {output}"
    success, sessions = tls_decryption_success(n_sessions=2)  # download index + package
    assert success, f"TLS client logs: {output}\n"
    save_benchmark_results("python_pip", dump_method, sessions)
