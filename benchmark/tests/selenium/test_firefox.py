"""
Tests for firefox using selenium
"""

import itertools
import logging
import os
import time

import pytest
from conftest import (DUMP_METHODS, URL_TLS_12_ONLY, URL_TLS_13_ONLY,
                      save_benchmark_results, tls_decryption_success)
from selenium import webdriver

import docker

LOGGER = logging.getLogger()

DOCKER_CLIENT = docker.from_env()


def start_containers(dump_method):
    try:
        DOCKER_CLIENT.containers.get("tls-traffic-analyzer").stop()
    except docker.errors.NotFound:
        pass
    try:
        DOCKER_CLIENT.containers.get("my-tls-clients").stop()
    except docker.errors.NotFound:
        pass

    selenium_container = DOCKER_CLIENT.containers.run(
        image="selenium/standalone-firefox",
        name="my-tls-clients",
        detach=True,
        tty=True,
        remove=True,
        ports={
            "4444/tcp": ("127.0.0.1", 4444)
        },
        shm_size="2G"
    )

    tls_traffic_analyzer_container = DOCKER_CLIENT.containers.run(
        image="tls-traffic-analyzer:latest",
        name="tls-traffic-analyzer",
        privileged=True,
        detach=True,
        tty=True,
        remove=True,
        mem_limit="4G",
        volumes=[f"{os.getcwd()}/benchmark/dumps:/dumps", "/var/run/docker.sock:/var/run/docker.sock"],
        environment={
            "ENABLE_BASELINE": "true",
            "STATUS_FILE": "/tmp/status",
            "DUMP_METHOD": dump_method,
            "MEM_REGIONS": "[heap],[stack],,"
        },
        network_mode="host",
        pid_mode="host",
        command=f"-o /dumps --chown-traffic-dumps {os.getuid()} --container my-tls-clients -vv"
    )

    return tls_traffic_analyzer_container, selenium_container


@pytest.mark.parametrize(
    "dump_method,url",
    [
        (dump_method, url)
        for dump_method, url in itertools.product(
            DUMP_METHODS, (URL_TLS_12_ONLY, URL_TLS_13_ONLY)
        )
    ]
)
def test_firefox(dump_method, url):
    tls_traffic_analyzer_container, selenium_container = start_containers(dump_method)

    try:
        options = webdriver.FirefoxOptions()
        for _ in range(20):
            try:
                driver = webdriver.Remote(
                    command_executor='http://localhost:4444/wd/hub',
                    options=options
                )
                break
            except:
                LOGGER.info("Waiting for selenium container to be up...")
                time.sleep(1)

        driver.get(url)
        driver.quit()

        success, sessions = tls_decryption_success(timeout=600)
        assert success, f"TLS client logs: {selenium_container.logs()}\n"
        save_benchmark_results("firefox", dump_method, sessions)

    except Exception as e:
        LOGGER.exception("Fail to run tests")
        raise e

    finally:
        tls_traffic_analyzer_container.stop()
        selenium_container.stop()
