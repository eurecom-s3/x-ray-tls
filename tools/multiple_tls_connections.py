#!/bin/env python3

"""
Threaded program that open multiple TLS connection simultaneously (10ms interval)
"""

import concurrent.futures
import os
import time

import requests

POOL = concurrent.futures.ThreadPoolExecutor(max_workers=100)


def req_https():
    requests.get("https://www.google.fr")

# print(f"PID: {os.getpid()}")
# print("Waiting 10s before starting connections...")
# time.sleep(10)

for _ in range(5):
    POOL.submit(req_https)
    time.sleep(2)

POOL.shutdown(wait=True)

print("Done")
