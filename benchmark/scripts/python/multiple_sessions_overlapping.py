"""
Threaded program that open multiple TLS connection simultaneously (10ms interval)
"""

import concurrent.futures
import sys
import time

import requests

POOL = concurrent.futures.ThreadPoolExecutor(max_workers=20)


def req_https():
    requests.get(sys.argv[1])

for _ in range(20):
    POOL.submit(req_https)
    time.sleep(10/1000)

POOL.shutdown(wait=True)

print("Done")
