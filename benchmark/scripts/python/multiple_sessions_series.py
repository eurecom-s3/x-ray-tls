"""
Program that opens multiple TLS connections in series
"""

import random
import sys

import requests

for _ in range(int(sys.argv[1])):
    requests.get(sys.argv[2])

    # Add noise between requests
    noise = ""
    for i in range(100*1024):
        noise += str(random.randint(1,100))

print("Done")
