"""
Sample program that print messages and store them in memory as ASCII
Useful to play with memdiff.py
"""

import os
import time

data = []
try:
    while True:
        msg = f"PID={os.getpid()}, random=event{len(data)}"
        print(msg)
        data.append(msg.encode("ascii"))
        time.sleep(0.5)

except KeyboardInterrupt:
    exit(0)
