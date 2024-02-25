"""
Open HTTPS using requests module
"""

import sys
import requests

session = requests.Session()
print(session.get(sys.argv[1]))
