#!/usr/bin/env python3
"""
This is a demo CGI script that sleeps for a number of seconds before
responding. Used to test concurrency / blocking CGI requests.
"""

import os
import time

query = os.environ["QUERY_STRING"] or "0"

print("20 text/html", flush=True)

for i in range(int(query)):
    print(i, flush=True)
    time.sleep(1)

print("Done")
