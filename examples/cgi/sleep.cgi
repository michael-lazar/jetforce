#!/usr/bin/env python3
"""
This is a demo CGI script that sleeps for a number of seconds before
responding. Used to test concurrency / blocking CGI requests.
"""

import os
import time

query = os.environ["QUERY_STRING"] or "0"

if query:
    time.sleep(int(query))

print("20 text/html")
print(f"Slept for {query} seconds.")
