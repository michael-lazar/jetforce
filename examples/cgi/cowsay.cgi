#!/usr/local/bin/python3.7
r"""
CGI script that requests user supplied text using the INPUT status, and
pipes it into the `cowsay` program.

 _________________
< Gemini is cool! >
 -----------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
"""
import os
import subprocess
import sys
import urllib.parse

query = os.environ["QUERY_STRING"]
if not query:
    print("10 Enter your cowsay message: ")
    sys.exit()

text = urllib.parse.unquote(query)
try:
    proc = subprocess.run(
        ["/usr/local/bin/cowsay"],
        input=text,
        capture_output=True,
        check=True,
        text=True,
    )
except Exception:
    print("42 Unexpected Error")
else:
    print("20 text/plain")
    print(proc.stdout)
