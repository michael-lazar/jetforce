#!/usr/bin/env python
"""
This is a demo CGI script that prints a bunch of debug information about
the request as an HTML document. Place it in the cgi-bin/ directory of your
server.
"""
import cgi

print("200 text/html")
cgi.test()
