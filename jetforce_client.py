#!/usr/bin/env python3.7
"""
A dead-simple gemini client intended to be used for server development and testing.

./jetforce-client gemini://mozz.us
"""
import argparse
import socket
import ssl
import urllib.parse

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE


def fetch(url: str, host: str = None, port: str = None):
    parsed_url = urllib.parse.urlparse(url)
    if not parsed_url.scheme:
        parsed_url = urllib.parse.urlparse(f"gemini://{url}")

    host = host or parsed_url.hostname
    port = port or parsed_url.port or 1965

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock) as ssock:
            ssock.sendall((url + "\r\n").encode())
            fp = ssock.makefile("rb")
            header = fp.readline().decode()
            print(header)
            body = fp.read().decode()
            print(body)


def run_client():
    parser = argparse.ArgumentParser(description="A simple gemini client")
    parser.add_argument("url")
    parser.add_argument(
        "--host", help="Optional server to connect to, will default to the URL"
    )
    parser.add_argument(
        "--port", help="Optional port to connect to, will default to the URL"
    )
    args = parser.parse_args()
    fetch(args.url, args.host, args.port)


if __name__ == "__main__":
    run_client()
