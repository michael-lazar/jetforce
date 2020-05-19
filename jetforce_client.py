#!/usr/bin/env python3
"""
A dead-simple gemini client intended to be used for server development and testing.

./jetforce-client gemini://mozz.us
"""
import argparse
import socket
import ssl
import sys
import urllib.parse

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE


def fetch(url, host=None, port=None, use_sni=False):
    parsed_url = urllib.parse.urlparse(url)
    if not parsed_url.scheme:
        parsed_url = urllib.parse.urlparse(f"gemini://{url}")

    host = host or parsed_url.hostname
    port = port or parsed_url.port or 1965

    server_hostname = host if use_sni else None

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
            ssock.sendall((url + "\r\n").encode())
            fp = ssock.makefile("rb", buffering=0)
            data = fp.read(1024)
            while data:
                sys.stdout.buffer.write(data)
                data = fp.read(1024)


def run_client():
    parser = argparse.ArgumentParser(description="A simple gemini client")
    parser.add_argument("url")
    parser.add_argument(
        "--host", help="Optional server to connect to, will default to the URL"
    )
    parser.add_argument(
        "--port", help="Optional port to connect to, will default to the URL"
    )
    parser.add_argument("--certfile", help="Optional client certificate")
    parser.add_argument("--keyfile", help="Optional client key")
    parser.add_argument("--alpn-protocol", help="Indicate the protocol using ALPN")
    parser.add_argument(
        "--use-sni", action="store_true", help="Specify the server hostname via SNI"
    )

    args = parser.parse_args()
    if args.certfile:
        context.load_cert_chain(args.certfile, args.keyfile)
    if args.alpn_protocol:
        context.set_alpn_protocols([args.alpn_protocol])

    fetch(args.url, args.host, args.port, args.use_sni)


if __name__ == "__main__":
    run_client()
