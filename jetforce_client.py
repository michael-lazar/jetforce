#!/usr/bin/env python3
"""
A very basic gemini client to use for testing server configurations.
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
    sni = host if use_sni else None

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=sni) as ssock:
            ssock.sendall((url + "\r\n").encode())
            fp = ssock.makefile("rb", buffering=0)
            data = fp.read(1024)
            while data:
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
                data = fp.read(1024)


def run_client():
    parser = argparse.ArgumentParser(description="A simple gemini client")
    parser.add_argument("url")
    parser.add_argument("--host", help="Server host")
    parser.add_argument("--port", help="Server port")
    parser.add_argument("--tls-certfile", help="Client certificate")
    parser.add_argument("--tls-keyfile", help="Client private key")
    parser.add_argument("--tls-alpn-protocol", help="Protocol for ALPN negotiation")
    parser.add_argument(
        "--tls-enable-sni", action="store_true", help="Specify the hostname using SNI"
    )

    args = parser.parse_args()
    if args.tls_certfile:
        context.load_cert_chain(args.tls_certfile, args.tls_keyfile)

    if args.tls_alpn_protocol:
        context.set_alpn_protocols([args.tls_alpn_protocol])

    fetch(args.url, args.host, args.port, args.tls_enable_sni)


if __name__ == "__main__":
    run_client()
