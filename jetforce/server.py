from __future__ import annotations

import socket
import sys
import typing

from twisted.internet import reactor
from twisted.internet.base import ReactorBase
from twisted.internet.endpoints import SSL4ServerEndpoint
from twisted.internet.protocol import Factory
from twisted.internet.tcp import Port

from .__version__ import __version__
from .protocol import GeminiProtocol
from .tls import GeminiCertificateOptions, generate_ad_hoc_certificate

if sys.stderr.isatty():
    CYAN = "\033[36m\033[1m"
    RESET = "\033[0m"
else:
    CYAN = ""
    RESET = ""


ABOUT = fr"""
{CYAN}You are now riding on...
_________    _____________
______  /______  /___  __/_______________________
___ _  /_  _ \  __/_  /_ _  __ \_  ___/  ___/  _ \
/ /_/ / /  __/ /_ _  __/ / /_/ /  /   / /__ /  __/
\____/  \___/\__/ /_/    \____//_/    \___/ \___/{RESET}

An Experimental Gemini Server, v{__version__}
https://github.com/michael-lazar/jetforce
"""


class GeminiServer(Factory):
    """
    Wrapper around twisted's TCP server that handles most of the setup and
    plumbing for you.
    """

    protocol_class = GeminiProtocol

    # The TLS twisted interface class is confusingly named SSL4, even though it
    # will accept either IPv4 & IPv6 interfaces.
    endpoint_class = SSL4ServerEndpoint

    def __init__(
        self,
        app: typing.Callable,
        reactor: ReactorBase = reactor,
        host: str = "127.0.0.1",
        port: int = 1965,
        hostname: str = "localhost",
        certfile: typing.Optional[str] = None,
        keyfile: typing.Optional[str] = None,
        cafile: typing.Optional[str] = None,
        capath: typing.Optional[str] = None,
    ):
        if certfile is None:
            self.log_message("Generating ad-hoc certificate files...")
            certfile, keyfile = generate_ad_hoc_certificate(hostname)

        self.app = app
        self.reactor = reactor
        self.host = host
        self.port = port
        self.hostname = hostname
        self.certfile = certfile
        self.keyfile = keyfile
        self.cafile = cafile
        self.capath = capath

    def log_message(self, message: str) -> None:
        """
        Log a diagnostic server message to stderr.
        """
        print(message, file=sys.stderr)

    def on_bind_interface(self, port: Port) -> None:
        """
        Log when the server binds to an interface.
        """
        sock_ip, sock_port, *_ = port.socket.getsockname()
        if port.addressFamily == socket.AF_INET:
            self.log_message(f"Listening on {sock_ip}:{sock_port}")
        else:
            self.log_message(f"Listening on [{sock_ip}]:{sock_port}")

    def buildProtocol(self, addr) -> GeminiProtocol:
        """
        This method is invoked by twisted once for every incoming connection.

        It builds the instance of the protocol class, which is what actually
        implements the Gemini protocol.
        """
        return GeminiProtocol(self, self.app)

    def run(self) -> None:
        """
        This is the main server loop.
        """
        self.log_message(ABOUT)
        self.log_message(f"Server hostname is {self.hostname}")
        self.log_message(f"TLS Certificate File: {self.certfile}")
        self.log_message(f"TLS Private Key File: {self.keyfile}")

        certificate_options = GeminiCertificateOptions(
            certfile=self.certfile,
            keyfile=self.keyfile,
            cafile=self.cafile,
            capath=self.capath,
        )

        interfaces = [self.host] if self.host else ["0.0.0.0", "::"]
        for interface in interfaces:
            endpoint = self.endpoint_class(
                reactor=self.reactor,
                port=self.port,
                sslContextFactory=certificate_options,
                interface=interface,
            )
            endpoint.listen(self).addCallback(self.on_bind_interface)

        self.reactor.run()
