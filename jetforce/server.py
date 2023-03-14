from __future__ import annotations

import socket
import sys
import typing

from twisted.internet import reactor as _reactor
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.protocol import Factory
from twisted.internet.tcp import Port
from twisted.protocols.haproxy import proxyEndpoint
from twisted.protocols.tls import TLSMemoryBIOFactory

from jetforce.__version__ import __version__
from jetforce.app.base import ApplicationCallable
from jetforce.protocol import GeminiProtocol
from jetforce.tls import GeminiCertificateOptions, generate_ad_hoc_certificate

if sys.stderr.isatty():
    CYAN = "\033[36m\033[1m"
    RESET = "\033[0m"
else:
    CYAN = ""
    RESET = ""


ABOUT = rf"""
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

    def __init__(
        self,
        app: ApplicationCallable,
        reactor: typing.Any = _reactor,
        host: str = "127.0.0.1",
        port: int = 1965,
        hostname: str = "localhost",
        certfile: str | None = None,
        keyfile: str | None = None,
        cafile: str | None = None,
        capath: str | None = None,
        proxy_protocol: bool = False,
        use_tls: bool = True,
    ):
        if certfile is None and use_tls:
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
        self.proxy_protocol = proxy_protocol
        self.use_tls = use_tls

    def log_access(self, message: str) -> None:
        """
        Log standard "access log"-type information.
        """
        print(message, file=sys.stdout)

    def log_message(self, message: str) -> None:
        """
        Log special messages like startup info or a traceback error.
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

    def buildProtocol(self, addr: typing.Any) -> GeminiProtocol:
        """
        This method is invoked by twisted once for every incoming connection.

        It builds the instance of the protocol class, which is what actually
        implements the Gemini protocol.
        """
        return self.protocol_class(self, self.app)

    def bind_interface(self, interface: str) -> None:
        """
        Binds the server to a twisted interface.
        """
        protocol_factory: Factory = self

        if self.use_tls:
            ssl_context_factory = GeminiCertificateOptions(
                certfile=self.certfile,  # type: ignore[arg-type]
                keyfile=self.keyfile,
                cafile=self.cafile,
                capath=self.capath,
            )
            protocol_factory = TLSMemoryBIOFactory(
                ssl_context_factory,
                False,
                protocol_factory,  # noqa
            )

        endpoint = TCP4ServerEndpoint(self.reactor, self.port, interface=interface)
        if self.proxy_protocol:
            endpoint = proxyEndpoint(endpoint)  # type: ignore

        endpoint.listen(protocol_factory).addCallback(self.on_bind_interface)

    def initialize(self) -> None:
        """
        Install the server into the twisted reactor.
        """
        interfaces = [self.host] if self.host else ["0.0.0.0", "::"]
        for interface in interfaces:
            self.bind_interface(interface)

    def run(self) -> None:
        """
        This is the main server loop.
        """
        self.log_message(ABOUT)
        self.log_message(f"Server hostname is {self.hostname}")
        if self.proxy_protocol:
            self.log_message("PROXY protocol is enabled")
        if self.use_tls:
            self.log_message(f"TLS Certificate File: {self.certfile}")
            self.log_message(f"TLS Private Key File: {self.keyfile}")
        else:
            self.log_message("TLS is disabled")
        self.initialize()
        self.reactor.run()
