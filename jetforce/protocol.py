from __future__ import annotations

import time
import traceback
import typing
import urllib.parse

from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.defer import Deferred, ensureDeferred
from twisted.internet.task import deferLater
from twisted.protocols.basic import LineOnlyReceiver

from .__version__ import __version__
from .app.base import JetforceApplication, Status
from .tls import inspect_certificate

if typing.TYPE_CHECKING:
    from .server import GeminiServer


class GeminiProtocol(LineOnlyReceiver):
    """
    Handle a single Gemini Protocol TCP request.

    The request handler manages the life of a single gemini request. It exposes
    a simplified interface to read the request URL and write the gemini response
    status line and body to the socket. The request URL and other server
    information is stuffed into an ``environ`` dictionary that encapsulates the
    request at a low level. This dictionary, along with a callback to write the
    response data, and passed to a configurable "application" function or class.

    This design borrows heavily from the standard library's HTTP request
    handler (http.server.BaseHTTPRequestHandler). However, I did not make any
    attempts to directly emulate the existing conventions, because Gemini is an
    inherently simpler protocol than HTTP and much of the boilerplate could be
    removed.
    """

    TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

    client_addr: typing.Union[IPv4Address, IPv6Address]
    connected_timestamp: time.struct_time
    request: bytes
    url: str
    status: int
    meta: str
    response_buffer: str
    response_size: int

    def __init__(self, server: GeminiServer, app: JetforceApplication):
        self.server = server
        self.app = app

    def connectionMade(self):
        """
        This is invoked by twisted after the connection is first established.
        """
        self.connected_timestamp = time.localtime()
        self.response_size = 0
        self.response_buffer = ""
        self.client_addr = self.transport.getPeer()

    def lineReceived(self, line):
        """
        This method is invoked by LineOnlyReceiver for every incoming line.
        """
        self.request = line
        return ensureDeferred(self._handle_request_noblock())

    async def _handle_request_noblock(self):
        """
        Handle the gemini request and write the raw response to the socket.

        This method is implemented using an async coroutine, which has been
        supported by twisted since python 3.5 by wrapping the method in
        ensureDeferred().

        There are two places that we call into the "application" code:

        1. The initial invoking of app(environ, write_callback) which will
           return an iterable.
        2. Every time that we call next() on the iterable to retrieve bytes to
           write to the response body.

        In both of these places, the app can either return the result directly,
        or it can return a "deferred" object, which is twisted's version of an
        asyncio future. The server will await on the result of this deferred,
        which yields control of the event loop for other requests to be handled
        concurrently.
        """
        try:
            self.parse_header()
        except Exception:
            # Malformed request, throw it away and exit immediately
            self.server.log_message(traceback.format_exc())
            self.write_status(Status.BAD_REQUEST, "Malformed request")
            self.flush_status()
            self.transport.loseConnection()
            raise

        try:
            environ = self.build_environ()
            response_generator = self.app(environ, self.write_status)
            if isinstance(response_generator, Deferred):
                response_generator = await response_generator
            else:
                # Yield control of the event loop
                await deferLater(self.server.reactor, 0)

            for data in response_generator:
                if isinstance(data, Deferred):
                    data = await data
                    self.write_body(data)
                else:
                    self.write_body(data)
                    # Yield control of the event loop
                    await deferLater(self.server.reactor, 0)

        except Exception:
            self.server.log_message(traceback.format_exc())
            self.write_status(Status.CGI_ERROR, "An unexpected error occurred")
        finally:
            self.flush_status()
            self.log_request()
            self.transport.loseConnection()

    def build_environ(self) -> typing.Dict[str, typing.Any]:
        """
        Construct a dictionary that will be passed to the application handler.

        Variable names (mostly) conform to the CGI spec defined in RFC 3875.
        The TLS variable names borrow from the GLV-1.12556 server.
        """
        url_parts = urllib.parse.urlparse(self.url)
        conn = self.transport.getHandle()
        environ = {
            "GEMINI_URL": self.url,
            "HOSTNAME": self.server.hostname,
            "QUERY_STRING": url_parts.query,
            "REMOTE_ADDR": self.client_addr.host,
            "REMOTE_HOST": self.client_addr.host,
            "SERVER_NAME": self.server.hostname,
            "SERVER_PORT": self.server.port,
            "SERVER_PROTOCOL": "GEMINI",
            "SERVER_SOFTWARE": f"jetforce/{__version__}",
            "TLS_CIPHER": conn.get_cipher_name(),
            "TLS_VERSION": conn.get_protocol_version_name(),
            "client_certificate": None,
        }

        cert = self.transport.getPeerCertificate()
        if cert:
            x509_cert = cert.to_cryptography()
            cert_data = inspect_certificate(x509_cert)
            environ.update(
                {
                    "client_certificate": x509_cert,
                    "AUTH_TYPE": "CERTIFICATE",
                    "REMOTE_USER": cert_data["common_name"],
                    "TLS_CLIENT_HASH": cert_data["fingerprint"],
                    "TLS_CLIENT_NOT_BEFORE": cert_data["not_before"],
                    "TLS_CLIENT_NOT_AFTER": cert_data["not_after"],
                    "TLS_CLIENT_SERIAL_NUMBER": cert_data["serial_number"],
                    # Grab the value that was stashed during the TLS handshake
                    "TLS_CLIENT_AUTHORISED": getattr(conn, "authorised", False),
                }
            )
        return environ

    def parse_header(self) -> None:
        """
        Parse the gemini header line.

        The request is a single UTF-8 line formatted as: <URL>\r\n
        """
        if len(self.request) > 1024:
            raise ValueError("URL exceeds max length of 1024 bytes")

        self.url = self.request.decode()

    def write_status(self, status: int, meta: str) -> None:
        """
        Write the gemini status line to an internal buffer.

        The status line is a single UTF-8 line formatted as:
            <code>\t<meta>\r\n

        If the response status is 2, the meta field will contain the mimetype
        of the response data sent. If the status is something else, the meta
        will contain a descriptive message.

        The status is not written immediately, it's added to an internal buffer
        that must be flushed. This is done so that the status can be updated as
        long as no other data has been written to the stream yet.
        """
        self.status = status
        self.meta = meta
        self.response_buffer = f"{status}\t{meta}\r\n"

    def write_body(self, data: typing.Union[str, bytes]) -> None:
        """
        Write bytes to the gemini response body.
        """
        if isinstance(data, str):
            data = data.encode()

        self.flush_status()
        self.response_size += len(data)
        self.transport.write(data)

    def flush_status(self) -> None:
        """
        Flush the status line from the internal buffer to the socket stream.
        """
        if self.response_buffer and not self.response_size:
            data = self.response_buffer.encode()
            self.response_size += len(data)
            self.transport.write(data)
        self.response_buffer = ""

    def log_request(self) -> None:
        """
        Log a gemini request using a format derived from the Common Log Format.
        """
        try:
            message = '{} [{}] "{}" {} {} {}'.format(
                self.client_addr.host,
                time.strftime(self.TIMESTAMP_FORMAT, self.connected_timestamp),
                self.url,
                self.status,
                self.meta,
                self.response_size,
            )
        except AttributeError:
            # The connection ended before we got far enough to log anything
            pass
        else:
            self.server.log_message(message)
