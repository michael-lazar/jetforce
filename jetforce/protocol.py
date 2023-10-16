from __future__ import annotations

import time
import traceback
import typing
import urllib.parse

from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.defer import CancelledError, Deferred, ensureDeferred
from twisted.internet.interfaces import ITransport
from twisted.internet.protocol import connectionDone
from twisted.internet.task import deferLater
from twisted.protocols.basic import LineOnlyReceiver
from twisted.python.failure import Failure

from jetforce.__version__ import __version__
from jetforce.app.base import ApplicationCallable, EnvironDict, Status
from jetforce.tls import inspect_certificate

if typing.TYPE_CHECKING:
    from jetforce.server import GeminiServer


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
    DEBUG = False

    connected_timestamp: time.struct_time
    request: bytes
    url: str
    status: int
    meta: str
    response_buffer: str
    response_size: int

    # The twisted base class has the wrong type hint for this
    transport: type[ITransport]  # type: ignore[assignment]

    def __init__(self, server: GeminiServer, app: ApplicationCallable):
        self.server = server
        self.app = app
        self._currently_deferred: Deferred | None = None

    def connectionMade(self) -> None:
        """
        This is invoked by twisted after the connection is first established.
        """
        self.connected_timestamp = time.localtime()
        self.response_size = 0
        self.response_buffer = ""

    def connectionLost(self, reason: Failure = connectionDone) -> None:
        """
        This is invoked by twisted after the connection has been closed.
        """
        if self._currently_deferred:
            self._currently_deferred.cancel()

    def lineReceived(self, line: bytes) -> Deferred:
        """
        This method is invoked by LineOnlyReceiver for every incoming line.
        """
        self.request = line
        return ensureDeferred(self._handle_request_noblock())

    def lineLengthExceeded(self, line: bytes) -> None:
        """
        Called when the maximum line length has been reached.
        """
        self.finish_connection()

    @property
    def client_addr(self) -> IPv4Address | IPv6Address:
        """
        Return the client IP address.

        This should be retrieved lazily (not cached when the connection is
        first established) because the underlying value of getPeer() will
        change depending on whether a PROXY header has been received or not.
        """
        return self.transport.getPeer()

    def finish_connection(self) -> None:
        """
        Send the TLS "close_notify" alert and then immediately close the TCP
        connection without waiting for the client to respond with it's own
        "close_notify" alert.

        > It is acceptable for an application to only send its shutdown alert
        > and then close the underlying connection without waiting for the
        > peer's response. This way resources can be saved, as the process can
        > already terminate or serve another connection. This should only be
        > done when it is known that the other side will not send more data,
        > otherwise there is a risk of a truncation attack.

        References:
            https://github.com/michael-lazar/jetforce/issues/32
            https://www.openssl.org/docs/man1.1.1/man3/SSL_shutdown.html
        """
        # Send the TLS close_notify alert and flush the write buffer. If the
        # client has already closed their end of the stream, this will also
        # close the underlying TCP connection.
        self.transport.loseConnection()

        # Ensure that the underlying connection will always be closed. There is
        # no harm in calling this method twice if it was already invoked as
        # part of the above TLS shutdown.
        if hasattr(self.transport, "transport"):
            self.transport.transport.loseConnection()

    async def _handle_request_noblock(self) -> None:
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
            self.finish_connection()
            raise

        try:
            environ = self.build_environ()
            response_generator = self.app(environ, self.write_status)
            if isinstance(response_generator, Deferred):
                response_generator = await self.track_deferred(response_generator)
            else:
                # Yield control of the event loop
                deferred: Deferred[None] = deferLater(self.server.reactor, 0)
                await self.track_deferred(deferred)

            for data in response_generator:
                if isinstance(data, Deferred):
                    data = await self.track_deferred(data)
                    self.write_body(data)  # type: ignore
                else:
                    self.write_body(data)
                    # Yield control of the event loop
                    deferred = deferLater(self.server.reactor, 0)
                    await self.track_deferred(deferred)
        except CancelledError:
            pass
        except Exception:
            self.server.log_message(traceback.format_exc())
            self.write_status(Status.CGI_ERROR, "An unexpected error occurred")
        finally:
            self.flush_status()
            self.log_request()
            self.finish_connection()

    async def track_deferred(self, deferred: Deferred) -> typing.Any:
        """
        Keep track of the deferred that we're waiting on so we can send an
        error back to it if the connection is abruptly killed.
        """
        self._currently_deferred = deferred
        try:
            return await deferred
        finally:
            self._currently_deferred = None

    def build_environ(self) -> EnvironDict:
        """
        Construct a dictionary that will be passed to the application handler.

        Variable names (mostly) conform to the CGI spec defined in RFC 3875.
        The TLS variable names borrow from the GLV-1.12556 server.
        """
        url_parts = urllib.parse.urlparse(self.url)
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
        }

        try:
            cert = self.transport.getPeerCertificate()
        except AttributeError:
            # We're not using a TLS-enabled transport, we can skip
            # all of the TLS environment initialization below.
            return environ

        conn = self.transport.getHandle()
        environ.update(
            {
                "TLS_CIPHER": conn.get_cipher_name(),
                "TLS_VERSION": conn.get_protocol_version_name(),
                # Lowercase variables are not set in the environment for CGI
                # scripts, but they can be accessed by python applications that
                # utilize jetforce as a library.
                "client_certificate": None,
            }
        )

        if cert:
            x509_cert = cert.to_cryptography()
            cert_data = inspect_certificate(x509_cert)
            environ.update(
                {
                    "client_certificate": x509_cert,
                    "AUTH_TYPE": "CERTIFICATE",
                    "REMOTE_USER": cert_data["common_name"],
                    "TLS_CLIENT_HASH": cert_data["fingerprint"],
                    "TLS_CLIENT_HASH_B64": cert_data["fingerprint_b64"],
                    "TLS_CLIENT_NOT_BEFORE": cert_data["not_before"],
                    "TLS_CLIENT_NOT_AFTER": cert_data["not_after"],
                    "TLS_CLIENT_SERIAL_NUMBER": cert_data["serial_number"],
                    # Grab the value that was stashed during the TLS handshake
                    "TLS_CLIENT_AUTHORISED": int(getattr(conn, "authorised", 0)),
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
            <STATUS><SPACE><META><CR><LF>

        If the response status is 2, the meta field will contain the mimetype
        of the response data sent. If the status is something else, the meta
        will contain a descriptive message.

        The status is not written immediately, it's added to an internal buffer
        that must be flushed. This is done so that the status can be updated as
        long as no other data has been written to the stream yet.
        """
        self.status = status
        self.meta = meta
        self.response_buffer = f"{status} {meta}\r\n"

    def write_body(self, data: str | bytes | None) -> None:
        """
        Write bytes to the gemini response body.
        """
        if data is None:
            return

        if isinstance(data, str):
            data = data.encode()

        self.flush_status()
        self.response_size += len(data)
        if self.DEBUG:
            print(f"Writing body: {len(data)} bytes")
        self.transport.write(data)

    def flush_status(self) -> None:
        """
        Flush the status line from the internal buffer to the socket stream.
        """
        if self.response_buffer and not self.response_size:
            data = self.response_buffer.encode()
            self.response_size += len(data)
            if self.DEBUG:
                print(f"Writing status: {len(data)} bytes")
            self.transport.write(data)
        self.response_buffer = ""

    def log_request(self) -> None:
        """
        Log a gemini request using a format derived from the Common Log Format.
        """
        try:
            message = '{} [{}] "{}" {} "{}" {}'.format(
                self.client_addr.host,
                time.strftime(self.TIMESTAMP_FORMAT, self.connected_timestamp),
                self.url,
                self.status,
                self.meta.replace('"', '\\"'),
                self.response_size,
            )
        except AttributeError:
            # The connection ended before we got far enough to log anything
            pass
        else:
            self.server.log_access(message)
