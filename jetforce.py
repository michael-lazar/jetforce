#!/usr/bin/env python3
"""
Jetforce, an experimental Gemini server.

Overview
--------

GeminiServer:
    A TCP + TLS server build on top of the python twisted framework. This class
    is responsible for binding to the TCP/IP interface, setting up the TLS
    context, handling incoming connections, and sending connections to to a
    request handler to be processed.

GeminiProtocol:
    The request handler manages the life of a single gemini request. It exposes
    a simplified interface to read the request URL and write the gemini response
    status line and body to the socket. The request URL and other server
    information is stuffed into an ``environ`` dictionary that encapsulates the
    request at a low level. This dictionary, along with a callback to write the
    response data, and passed to a configurable "application" function or class.

JetforceApplication:
    This is a base class for writing jetforce server applications. It doesn't
    anything on its own, but it does provide a convenient interface to define
    custom server endpoints using route decorators. If you want to utilize
    jetforce as a library and write your own server in python, this is the class
    that you want to extend. The examples/ directory contains some examples of
    how to accomplish this.

StaticDirectoryApplication:
    This is a batteries-included application that serves files from a static
    directory. It provides a preconfigured gemini server without needing to
    write any lines of code. This is what is invoked when you launch jetforce
    from the command line.
"""
from __future__ import annotations

import argparse
import base64
import codecs
import dataclasses
import datetime
import mimetypes
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import time
import typing
import urllib.parse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from OpenSSL import SSL
from twisted.internet import reactor
from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.base import ReactorBase
from twisted.internet.endpoints import SSL4ServerEndpoint
from twisted.internet.protocol import Factory
from twisted.internet.ssl import CertificateOptions, TLSVersion
from twisted.internet.tcp import Port
from twisted.protocols.basic import LineOnlyReceiver
from twisted.python.randbytes import secureRandom

if sys.version_info < (3, 7):
    sys.exit("Fatal Error: jetforce requires Python 3.7+")

__version__ = "0.2.2"
__title__ = "Jetforce Gemini Server"
__author__ = "Michael Lazar"
__license__ = "Floodgap Free Software License"
__copyright__ = "(c) 2020 Michael Lazar"

ABOUT = fr"""
You are now riding on...
_________    _____________
______  /______  /___  __/_______________________
___ _  /_  _ \  __/_  /_ _  __ \_  ___/  ___/  _ \
/ /_/ / /  __/ /_ _  __/ / /_/ /  /   / /__ /  __/
\____/  \___/\__/ /_/    \____//_/    \___/ \___/

An Experimental Gemini Server, v{__version__}
https://github.com/michael-lazar/jetforce
"""

CN = x509.NameOID.COMMON_NAME


class Status:
    """
    Gemini response status codes.
    """

    INPUT = 10

    SUCCESS = 20
    SUCCESS_END_OF_SESSION = 21

    REDIRECT_TEMPORARY = 30
    REDIRECT_PERMANENT = 31

    TEMPORARY_FAILURE = 40
    SERVER_UNAVAILABLE = 41
    CGI_ERROR = 42
    PROXY_ERROR = 43
    SLOW_DOWN = 44

    PERMANENT_FAILURE = 50
    NOT_FOUND = 51
    GONE = 52
    PROXY_REQUEST_REFUSED = 53
    BAD_REQUEST = 59

    CLIENT_CERTIFICATE_REQUIRED = 60
    TRANSIENT_CERTIFICATE_REQUESTED = 61
    AUTHORISED_CERTIFICATE_REQUIRED = 62
    CERTIFICATE_NOT_ACCEPTED = 63
    FUTURE_CERTIFICATE_REJECTED = 64
    EXPIRED_CERTIFICATE_REJECTED = 65


class Request:
    """
    Object that encapsulates information about a single gemini request.
    """

    def __init__(self, environ: dict):
        self.environ = environ
        self.url = environ["GEMINI_URL"]

        url_parts = urllib.parse.urlparse(self.url)
        if not url_parts.hostname:
            raise ValueError("URL must contain a `hostname` part")

        if not url_parts.scheme:
            # If scheme is missing, infer it to be gemini://
            self.scheme = "gemini"
        else:
            self.scheme = url_parts.scheme

        self.hostname = url_parts.hostname
        self.port = url_parts.port
        self.path = url_parts.path
        self.params = url_parts.params
        self.query = urllib.parse.unquote(url_parts.query)
        self.fragment = url_parts.fragment


@dataclasses.dataclass
class Response:
    """
    Object that encapsulates information about a single gemini response.
    """

    status: int
    meta: str
    body: typing.Union[None, bytes, str, typing.Iterator[bytes]] = None


@dataclasses.dataclass
class RoutePattern:
    """
    A pattern for matching URLs with a single endpoint or route.
    """

    path: str = ".*"
    scheme: str = "gemini"
    hostname: typing.Optional[str] = None

    strict_hostname: bool = True
    strict_port: bool = True
    strict_trailing_slash: bool = False

    def match(self, request: Request) -> typing.Optional[re.Match]:
        """
        Check if the given request URL matches this route pattern.
        """
        if self.hostname is None:
            server_hostname = request.environ["HOSTNAME"]
        else:
            server_hostname = self.hostname
        server_port = int(request.environ["SERVER_PORT"])

        if self.strict_hostname and request.hostname != server_hostname:
            return
        if self.strict_port and request.port is not None:
            if request.port != server_port:
                return
        if self.scheme and self.scheme != request.scheme:
            return

        if self.strict_trailing_slash:
            request_path = request.path
        else:
            request_path = request.path.rstrip("/")

        return re.fullmatch(self.path, request_path)


class JetforceApplication:
    """
    Base Jetforce application class with primitive URL routing.

    This is a base class for writing jetforce server applications. It doesn't
    anything on its own, but it does provide a convenient interface to define
    custom server endpoints using route decorators. If you want to utilize
    jetforce as a library and write your own server in python, this is the class
    that you want to extend. The examples/ directory contains some examples of
    how to accomplish this.
    """

    def __init__(self):
        self.routes: typing.List[
            typing.Tuple[RoutePattern, typing.Callable[[Request], Response]]
        ] = []

    def __call__(
        self, environ: dict, send_status: typing.Callable
    ) -> typing.Iterator[bytes]:
        try:
            request = Request(environ)
        except Exception:
            send_status(Status.BAD_REQUEST, "Unrecognized URL format")
            return

        for route_pattern, callback in self.routes[::-1]:
            if route_pattern.match(request):
                break
        else:
            callback = self.default_callback

        response = callback(request)
        send_status(response.status, response.meta)
        if isinstance(response.body, bytes):
            yield response.body
        elif isinstance(response.body, str):
            yield response.body.encode()
        elif response.body:
            yield from response.body

    def route(
        self,
        path: str = ".*",
        scheme: str = "gemini",
        hostname: typing.Optional[str] = None,
        strict_hostname: bool = True,
        strict_trailing_slash: bool = False,
    ) -> typing.Callable:
        """
        Decorator for binding a function to a route based on the URL path.

            app = JetforceApplication()

            @app.route('/my-path')
            def my_path(request):
                return Response(Status.SUCCESS, 'text/plain', 'Hello world!')
        """
        route_pattern = RoutePattern(
            path, scheme, hostname, strict_hostname, strict_trailing_slash
        )

        def wrap(func: typing.Callable) -> typing.Callable:
            self.routes.append((route_pattern, func))
            return func

        return wrap

    def default_callback(self, request: Request) -> Response:
        """
        Set the error response based on the URL type.
        """
        return Response(Status.PERMANENT_FAILURE, "Not Found")

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        """
        Add any application-specific arguments to the GeminiServer parser.

        The destination variables for these arguments should match the method
        signature for this class's __init__ method.
        """
        return


class StaticDirectoryApplication(JetforceApplication):
    """
    Application for serving static files & CGI over gemini.

    This is a batteries-included application that serves files from a static
    directory. It provides a preconfigured gemini server without needing to
    write any lines of code. This is what is invoked when you launch jetforce
    from the command line.

    If a directory contains a file with the name "index.gmi", that file will
    be returned when the directory path is requested. Otherwise, a directory
    listing will be auto-generated.
    """

    def __init__(
        self,
        root_directory: str = "/var/gemini",
        index_file: str = "index.gmi",
        cgi_directory: str = "cgi-bin",
    ):
        super().__init__()
        self.routes.append((RoutePattern(), self.serve_static_file))

        self.root = pathlib.Path(root_directory).resolve(strict=True)
        self.cgi_directory = cgi_directory.strip("/") + "/"

        self.index_file = index_file
        self.mimetypes = mimetypes.MimeTypes()
        self.mimetypes.add_type("text/gemini", ".gmi")
        self.mimetypes.add_type("text/gemini", ".gemini")

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser):
        # fmt: off
        group = parser.add_argument_group("static file configuration")
        group.add_argument(
            "--dir",
            help="Root directory on the filesystem to serve",
            default="/var/gemini",
            metavar="DIR",
            dest="root_directory",
        )
        group.add_argument(
            "--cgi-dir",
            help="CGI script directory, relative to the server's root directory",
            default="cgi-bin",
            metavar="DIR",
            dest="cgi_directory",
        )
        group.add_argument(
            "--index-file",
            help="If a directory contains a file with this name, "
                 "that file will be served instead of auto-generating an index page",
            default="index.gmi",
            metavar="FILE",
            dest="index_file",
        )
        # fmt: on

    def serve_static_file(self, request: Request) -> Response:
        """
        Convert a URL into a filesystem path, and attempt to serve the file
        or directory that is represented at that path.
        """
        url_path = pathlib.Path(request.path.strip("/"))

        filename = pathlib.Path(os.path.normpath(str(url_path)))
        if filename.is_absolute() or str(filename.name).startswith(".."):
            # Guard against breaking out of the directory
            return Response(Status.NOT_FOUND, "Not Found")

        filesystem_path = self.root / filename

        try:
            if not os.access(filesystem_path, os.R_OK):
                # File not readable
                return Response(Status.NOT_FOUND, "Not Found")
        except OSError:
            # Filename too large, etc.
            return Response(Status.NOT_FOUND, "Not Found")

        if filesystem_path.is_file():
            is_cgi = str(filename).startswith(self.cgi_directory)
            is_exe = os.access(filesystem_path, os.X_OK)
            if is_cgi and is_exe:
                return self.run_cgi_script(filesystem_path, request.environ)

            mimetype = self.guess_mimetype(filesystem_path.name)
            generator = self.load_file(filesystem_path)
            return Response(Status.SUCCESS, mimetype, generator)

        elif filesystem_path.is_dir():
            if not request.path.endswith("/"):
                url_parts = urllib.parse.urlparse(request.url)
                # noinspection PyProtectedMember
                url_parts = url_parts._replace(path=request.path + "/")
                return Response(Status.REDIRECT_PERMANENT, url_parts.geturl())

            index_file = filesystem_path / self.index_file
            if index_file.exists():
                generator = self.load_file(index_file)
                return Response(Status.SUCCESS, "text/gemini", generator)

            generator = self.list_directory(url_path, filesystem_path)
            return Response(Status.SUCCESS, "text/gemini", generator)

        else:
            return Response(Status.NOT_FOUND, "Not Found")

    def run_cgi_script(self, filesystem_path: pathlib.Path, environ: dict) -> Response:
        """
        Execute the given file as a CGI script and return the script's stdout
        stream to the client.
        """
        script_name = str(filesystem_path)

        cgi_env = {k: v for k, v in environ.items() if k.isupper()}
        cgi_env["GATEWAY_INTERFACE"] = "GCI/1.1"
        cgi_env["SCRIPT_NAME"] = script_name

        # Decode the stream as unicode so we can parse the status line
        # Use surrogateescape to preserve any non-UTF8 byte sequences.
        out = subprocess.Popen(
            [script_name],
            stdout=subprocess.PIPE,
            env=cgi_env,
            bufsize=1,
            universal_newlines=True,
            errors="surrogateescape",
        )

        status_line = out.stdout.readline().strip()
        status_parts = status_line.split(maxsplit=1)
        if len(status_parts) != 2 or not status_parts[0].isdecimal():
            return Response(Status.CGI_ERROR, "Unexpected Error")

        status, meta = status_parts

        # Re-encode the rest of the body as bytes
        body = codecs.iterencode(out.stdout, encoding="utf-8", errors="surrogateescape")
        return Response(int(status), meta, body)

    def load_file(self, filesystem_path: pathlib.Path) -> typing.Iterator[bytes]:
        """
        Load a file in chunks to allow streaming to the TCP socket.
        """
        with filesystem_path.open("rb") as fp:
            data = fp.read(1024)
            while data:
                yield data
                data = fp.read(1024)

    def list_directory(
        self, url_path: pathlib.Path, filesystem_path: pathlib.Path
    ) -> typing.Iterator[bytes]:
        """
        Auto-generate a text/gemini document based on the contents of the file system.
        """
        yield f"Directory: /{url_path}\r\n".encode()
        if url_path.parent != url_path:
            yield f"=>/{url_path.parent}\t..\r\n".encode()

        for file in sorted(filesystem_path.iterdir()):
            if file.name.startswith("."):
                # Skip hidden directories/files that may contain sensitive info
                continue
            elif file.is_dir():
                yield f"=>/{url_path / file.name}/\t{file.name}/\r\n".encode()
            else:
                yield f"=>/{url_path / file.name}\t{file.name}\r\n".encode()

    def guess_mimetype(self, filename: str) -> str:
        """
        Guess the mimetype of a file based on the file extension.
        """
        mime, encoding = self.mimetypes.guess_type(filename)
        if encoding:
            return f"{mime}; charset={encoding}"
        else:
            return mime or "text/plain"

    def default_callback(self, request: Request) -> Response:
        """
        Since the StaticDirectoryApplication only serves gemini URLs, return
        a proxy request refused for suspicious URLs.
        """
        if request.scheme != "gemini":
            return Response(
                Status.PROXY_REQUEST_REFUSED,
                "This server does not allow proxy requests",
            )
        elif request.hostname != request.environ["HOSTNAME"]:
            return Response(
                Status.PROXY_REQUEST_REFUSED,
                "This server does not allow proxy requests",
            )
        elif request.port and request.port != request.environ["SERVER_PORT"]:
            return Response(
                Status.PROXY_REQUEST_REFUSED,
                "This server does not allow proxy requests",
            )
        else:
            return Response(Status.NOT_FOUND, "Not Found")


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

        Because Gemini requests are only ever a single line long, this will
        only be called once and we can use it to handle the lifetime of the
        connection without managing any state.
        """
        self.request = line
        try:
            self.handle_request()
        finally:
            self.log_request()
            self.transport.loseConnection()

    def handle_request(self):
        try:
            self.parse_header()
        except Exception:
            # Malformed request, throw it away and exit immediately
            self.write_status(Status.BAD_REQUEST, "Malformed request")
            self.flush_status()
            raise

        try:
            environ = self.build_environ()
            response_generator = self.app(environ, self.write_status)
            for data in response_generator:
                self.write_body(data)
        except Exception:
            self.write_status(Status.CGI_ERROR, "An unexpected error occurred")
            raise
        finally:
            self.flush_status()

    def build_environ(self) -> typing.Dict[str, typing.Any]:
        """
        Construct a dictionary that will be passed to the application handler.

        Variable names (mostly) conform to the CGI spec defined in RFC 3875.
        The TLS variable names borrow from the GLV-1.12556 server.
        """
        url_parts = urllib.parse.urlparse(self.url)
        environ = {
            "GEMINI_URL": self.url,
            "HOSTNAME": self.server.hostname,
            "PATH_INFO": url_parts.path,
            "QUERY_STRING": url_parts.query,
            "REMOTE_ADDR": self.client_addr.host,
            "REMOTE_HOST": self.client_addr.host,
            "SERVER_NAME": self.server.hostname,
            "SERVER_PORT": str(self.client_addr.port),
            "SERVER_PROTOCOL": "GEMINI",
            "SERVER_SOFTWARE": f"jetforce/{__version__}",
            "client_certificate": None,
        }

        peer_certificate = self.transport.getPeerCertificate()
        if peer_certificate:
            cert = peer_certificate.to_cryptography()
            environ["client_certificate"] = cert

            # Extract useful information from the client certificate.
            name_attrs = cert.subject.get_attributes_for_oid(CN)
            common_name = name_attrs[0].value if name_attrs else ""

            fingerprint_bytes = cert.fingerprint(hashes.SHA256())
            fingerprint = base64.b64encode(fingerprint_bytes).decode()

            not_before = cert.not_valid_before.strftime("%Y-%m-%dT%H:%M:%SZ")
            not_after = cert.not_valid_after.strftime("%Y-%m-%dT%H:%M:%SZ")

            conn = self.transport.getHandle()

            tls_version = conn.get_protocol_version_name()
            tls_cipher = conn.get_cipher_name()

            # Grab the value that we stashed during the TLS handshake.
            verified = getattr(conn, "preverify_ok", False)

            environ.update(
                {
                    "AUTH_TYPE": "CERTIFICATE",
                    "REMOTE_USER": common_name,
                    "TLS_CIPHER": tls_cipher,
                    "TLS_VERSION": tls_version,
                    "TLS_CLIENT_VERIFIED": verified,
                    "TLS_CLIENT_HASH": fingerprint,
                    "TLS_CLIENT_NOT_BEFORE": not_before,
                    "TLS_CLIENT_NOT_AFTER": not_after,
                    "TLS_CLIENT_SERIAL_NUMBER": cert.serial_number,
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

    def write_body(self, data: bytes) -> None:
        """
        Write bytes to the gemini response body.
        """
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


def generate_ad_hoc_certificate(hostname: str) -> typing.Tuple[str, str]:
    """
    Utility function to generate an ad-hoc self-signed SSL certificate.
    """
    certfile = os.path.join(tempfile.gettempdir(), f"{hostname}.crt")
    keyfile = os.path.join(tempfile.gettempdir(), f"{hostname}.key")

    if not os.path.exists(certfile) or not os.path.exists(keyfile):
        backend = default_backend()

        print("Generating private key...", file=sys.stderr)
        private_key = rsa.generate_private_key(65537, 2048, backend)
        with open(keyfile, "wb") as fp:
            # noinspection PyTypeChecker
            key_data = private_key.private_bytes(
                serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            fp.write(key_data)

        print("Generating certificate...", file=sys.stderr)
        common_name = x509.NameAttribute(CN, hostname)
        subject_name = x509.Name([common_name])
        not_valid_before = datetime.datetime.utcnow()
        not_valid_after = not_valid_before + datetime.timedelta(days=365)
        certificate = x509.CertificateBuilder(
            subject_name=subject_name,
            issuer_name=subject_name,
            public_key=private_key.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
        )
        certificate = certificate.sign(private_key, hashes.SHA256(), backend)
        with open(certfile, "wb") as fp:
            # noinspection PyTypeChecker
            cert_data = certificate.public_bytes(serialization.Encoding.PEM)
            fp.write(cert_data)

    return certfile, keyfile


class GeminiOpenSSLCertificateOptions(CertificateOptions):
    """
    CertificateOptions is a factory function that twisted uses to do all of the
    gnarly OpenSSL setup and return a PyOpenSSL context object. Unfortunately,
    it doesn't do *exactly* what I need it to do, so I need to subclass to add
    some custom behavior.

    References:
        https://twistedmatrix.com/documents/16.1.1/core/howto/ssl.html
        https://github.com/urllib3/urllib3/blob/master/src/urllib3/util/ssl_.py
        https://github.com/twisted/twisted/blob/trunk/src/twisted/internet/_sslverify.py
    """

    def verify_callback(self, conn, cert, errno, depth, preverify_ok):
        """
        Callback used by OpenSSL for client certificate verification.

        preverify_ok returns the verification result that OpenSSL has already
        obtained, so return this value to cede control to the underlying
        library. Returning true will always allow client certificates, even if
        they are self-signed.
        """
        conn.preverify_ok = preverify_ok
        return True

    def proto_select_callback(self, conn, protocols):
        """
        Callback used by OpenSSL for ALPN support.

        Return the first matching protocol in our list of acceptable values.
        """
        for p in self._acceptableProtocols:
            if p in protocols:
                return p
        else:
            return b""

    def __init__(
        self,
        certfile: str,
        keyfile: typing.Optional[str] = None,
        cafile: typing.Optional[str] = None,
        capath: typing.Optional[str] = None,
        **kwargs,
    ):
        self.certfile = certfile
        self.keyfile = keyfile
        self.cafile = cafile
        self.capath = capath
        super().__init__(**kwargs)

    def _makeContext(self):
        """
        Most of this code is copied directly from the parent class method.

        I switched to using the OpenSSL methods that read keys/certs from files
        instead of manually loading the objects into memory. I also added
        configurable verify & ALPN callbacks.
        """
        ctx = self._contextFactory(self.method)
        ctx.set_options(self._options)
        ctx.set_mode(self._mode)

        ctx.use_certificate_file(self.certfile)
        ctx.use_privatekey_file(self.keyfile or self.certfile)
        for extraCert in self.extraCertChain:
            ctx.add_extra_chain_cert(extraCert)
        # Sanity check
        ctx.check_privatekey()

        if self.cafile or self.capath:
            ctx.load_verify_locations(self.cafile, self.capath)

        verify_flags = SSL.VERIFY_PEER
        if self.requireCertificate:
            verify_flags |= SSL.VERIFY_FAIL_IF_NO_PEER_CERT
        if self.verifyOnce:
            verify_flags |= SSL.VERIFY_CLIENT_ONCE

        ctx.set_verify(verify_flags, self.verify_callback)
        if self.verifyDepth is not None:
            ctx.set_verify_depth(self.verifyDepth)

        if self.enableSessions:
            session_name = secureRandom(32)
            ctx.set_session_id(session_name)

        ctx.set_cipher_list(self._cipherString.encode("ascii"))

        self._ecChooser.configureECDHCurve(ctx)

        if self._acceptableProtocols:
            ctx.set_alpn_select_callback(self.proto_select_callback)
            ctx.set_alpn_protos(self._acceptableProtocols)

        return ctx


class GeminiServer(Factory):
    """
    This class acts as a wrapper around most of the plumbing for twisted.

    There's not much going on here, the main intention is to make it as simple
    as possible to import and run a server without needing to understand the
    complicated class hierarchy and conventions defined by twisted.
    """

    # Request handler class, you probably don't want to override this.
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
        **_,
    ):
        if certfile is None:
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

        It builds the protocol instance which acts as a request handler and
        implements the actual Gemini protocol.
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

        certificate_options = GeminiOpenSSLCertificateOptions(
            certfile=self.certfile,
            keyfile=self.keyfile,
            cafile=self.cafile,
            capath=self.capath,
            raiseMinimumTo=TLSVersion.TLSv1_3,
            requireCertificate=False,
            fixBrokenPeers=True,
            # This is for ALPN, I may look into supporting this later.
            acceptableProtocols=None,
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

    @classmethod
    def build_argument_parser(cls):
        """
        Build the default command line argument parser for the jetforce server.
        """
        # fmt: off
        # noinspection PyTypeChecker
        parser = argparse.ArgumentParser(
            prog="jetforce",
            description="An Experimental Gemini Protocol Server",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )
        parser.add_argument(
            "-V", "--version",
            action="version",
            version="jetforce " + __version__
        )
        group = parser.add_argument_group("server configuration")
        group.add_argument(
            "--host",
            help="Server address to bind to",
            default="127.0.0.1"
        )
        group.add_argument(
            "--port",
            help="Server port to bind to",
            type=int,
            default=1965
        )
        group.add_argument(
            "--hostname",
            help="Server hostname",
            default="localhost"
        )
        group.add_argument(
            "--tls-certfile",
            dest="certfile",
            help="Server TLS certificate file",
            metavar="FILE",
        )
        group.add_argument(
            "--tls-keyfile",
            dest="keyfile",
            help="Server TLS private key file",
            metavar="FILE",
        )
        group.add_argument(
            "--tls-cafile",
            dest="cafile",
            help="A CA file to use for validating clients",
            metavar="FILE",
        )
        group.add_argument(
            "--tls-capath",
            dest="capath",
            help="A directory containing CA files for validating clients",
            metavar="DIR",
        )
        # fmt: on
        return parser

    @classmethod
    def from_command_line(
        cls, app_class: typing.Type[JetforceApplication], reactor: ReactorBase = reactor
    ):
        """
        Shortcut to parse command line arguments and build a server instance
        for a class-based jetforce application.
        """
        parser = cls.build_argument_parser()
        app_class.add_arguments(parser)

        args = vars(parser.parse_args())

        # Split command line arguments into the group that should be passed to
        # the server class, and the group that should be passed to the app class.
        keys = cls.__init__.__annotations__.keys()
        server_args = {k: v for k, v in args.items() if k in keys}
        extra_args = {k: v for k, v in args.items() if k not in keys}

        app = app_class(**extra_args)
        return cls(app, reactor, **server_args)


def run_server() -> None:
    """
    Entry point for running the static directory server.
    """
    server = GeminiServer.from_command_line(app_class=StaticDirectoryApplication)
    server.run()


if __name__ == "__main__":
    run_server()
