#!/usr/bin/env python3
"""
Jetforce, an experimental Gemini server.

Overview
--------

GeminiServer:
    An asynchronous TCP server built on top of python's asyncio stream
    abstraction. This is a lightweight class that accepts incoming requests,
    logs them, and sends them to a configurable request handler to be processed.

GeminiRequestHandler:
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
    This is a pre-built application that serves files from a static directory.
    It provides an "out-of-the-box" gemini server without needing to write any
    lines of code. This is what is invoked when you launch jetforce from the
    command line.
"""
from __future__ import annotations

import argparse
import codecs
import dataclasses
import datetime
import mimetypes
import os
import pathlib
import re
import socket
import socketserver
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
parser.add_argument(
    "--host",
    help="Server address to bind to",
    default="127.0.0.1"
)
parser.add_argument(
    "--port",
    help="Server port to bind to",
    type=int,
    default=1965
)
parser.add_argument(
    "--hostname",
    help="Server hostname",
    default="localhost"
)
parser.add_argument(
    "--tls-certfile",
    dest="certfile",
    help="Server TLS certificate file",
    metavar="FILE",
)
parser.add_argument(
    "--tls-keyfile",
    dest="keyfile",
    help="Server TLS private key file",
    metavar="FILE",
)
parser.add_argument(
    "--tls-cafile",
    dest="cafile",
    help="A CA file to use for validating clients",
    metavar="FILE",
)
parser.add_argument(
    "--tls-capath",
    dest="capath",
    help="A directory containing CA files for validating clients",
    metavar="DIR",
)
# Arguments below this line are specific to the StaticDirectoryApplication
parser.add_argument(
    "--dir",
    help="Root directory on the filesystem to serve",
    default="/var/gemini",
    metavar="DIR",
)
parser.add_argument(
    "--cgi-dir",
    help="CGI script directory, relative to the server's root directory",
    default="cgi-bin",
    metavar="DIR",
)
parser.add_argument(
    "--index-file",
    help="If a directory contains a file with this name, "
         "that file will be served instead of auto-generating an index page",
    default="index.gmi",
    metavar="FILE",
)
# fmt: on


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


class StaticDirectoryApplication(JetforceApplication):
    """
    Application for serving static files & CGI over gemini.

    This is a pre-built application that serves files from a static directory.
    It provides an "out-of-the-box" gemini server without needing to write any
    lines of code. This is what is invoked when you launch jetforce from the
    command line.

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
        cgi_env = environ.copy()
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


class GeminiRequestHandler(socketserver.StreamRequestHandler):
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

    server: GeminiServer
    received_timestamp: time.struct_time
    url: str
    status: int
    meta: str
    response_buffer: str
    response_size: int

    def setup(self) -> None:
        self.response_size = 0
        self.response_buffer = ""
        super().setup()

    def handle(self) -> None:
        """
        The request handler entry point, called once for each connection.
        """
        self.received_timestamp = time.localtime()
        self.request.do_handshake()

        try:
            self.parse_header()
        except Exception:
            # Malformed request, throw it away and exit immediately
            self.write_status(Status.BAD_REQUEST, "Malformed request")
            return

        try:
            environ = self.build_environ()
            response_generator = self.server.app(environ, self.write_status)
            for data in response_generator:
                self.write_body(data)
        except Exception:
            self.write_status(Status.CGI_ERROR, "An unexpected error occurred")

    def build_environ(self) -> typing.Dict[str, typing.Any]:
        """
        Construct a dictionary that will be passed to the application handler.

        Variable names conform to the CGI spec defined in RFC 3875.
        """
        url_parts = urllib.parse.urlparse(self.url)
        remote_addr, remote_port, *_ = self.client_address
        environ = {
            "GEMINI_URL": self.url,
            "HOSTNAME": self.server.hostname,
            "PATH_INFO": url_parts.path,
            "QUERY_STRING": url_parts.query,
            "REMOTE_ADDR": remote_addr,
            "REMOTE_HOST": remote_addr,
            "SERVER_NAME": self.server.hostname,
            "SERVER_PORT": str(remote_port),
            "SERVER_PROTOCOL": "GEMINI",
            "SERVER_SOFTWARE": f"jetforce/{__version__}",
        }

        client_cert = self.request.getpeercert()
        if client_cert:
            subject = dict(x[0] for x in client_cert["subject"])
            environ.update(
                {
                    "AUTH_TYPE": "CERTIFICATE",
                    "REMOTE_USER": subject.get("commonName", ""),
                    "TLS_CLIENT_NOT_BEFORE": client_cert["notBefore"],
                    "TLS_CLIENT_NOT_AFTER": client_cert["notAfter"],
                    "TLS_CLIENT_SERIAL_NUMBER": client_cert["serialNumber"],
                }
            )

        return environ

    def parse_header(self) -> None:
        """
        Parse the gemini header line.

        The request is a single UTF-8 line formatted as: <URL>\r\n
        """
        data = self.rfile.readline(1026)
        data = data.rstrip(b"\r\n")
        if len(data) > 1024:
            raise ValueError("URL exceeds max length of 1024 bytes")

        self.url = data.decode()

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
        self.wfile.write(data)

    def flush_status(self) -> None:
        """
        Flush the status line from the internal buffer to the socket stream.
        """
        if self.response_buffer and not self.response_size:
            data = self.response_buffer.encode()
            self.response_size += len(data)
            self.wfile.write(data)
        self.response_buffer = ""

    def finish(self) -> None:
        self.flush_status()
        try:
            self.log_request()
        except AttributeError:
            # Malformed request or dropped connection
            pass
        super().finish()

    def log_request(self) -> None:
        """
        Log a gemini request using a format derived from the Common Log Format.
        """
        self.server.log_message(
            f"{self.client_address[0]} "
            f"[{time.strftime(self.TIMESTAMP_FORMAT, self.received_timestamp)}] "
            f'"{self.url}" '
            f"{self.status} "
            f'"{self.meta}" '
            f"{self.response_size}"
        )


class GeminiServer(socketserver.ThreadingTCPServer):
    """
    An asynchronous TCP server that uses the asyncio stream abstraction.

    This is a lightweight class that accepts incoming requests, logs them, and
    sends them to a configurable request handler to be processed.
    """

    request_handler_class = GeminiRequestHandler

    def __init__(
        self,
        app: typing.Callable,
        host: str = "127.0.0.1",
        port: int = 1965,
        ssl_context: SSL.Context = None,
        hostname: str = "localhost",
    ) -> None:

        self.app = app
        self.hostname = hostname
        self.ssl_context = ssl_context
        super().__init__((host, port), self.request_handler_class, False)

    def run(self) -> None:
        """
        Launch the main server loop.
        """
        self.log_message(ABOUT)
        self.log_message(f"Server hostname is {self.hostname}")
        try:
            self.server_bind()
            self.server_activate()
        except Exception:
            self.server_close()
            raise

        sock_ip, sock_port, *_ = self.server_address
        if self.address_family == socket.AF_INET:
            self.log_message(f"Listening on {sock_ip}:{sock_port}")
        else:
            self.log_message(f"Listening on [{sock_ip}]:{sock_port}")

        self.serve_forever()

    def get_request(self) -> typing.Tuple[SSL.Connection, typing.Tuple[str, int]]:
        """
        Wrap the incoming request in an SSL connection.
        """
        # noinspection PyTupleAssignmentBalance
        sock, client_addr = super(GeminiServer, self).get_request()
        sock = SSL.Connection(self.ssl_context, sock)
        return sock, client_addr

    def log_message(self, message: str) -> None:
        """
        Log a diagnostic server message to stderr, may be overridden.
        """
        print(message, file=sys.stderr)


def generate_ad_hoc_certificate(hostname: str) -> typing.Tuple[str, str]:
    """
    Utility function to generate an ad-hoc self-signed SSL certificate.
    """
    certfile = os.path.join(tempfile.gettempdir(), f"{hostname}.crt")
    keyfile = os.path.join(tempfile.gettempdir(), f"{hostname}.key")

    if not os.path.exists(certfile) or not os.path.exists(keyfile):
        backend = default_backend()

        print("Generating private key...", file=sys.stderr)
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        with open(keyfile, "wb") as fp:
            # noinspection PyTypeChecker
            key_data = private_key.private_bytes(
                serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            fp.write(key_data)

        print("Generating certificate...", file=sys.stderr)
        common_name = x509.NameAttribute(x509.NameOID.COMMON_NAME, hostname)
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


def make_ssl_context(
    hostname: str = "localhost",
    certfile: typing.Optional[str] = None,
    keyfile: typing.Optional[str] = None,
    cafile: typing.Optional[str] = None,
    capath: typing.Optional[str] = None,
) -> SSL.Context:
    """
    Generate a sane default SSL context for a Gemini server.
    """
    if certfile is None:
        certfile, keyfile = generate_ad_hoc_certificate(hostname)

    context = SSL.Context(SSL.TLSv1_2_METHOD)
    context.use_certificate_file(certfile)
    context.use_privatekey_file(keyfile or certfile)
    context.check_privatekey()
    if cafile or capath:
        context.load_verify_locations(cafile, capath)

    def verify_cb(connection, x509, err_no, err_depth, return_code):
        pass

    context.set_verify(SSL.VERIFY_PEER, verify_cb)

    return context


def run_server() -> None:
    """
    Entry point for running the static directory server.
    """
    args = parser.parse_args()
    app = StaticDirectoryApplication(args.dir, args.index_file, args.cgi_dir)
    ssl_context = make_ssl_context(
        args.hostname, args.certfile, args.keyfile, args.cafile, args.capath
    )
    server = GeminiServer(app, args.host, args.port, ssl_context, args.hostname)
    server.run()


if __name__ == "__main__":
    run_server()
