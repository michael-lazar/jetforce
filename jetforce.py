#!/usr/bin/env python3.7
import argparse
import asyncio
import datetime
import mimetypes
import os
import pathlib
import ssl
import subprocess
import sys
import tempfile
import typing
import urllib.parse

# Fail early to avoid crashing with an obscure error
if sys.version_info < (3, 7):
    sys.exit("Fatal Error: jetforce requires Python 3.7+")

__version__ = "0.0.5"
__title__ = "Jetforce Gemini Server"
__author__ = "Michael Lazar"
__license__ = "GNU General Public License v3.0"
__copyright__ = "(c) 2019 Michael Lazar"

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

EPILOG = """
If the TLS cert/keyfile is not provided, a self-signed certificate will
automatically be generated and saved to your temporary file directory.
"""

STATUS_INPUT = 10

STATUS_SUCCESS = 20
STATUS_SUCCESS_END_OF_SESSION = 21

STATUS_REDIRECT_TEMPORARY = 30
STATUS_REDIRECT_PERMANENT = 31
STATUS_TEMPORARY_FAILURE = 40
STATUS_SERVER_UNAVAILABLE = 41
STATUS_CGI_ERROR = 42
STATUS_PROXY_ERROR = 43
STATUS_SLOW_DOWN = 44

STATUS_PERMANENT_FAILURE = 50
STATUS_NOT_FOUND = 51
STATUS_GONE = 52
STATUS_PROXY_REQUEST_REFUSED = 53
STATUS_BAD_REQUEST = 59

STATUS_CLIENT_CERTIFICATE_REQUIRED = 60
STATUS_TRANSIENT_CERTIFICATE_REQUESTED = 61
STATUS_AUTHORISED_CERTIFICATE_REQUIRED = 62
STATUS_CERTIFICATE_NOT_ACCEPTED = 63
STATUS_FUTURE_CERTIFICATE_REJECTED = 64
STATUS_EXPIRED_CERTIFICATE_REJECTED = 65


class EchoApp:
    """
    A simple application that echos back the requested path.
    """

    def __init__(self, environ: dict, send_status: typing.Callable) -> None:
        self.environ = environ
        self.send_status = send_status

    def __iter__(self) -> typing.Iterator[bytes]:
        self.send_status(STATUS_SUCCESS, "text/plain")
        url = self.environ["RAW_URL"]
        yield f"Received path: {url}".encode()


class StaticDirectoryApp:
    """
    Serve a static directory over Gemini.

    If a directory contains a hidden file with the name ".gemini", that file
    will be returned when the directory path is requested. Otherwise, a
    directory listing will be auto-generated.
    """

    def __init__(self, root: str, environ: dict, send_status: typing.Callable) -> None:
        self.root = pathlib.Path(root).resolve(strict=True)
        self.environ = environ
        self.send_status = send_status
        self.mimetypes = mimetypes.MimeTypes()

    @classmethod
    def serve_directory(cls, root: str) -> typing.Callable:
        """
        Return an app that points to the given root directory on the file system.
        """

        def build_class(environ: dict, send_status: typing.Callable):
            return cls(root, environ, send_status)

        return build_class

    def __iter__(self) -> typing.Iterator[bytes]:
        url_path = pathlib.Path(self.environ["URL"].path.strip("/"))

        filename = pathlib.Path(os.path.normpath(str(url_path)))
        if filename.is_absolute() or str(filename.name).startswith(".."):
            # Guard against breaking out of the directory
            self.send_status(STATUS_NOT_FOUND, "Not Found")
            return
        else:
            filesystem_path = self.root / filename

        if filesystem_path.is_file():
            mimetype = self.guess_mimetype(filesystem_path.name)
            yield from self.load_file(filesystem_path, mimetype)

        elif filesystem_path.is_dir():
            gemini_file = filesystem_path / ".gemini"
            if gemini_file.exists():
                yield from self.load_file(gemini_file, "text/gemini")
            else:
                yield from self.list_directory(url_path, filesystem_path)

        else:
            self.send_status(STATUS_NOT_FOUND, "Not Found")

    def load_file(self, filesystem_path: pathlib.Path, mimetype: str):
        self.send_status(STATUS_SUCCESS, mimetype)
        with filesystem_path.open("rb") as fp:
            data = fp.read(1024)
            while data:
                yield data
                data = fp.read(1024)

    def list_directory(self, url_path: pathlib.Path, filesystem_path: pathlib.Path):
        self.send_status(STATUS_SUCCESS, "text/gemini")

        yield f"Directory: /{url_path}\r\n".encode()
        if url_path.parent != url_path:
            yield f"=>/{url_path.parent}\t..\r\n".encode()

        for file in sorted(filesystem_path.iterdir()):
            if file.name.startswith((".", "~")):
                # Skip hidden and temporary files for security reasons
                continue
            elif file.is_dir():
                yield f"=>/{url_path / file.name}\t{file.name}/\r\n".encode()
            else:
                yield f"=>/{url_path / file.name}\t{file.name}\r\n".encode()

    def guess_mimetype(self, filename: str):
        mime, encoding = self.mimetypes.guess_type(filename)
        if encoding:
            return f"{mime}; charset={encoding}"
        elif mime:
            return mime
        else:
            return "text/plain"


class GeminiRequestHandler:
    """
    Handle a single Gemini Protocol TCP request.

    This design borrows heavily from the standard library's HTTP request
    handler (http.server.BaseHTTPRequestHandler). However, I did not make any
    attempts to directly emulate the existing conventions, because Gemini is an
    inherently simpler protocol than HTTP and much of the boilerplate could be
    removed or slimmed-down.
    """

    def __init__(self, server: "GeminiServer", app: typing.Callable) -> None:
        self.server = server
        self.app = app
        self.reader: typing.Optional[asyncio.StreamReader] = None
        self.writer: typing.Optional[asyncio.StreamWriter] = None
        self.received_timestamp: typing.Optional[datetime.datetime] = None
        self.remote_addr: typing.Optional[str] = None
        self.raw_url: typing.Optional[str] = None
        self.url: typing.Optional[urllib.parse.ParseResult] = None
        self.status: typing.Optional[int] = None
        self.meta: typing.Optional[str] = None
        self.response_buffer: typing.Optional[str] = None
        self.response_size: int = 0

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Main method for the request handler, performs the following:

            1. Read the request bytes from the reader stream
            2. Parse the request and generate response data
            3. Write the response bytes to the writer stream
        """
        self.reader = reader
        self.writer = writer
        self.remote_addr = writer.get_extra_info("peername")[0]
        self.received_timestamp = datetime.datetime.utcnow()

        try:
            await self.parse_header()
        except Exception:
            # Malformed request, throw it away and exit immediately
            self.write_status(STATUS_BAD_REQUEST, "Could not understand request line")
            return await self.close_connection()

        # Discard proxy requests, may revisit this in a later version
        if self.url.scheme and self.url.scheme != "gemini":
            self.write_status(
                STATUS_PROXY_REQUEST_REFUSED, 'URL scheme must be "gemini://"'
            )
            return await self.close_connection()
        elif self.url.hostname and self.url.hostname != self.server.hostname:
            self.write_status(
                STATUS_PROXY_REQUEST_REFUSED,
                f'URL hostname must be "{self.server.hostname}"',
            )
            return await self.close_connection()

        try:
            environ = self.build_environ()
            app = self.app(environ, self.write_status)
            for data in app:
                await self.write_body(data)
        except Exception as e:
            self.write_status(STATUS_CGI_ERROR, str(e))
            raise
        finally:
            await self.close_connection()

    def build_environ(self) -> typing.Dict[str, typing.Any]:
        """
        Construct a dictionary that will be passed to the application handler.
        """
        return {
            "SERVER_HOST": self.server.host,
            "SERVER_PORT": self.server.port,
            "REMOTE_ADDR": self.remote_addr,
            "HOSTNAME": self.server.hostname,
            "RAW_URL": self.raw_url,
            "URL": self.url,
        }

    async def parse_header(self) -> None:
        """
        Parse the gemini header line.

        The request is a single UTF-8 line formatted as: <URL>\r\n
        """
        data = await self.reader.readuntil(b"\r\n")
        data = data[:-2]  # strip the line ending
        if len(data) > 1024:
            raise ValueError("URL exceeds max length of 1024 bytes")

        self.raw_url = data.decode()
        self.url = urllib.parse.urlparse(self.raw_url)
        if not self.url.netloc:
            # URL does not contain a scheme and was not prefixed with // per RFC 1808
            # TODO: Suggest spec should enforce // when scheme is omitted
            self.url = urllib.parse.urlparse(f"//{self.raw_url}")

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
        # TODO: enforce restriction on response meta <= 1024 bytes
        self.status = status
        self.meta = meta
        self.response_buffer = f"{status}\t{meta}\r\n"

    async def write_body(self, data: bytes) -> None:
        """
        Write bytes to the gemini response body.
        """
        await self.flush_status()
        self.response_size += len(data)
        self.writer.write(data)
        await self.writer.drain()

    async def flush_status(self) -> None:
        """
        Flush the status line from the internal buffer to the socket stream.
        """
        if self.response_buffer and not self.response_size:
            data = self.response_buffer.encode()
            self.response_size += len(data)
            self.writer.write(data)
            await self.writer.drain()
        self.response_buffer = None

    async def close_connection(self) -> None:
        """
        Flush any remaining bytes and close the stream.
        """
        await self.flush_status()
        self.log_request()
        await self.writer.drain()

    def log_request(self) -> None:
        """
        Log a gemini request using a format derived from the Common Log Format.
        """
        self.server.log_message(
            f"{self.remote_addr} "
            f"[{self.received_timestamp:%d/%b/%Y:%H:%M:%S +0000}] "
            f'"{self.raw_url}" '
            f"{self.status} "
            f'"{self.meta}" '
            f"{self.response_size}"
        )


class GeminiServer:
    """
    An asynchronous TCP server that understands the Gemini Protocol.
    """

    request_handler_class = GeminiRequestHandler

    def __init__(
        self,
        host: str,
        port: int,
        ssl_context: ssl.SSLContext,
        hostname: str,
        app: typing.Callable,
    ) -> None:
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.hostname = hostname
        self.app = app

    async def run(self) -> None:
        """
        The main asynchronous server loop.
        """
        self.log_message(ABOUT)
        server = await asyncio.start_server(
            self.accept_connection, self.host, self.port, ssl=self.ssl_context
        )

        socket_info = server.sockets[0].getsockname()
        self.log_message(f"Server hostname is {self.hostname}")
        self.log_message(f"Listening on {socket_info[0]}:{socket_info[1]}")

        async with server:
            await server.serve_forever()

    async def accept_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """
        Hook called by the socket server when a new connection is accepted.
        """
        request_handler = self.request_handler_class(self, self.app)
        try:
            await request_handler.handle(reader, writer)
        finally:
            writer.close()

    def log_message(self, message: str):
        """
        Log a diagnostic server message.
        """
        print(message, file=sys.stderr)


def generate_tls_certificate(hostname: str) -> typing.Tuple[str, str]:
    """
    Utility function to generate a self-signed SSL certificate key pair if
    one isn't provided. Results may vary depending on your version of OpenSSL.
    """
    certfile = pathlib.Path(tempfile.gettempdir()) / f"{hostname}.crt"
    keyfile = pathlib.Path(tempfile.gettempdir()) / f"{hostname}.key"
    if not certfile.exists() or not keyfile.exists():
        print(f"Writing ad hoc TLS certificate to {certfile}")
        subprocess.run(
            [
                f"openssl req -newkey rsa:2048 -nodes -keyout {keyfile}"
                f' -nodes -x509 -out {certfile} -subj "/CN={hostname}"'
            ],
            shell=True,
            check=True,
        )
    return str(certfile), str(keyfile)


def run_server() -> None:
    """
    Entry point for running the command line directory server.
    """
    parser = argparse.ArgumentParser(
        prog="jetforce",
        description="An Experimental Gemini Protocol Server",
        epilog=EPILOG,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", help="Address to bind server to", default="127.0.0.1")
    parser.add_argument("--port", help="Port to bind server to", type=int, default=1965)
    parser.add_argument("--tls-certfile", help="TLS certificate file", metavar="FILE")
    parser.add_argument("--tls-keyfile", help="TLS private key file", metavar="FILE")
    parser.add_argument("--hostname", help="Server hostname", default="localhost")
    parser.add_argument("--dir", help="local directory to serve", default="/var/gemini")
    args = parser.parse_args()

    certfile, keyfile = args.tls_certfile, args.tls_keyfile
    if not certfile:
        certfile, keyfile = generate_tls_certificate(args.hostname)

    ssl_context = ssl.SSLContext()
    ssl_context.load_cert_chain(certfile, keyfile)

    server = GeminiServer(
        host=args.host,
        port=args.port,
        ssl_context=ssl_context,
        hostname=args.hostname,
        app=StaticDirectoryApp.serve_directory(args.dir),
    )
    asyncio.run(server.run())


if __name__ == "__main__":
    run_server()
