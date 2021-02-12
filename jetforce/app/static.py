import mimetypes
import os
import pathlib
import subprocess
import typing
import urllib.parse

from twisted.internet import reactor
from twisted.internet.task import deferLater
from twisted.internet.defer import Deferred

from .base import (
    EnvironDict,
    JetforceApplication,
    RateLimiter,
    Request,
    Response,
    RoutePattern,
    Status,
)


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

    # Chunk size for streaming files, taken from the twisted FileSender class
    CHUNK_SIZE = 2 ** 14

    # Length of time to defer while waiting for more data from a CGI script
    CGI_POLLING_PERIOD = 0.05

    # Maximum size in bytes of the first line of a server response
    CGI_MAX_RESPONSE_HEADER_SIZE = 2048

    mimetypes: mimetypes.MimeTypes

    def __init__(
        self,
        root_directory: str = "/var/gemini",
        index_file: str = "index.gmi",
        cgi_directory: str = "cgi-bin",
        default_lang: typing.Optional[str] = None,
        rate_limiter: typing.Optional[RateLimiter] = None,
    ):
        super().__init__(rate_limiter=rate_limiter)

        self.routes.append((RoutePattern(), self.serve_static_file))

        self.root = pathlib.Path(root_directory).resolve(strict=True)
        self.cgi_directory = cgi_directory.strip("/") + "/"
        self.default_lang = default_lang

        self.index_file = index_file
        self.mimetypes = mimetypes.MimeTypes()
        # We need to manually load all of the operating system mimetype files
        # https://bugs.python.org/issue38656
        for fn in mimetypes.knownfiles:
            if os.path.isfile(fn):
                self.mimetypes.read(fn)

        # This is a valid method but the type stubs are incorrect
        self.mimetypes.add_type("text/gemini", ".gmi")  # type: ignore
        self.mimetypes.add_type("text/gemini", ".gemini")  # type: ignore

    def serve_static_file(self, request: Request) -> Response:
        """
        Convert a URL into a filesystem path, and attempt to serve the file
        or directory that is represented at that path.
        """
        url_path = pathlib.Path(request.path.strip("/"))

        filename = pathlib.Path(os.path.normpath(str(url_path)))
        if filename.is_absolute() or str(filename).startswith(".."):
            # Guard against breaking out of the directory
            return Response(Status.NOT_FOUND, "Not Found")

        if str(filename).startswith(self.cgi_directory):
            # CGI needs special treatment to account for extra-path
            # PATH_INFO component (RFC 3875 section 4.1.5)

            # Identify the shortest path that is not a directory
            for i in range(2, len(filename.parts) + 1):
                # Split the path into SCRIPT_NAME and PATH_INFO
                script_name = pathlib.Path(*filename.parts[:i])
                path_info = pathlib.Path(*filename.parts[i:])

                filesystem_path = self.root / script_name
                try:
                    if not filesystem_path.is_file():
                        continue
                    elif not os.access(filesystem_path, os.R_OK):
                        continue
                    elif not os.access(filesystem_path, os.X_OK):
                        continue
                    else:
                        if str(script_name) == ".":
                            request.environ["SCRIPT_NAME"] = ""
                        else:
                            request.environ["SCRIPT_NAME"] = f"/{script_name}"

                        if str(path_info) == ".":
                            request.environ["PATH_INFO"] = ""
                        else:
                            request.environ["PATH_INFO"] = f"/{path_info}"

                        return self.run_cgi_script(filesystem_path, request.environ)

                except OSError:
                    # Filename too large, etc.
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
            mimetype = self.guess_mimetype(filesystem_path.name)
            mimetype = self.add_extra_parameters(mimetype)
            generator = self.load_file(filesystem_path)
            return Response(Status.SUCCESS, mimetype, generator)

        elif filesystem_path.is_dir():
            if request.path and not request.path.endswith("/"):
                url_parts = urllib.parse.urlparse(request.url)
                # noinspection PyProtectedMember
                url_parts = url_parts._replace(path=request.path + "/")
                return Response(Status.REDIRECT_PERMANENT, url_parts.geturl())

            index_file = filesystem_path / self.index_file
            if index_file.exists():
                mimetype = self.add_extra_parameters("text/gemini")
                generator = self.load_file(index_file)
                return Response(Status.SUCCESS, mimetype, generator)

            mimetype = self.add_extra_parameters("text/gemini")
            generator = self.list_directory(url_path, filesystem_path)
            return Response(Status.SUCCESS, mimetype, generator)

        else:
            return Response(Status.NOT_FOUND, "Not Found")

    def run_cgi_script(
        self, filesystem_path: typing.Union[str, pathlib.Path], environ: EnvironDict
    ) -> Response:
        """
        Execute the given file as a CGI script and return the script's stdout
        stream to the client.
        """
        cgi_env = {k: str(v) for k, v in environ.items() if k.isupper()}
        cgi_env["GATEWAY_INTERFACE"] = "CGI/1.1"

        proc = subprocess.Popen(
            [str(filesystem_path)],
            stdout=subprocess.PIPE,
            env=cgi_env,
            bufsize=0,
        )
        proc.stdout = typing.cast(typing.IO[bytes], proc.stdout)

        status_line = proc.stdout.readline(self.CGI_MAX_RESPONSE_HEADER_SIZE)
        if len(status_line) == self.CGI_MAX_RESPONSE_HEADER_SIZE:
            # Too large response header line received from the CGI script.
            return Response(Status.CGI_ERROR, "Unexpected Error")

        status_parts = status_line.decode().strip().split(maxsplit=1)
        if len(status_parts) != 2 or not status_parts[0].isdecimal():
            # Malformed header line received from the CGI script.
            return Response(Status.CGI_ERROR, "Unexpected Error")

        status, meta = status_parts
        return Response(int(status), meta, self.cgi_body_generator(proc))

    def cgi_body_generator(
        self,
        proc: subprocess.Popen,
    ) -> typing.Iterator[typing.Union[bytes, Deferred]]:
        """
        Non-blocking read from the stdout of the CGI process and pipe it
        to the socket transport.
        """
        proc.stdout = typing.cast(typing.IO[bytes], proc.stdout)

        while True:
            proc.poll()

            data = proc.stdout.read(self.CHUNK_SIZE)
            if len(data) == self.CHUNK_SIZE:
                # Send the chunk and yield control of the event loop
                yield data
            elif proc.returncode is None:
                # We didn't get a full chunk's worth of data from the
                # subprocess. Send what we have, but add a delay before
                # attempting to read again to allow time for more bytes
                # to buffer in stdout.
                if data:
                    yield data
                yield deferLater(reactor, self.CGI_POLLING_PERIOD)
            else:
                # Subprocess has finished, send everything that's left.
                if data:
                    yield data
                break

    def load_file(self, filesystem_path: pathlib.Path) -> typing.Iterator[bytes]:
        """
        Load a file in chunks to allow streaming to the TCP socket.
        """
        with filesystem_path.open("rb") as fp:
            while True:
                data = fp.read(self.CHUNK_SIZE)
                if not data:
                    break
                yield data

    def list_directory(
        self, url_path: pathlib.Path, filesystem_path: pathlib.Path
    ) -> typing.Iterator[bytes]:
        """
        Auto-generate a text/gemini document based on the contents of the file system.
        """
        buffer = f"Directory: /{url_path}\r\n".encode()
        if url_path.parent != url_path:
            buffer += f"=>/{url_path.parent}\t..\r\n".encode()

        for file in sorted(filesystem_path.iterdir()):
            if file.name.startswith("."):
                # Skip hidden directories/files that may contain sensitive info
                continue

            encoded_path = urllib.parse.quote(str(url_path / file.name))
            if file.is_dir():
                buffer += f"=>/{encoded_path}/\t{file.name}/\r\n".encode()
            else:
                buffer += f"=>/{encoded_path}\t{file.name}\r\n".encode()

            if len(buffer) >= self.CHUNK_SIZE:
                data, buffer = buffer[: self.CHUNK_SIZE], buffer[self.CHUNK_SIZE :]
                yield data

        if buffer:
            yield buffer

    def guess_mimetype(self, filename: str) -> str:
        """
        Guess the mimetype of a file based on the file extension.
        """
        mime, encoding = self.mimetypes.guess_type(filename)
        if encoding:
            return f"{mime}; charset={encoding}"
        else:
            return mime or "application/octet-stream"

    def add_extra_parameters(self, meta: str) -> str:
        """
        Attach extra parameters to the response meta string.
        """
        if self.default_lang is not None:
            if meta.startswith("text/gemini"):
                meta += f"; lang={self.default_lang}"
        return meta

    def default_callback(self, request: Request, **_: typing.Any) -> Response:
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
