import mimetypes
import os
import pathlib
import typing
import urllib.parse

from twisted.internet import protocol, reactor
from twisted.internet.defer import Deferred

from jetforce.app.base import (
    DeferredResponse,
    EnvironDict,
    JetforceApplication,
    RateLimiter,
    Request,
    Response,
    RoutePattern,
    Status,
)


class CGISubprocessProtocol(protocol.ProcessProtocol):
    """
    Twisted ProcessProtocol for handling CGI script execution asynchronously.

    This protocol manages the lifecycle of a CGI subprocess, capturing its
    stdout output and parsing the CGI response header (status line) before
    streaming the body data back through deferred objects.
    """

    # Maximum size in bytes of the first line of a server response
    CGI_MAX_RESPONSE_HEADER_SIZE = 2048

    def __init__(self):
        self.send_status: Deferred[tuple[int, str]] = Deferred()
        self.status_line_sent = False
        self.status_line_buffer = b""
        self.pending_deferred: Deferred[bytes] = Deferred()
        self.process_ended = False
        self.error_occurred = False

    def outReceived(self, data: bytes) -> None:
        """
        Called when data is received from the subprocess stdout.
        """
        print(data)
        if self.error_occurred:
            return

        if self.status_line_sent:
            # Status line already sent, send the data immediately
            self._resolve_pending(data)
            return

        # Still parsing the status line
        self.status_line_buffer += data

        if b"\n" in self.status_line_buffer:
            # Found the end of the status line
            status_line, remaining_data = self.status_line_buffer.split(b"\n", 1)

            if len(status_line) >= self.CGI_MAX_RESPONSE_HEADER_SIZE:
                # Status line is too large
                self.error_occurred = True
                self._resolve_status(Status.CGI_ERROR, "Unexpected Error")
                return

            status_parts = status_line.decode().strip().split(maxsplit=1)
            if len(status_parts) != 2 or not status_parts[0].isdecimal():
                # Malformed header line
                self.error_occurred = True
                self._resolve_status(Status.CGI_ERROR, "Unexpected Error")
                return

            status, meta = status_parts
            self._resolve_status(int(status), meta)
            self.status_line_sent = True

            # If there's remaining data after the status line, send it
            if remaining_data:
                self._resolve_pending(remaining_data)

    def processEnded(self, reason) -> None:
        """
        Called when the subprocess has ended.
        """
        self.process_ended = True

        # If we never sent the status line, send an error
        if not self.status_line_sent and not self.error_occurred:
            self.error_occurred = True
            self._resolve_status(Status.CGI_ERROR, "Unexpected Error")

        # Resolve the last deferred to signal the end
        self._resolve_pending(b"")

    def _resolve_pending(self, data: bytes) -> None:
        """
        Helper method to resolve the pending deferred with the given data.
        """
        if not self.pending_deferred.called:
            self.pending_deferred.callback(data)

    def _resolve_status(self, status: int, meta: str) -> None:
        """
        Helper method to resolve the status deferred with status and meta.
        """
        if not self.send_status.called:
            self.send_status.callback((status, meta))

    def body_generator(self) -> typing.Iterator[Deferred[bytes]]:
        """
        Generator that yields deferred objects which resolve when the CGI
        process has data available.
        """
        while not self.process_ended:
            # Create a new deferred that will resolve when data is available
            self.pending_deferred = Deferred()
            yield self.pending_deferred


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
    CHUNK_SIZE = 2**14

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

        # The mimetype library will try to split out the compression algorithm
        # from the underlying filetype, e.g. "./file.mbox.gz" will be parsed as
        # mimetype="application/mbox",encoding="gzip". This is useful for
        # HTTP because you can then set the encoding using the Content-Encoding
        # header. However, for gemini there is no way to specify the encoding
        # of a response, so we need to disable this behavior and stick to
        # straight mimetypes for compressed files.
        self.mimetypes.encodings_map = {}
        self.mimetypes.add_type("application/gzip", ".gz")  # type: ignore
        self.mimetypes.add_type("application/x-bzip2", ".bz2")  # type: ignore

        # Add some non-standard mimetypes
        self.mimetypes.add_type("text/gemini", ".gmi")  # type: ignore
        self.mimetypes.add_type("text/gemini", ".gemini")  # type: ignore

    def serve_static_file(
        self,
        request: Request,
    ) -> typing.Union[Response, DeferredResponse]:
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

                        # Add back the trailing slash that was stripped off
                        if request.path.endswith("/"):
                            request.environ["PATH_INFO"] += "/"

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
        self,
        filesystem_path: typing.Union[str, pathlib.Path],
        environ: EnvironDict,
    ) -> DeferredResponse:
        """
        Execute the given file as a CGI script and return the script's stdout
        stream to the client using Twisted's ProcessProtocol.
        """
        cgi_env = {k: str(v) for k, v in environ.items() if k.isupper()}
        cgi_env["GATEWAY_INTERFACE"] = "CGI/1.1"

        cgi_protocol = CGISubprocessProtocol()

        # Spawn the CGI process using Twisted's reactor
        reactor.spawnProcess(  # type: ignore
            cgi_protocol,
            str(filesystem_path),
            [str(filesystem_path)],
            env=cgi_env,
        )

        return DeferredResponse(
            cgi_protocol.send_status,
            cgi_protocol.body_generator(),
        )

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
        mimetype, _ = self.mimetypes.guess_type(filename)
        return mimetype or "application/octet-stream"

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
