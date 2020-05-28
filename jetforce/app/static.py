import codecs
import mimetypes
import os
import pathlib
import subprocess
import typing
import urllib.parse

from .base import JetforceApplication, Request, Response, RoutePattern, Status


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
        cgi_env = {k: str(v) for k, v in environ.items() if k.isupper()}
        cgi_env["GATEWAY_INTERFACE"] = "GCI/1.1"

        # Decode the stream as unicode so we can parse the status line
        # Use surrogateescape to preserve any non-UTF8 byte sequences.
        out = subprocess.Popen(
            [str(filesystem_path)],
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

    def default_callback(self, request: Request, **_) -> Response:
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
