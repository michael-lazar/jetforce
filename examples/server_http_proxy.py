"""
This is an example of setting up a Gemini server to proxy requests to other
protocols. This application will accept HTTP URLs, download and render them
locally using the `w3m` tool, and render the output to the client as plain text.
"""
import asyncio
import subprocess
import typing
import urllib.parse

import jetforce


class HTTPProxyApplication(jetforce.BaseApplication):

    command = [b"w3m", b"-dump"]

    def __call__(
        self, environ: dict, send_status: typing.Callable
    ) -> typing.Iterator[bytes]:
        url = environ["URL"]
        url_parts = urllib.parse.urlparse(url)
        if url_parts.scheme not in ("http", "https"):
            return send_status(jetforce.STATUS_NOT_FOUND, "Invalid Resource")

        try:
            command = self.command + [url.encode()]
            out = subprocess.run(command, stdout=subprocess.PIPE)
            out.check_returncode()
        except Exception:
            send_status(jetforce.STATUS_CGI_ERROR, "Failed to load URL")
        else:
            send_status(jetforce.STATUS_SUCCESS, "text/plain")
            yield out.stdout


if __name__ == "__main__":
    parser = jetforce.build_argument_parser()
    args = parser.parse_args()
    app = HTTPProxyApplication()
    server = jetforce.GeminiServer(
        host=args.host,
        port=args.port,
        certfile=args.certfile,
        keyfile=args.keyfile,
        hostname=args.hostname,
        app=app,
    )
    asyncio.run(server.run())
