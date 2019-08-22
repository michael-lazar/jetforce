"""
This is an example of setting up a Gemini server to proxy requests to other
protocols. This application will accept HTTP URLs, download and render them
locally using the `w3m` tool, and render the output to the client as plain text.
"""
import asyncio
import subprocess

import jetforce
from jetforce import Response, Status

app = jetforce.JetforceApplication()


@app.route(scheme="https", strict_hostname=False)
@app.route(scheme="http", strict_hostname=False)
def proxy_request(request):
    command = [b"w3m", b"-dump", request.url.encode()]
    try:
        out = subprocess.run(command, stdout=subprocess.PIPE)
        out.check_returncode()
    except Exception:
        return Response(Status.CGI_ERROR, "Failed to load URL")
    else:
        return Response(Status.SUCCESS, "text/plain", out.stdout)


if __name__ == "__main__":
    args = jetforce.command_line_parser().parse_args()
    server = jetforce.GeminiServer(
        host=args.host,
        port=args.port,
        certfile=args.certfile,
        keyfile=args.keyfile,
        hostname=args.hostname,
        app=app,
    )
    asyncio.run(server.run())
