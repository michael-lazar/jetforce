"""
A server that proxies HTTP websites over gemini.

This example demonstrates how your application routes aren't just limited to
gemini URLs. The server will accept any HTTP URL, download the page and
render it using the external `w3m` tool, and then render the output to the
client as plain-text.

Most gemini clients won't be able to make this request, because the hostname
in the URL doesn't match the hostname of the server. You can test this out
using jetforce-client like this:

> jetforce-client https://mozz.us --host localhost
"""
import subprocess

from jetforce import GeminiServer, JetforceApplication, Response, Status

app = JetforceApplication()


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
    server = GeminiServer(app)
    server.run()
