#!/usr/local/env python3
"""
This example shows how you can extend the jetforce static directory server to
support advanced behavior like custom redirects and directory authentication.
"""

from jetforce import GeminiServer, Response, StaticDirectoryApplication, Status

app = StaticDirectoryApplication("/var/gemini")


# Example of registering a custom file extension
app.mimetypes.add_type("text/gemini", ".gemlog")  # type: ignore


@app.route("/old/(?P<route>.*)")
def redirect_old_regex(request, route):
    """
    Redirect any request that starts with "/old/..." to "/new/...".
    """
    return Response(Status.REDIRECT_PERMANENT, f"/new/{route}")


@app.route("/custom-cgi")
def custom_cgi(request):
    """
    Invoke a CGI script from anywhere in the filesystem.
    """
    return app.run_cgi_script("/opt/custom-cgi.sh", request.environ)


@app.route("/auth/.*")
def authenticated(request):
    """
    Require a TLS client certificate to access files in the /auth directory.
    """
    if request.environ.get("TLS_CLIENT_HASH"):
        return app.serve_static_file(request)
    else:
        return Response(Status.CLIENT_CERTIFICATE_REQUIRED, "Need certificate")


if __name__ == "__main__":
    server = GeminiServer(app, host="127.0.0.1", hostname="localhost")
    server.run()
