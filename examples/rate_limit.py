#!/usr/local/env python3
"""
This example shows how you can implement advanced rate limiting schemes.
"""
from jetforce import GeminiServer, JetforceApplication, RateLimiter, Response, Status

app = JetforceApplication()

INDEX_PAGE = """\
# Rate Limiting Demo

=>/short short rate limiter (5/30s)
=>/long long rate limiter (60/5m)
"""


@app.route("", strict_trailing_slash=False)
def index(request):
    return Response(Status.SUCCESS, "text/gemini", INDEX_PAGE)


@app.route("/short")
@RateLimiter("5/30s")
def short(request):
    # Maximum of 5 requests per 30 seconds
    return Response(Status.SUCCESS, "text/gemini", "Request was successful")


@app.route("/long")
@RateLimiter("60/5m")
def long(request):
    # Maximum of 60 requests per 5 minutes
    return Response(Status.SUCCESS, "text/gemini", "Request was successful")


if __name__ == "__main__":
    server = GeminiServer(app, host="127.0.0.1", hostname="localhost")
    server.run()
