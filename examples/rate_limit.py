#!/usr/local/env python3
"""
This example shows how you can implement rate limiting on a per-endpoint basis.
"""
from jetforce import GeminiServer, JetforceApplication, RateLimiter, Response, Status

# Apply a global rate limiter that will be applied to all requests
global_rate_limiter = RateLimiter("100/m")
app = JetforceApplication(rate_limiter=global_rate_limiter)

# Setup some custom rate limiting for specific endpoints
short_rate_limiter = RateLimiter("5/30s")
long_rate_limiter = RateLimiter("60/5m")


INDEX_PAGE = """\
# Rate Limiting Demo

=>/short short rate limiter (5/30s)
=>/long long rate limiter (60/5m)
"""


@app.route("", strict_trailing_slash=False)
def index(request):
    return Response(Status.SUCCESS, "text/gemini", INDEX_PAGE)


@app.route("/short")
@short_rate_limiter.apply
def short(request):
    return Response(Status.SUCCESS, "text/gemini", "Request was successful")


@app.route("/long")
@long_rate_limiter.apply
def long(request):
    return Response(Status.SUCCESS, "text/gemini", "Request was successful")


if __name__ == "__main__":
    server = GeminiServer(app, host="127.0.0.1", hostname="localhost")
    server.run()
