from __future__ import annotations

import dataclasses
import re
import time
import typing
from collections import defaultdict
from urllib.parse import unquote, urlparse

from twisted.internet.defer import Deferred

EnvironDict = typing.Dict[str, object]
ResponseType = typing.Union[str, bytes, Deferred]
ApplicationResponse = typing.Iterable[ResponseType]
WriteStatusCallable = typing.Callable[[int, str], None]
ApplicationCallable = typing.Callable[
    [EnvironDict, WriteStatusCallable], ApplicationResponse
]


class Status:
    """
    Gemini response status codes.
    """

    INPUT = 10
    SENSITIVE_INPUT = 11

    SUCCESS = 20

    REDIRECT_TEMPORARY = 30
    REDIRECT_PERMANENT = 31

    TEMPORARY_FAILURE = 40
    SERVER_UNAVAILABLE = 41
    CGI_ERROR = 42
    PROXY_ERROR = 43
    SLOW_DOWN = 44

    PERMANENT_FAILURE = 50
    NOT_FOUND = 51
    GONE = 52
    PROXY_REQUEST_REFUSED = 53
    BAD_REQUEST = 59

    CLIENT_CERTIFICATE_REQUIRED = 60
    CERTIFICATE_NOT_AUTHORISED = 61
    CERTIFICATE_NOT_VALID = 62


class Request:
    """
    Object that encapsulates information about a single gemini request.
    """

    environ: EnvironDict
    url: str
    scheme: str
    hostname: str
    port: typing.Optional[int]
    path: str
    params: str
    query: str
    fragment: str

    def __init__(self, environ: EnvironDict):
        self.environ = environ
        self.url = typing.cast(str, environ["GEMINI_URL"])

        url_parts = urlparse(self.url)
        if not url_parts.hostname:
            raise ValueError("Missing hostname component")

        if not url_parts.scheme:
            raise ValueError("Missing scheme component")

        self.scheme = url_parts.scheme

        # gemini://username@host/... is forbidden by the specification
        if self.scheme == "gemini" and url_parts.username:
            raise ValueError("Invalid userinfo component")

        # Convert domain names to punycode for compatibility with URLs that
        # contain encoded IDNs (follows RFC 3490).
        hostname = url_parts.hostname
        hostname = hostname.encode("idna").decode("ascii")

        self.hostname = hostname
        self.port = url_parts.port

        self.path = unquote(url_parts.path)
        self.params = unquote(url_parts.params)
        self.query = unquote(url_parts.query)
        self.fragment = unquote(url_parts.fragment)


@dataclasses.dataclass
class Response:
    """
    Object that encapsulates information about a single gemini response.
    """

    status: int
    meta: str
    body: typing.Union[None, ResponseType, ApplicationResponse] = None


RouteHandler = typing.Callable[..., Response]


@dataclasses.dataclass
class RoutePattern:
    """
    A pattern for matching URLs with a single endpoint or route.
    """

    path: str = ".*"
    scheme: str = "gemini"
    hostname: typing.Optional[str] = None

    strict_hostname: bool = True
    strict_port: bool = True
    strict_trailing_slash: bool = False

    def match(self, request: Request) -> typing.Optional[re.Match[str]]:
        """
        Check if the given request URL matches this route pattern.
        """
        if self.hostname is None:
            server_hostname = request.environ["HOSTNAME"]
        else:
            server_hostname = self.hostname
        server_port = request.environ["SERVER_PORT"]

        if self.strict_hostname and request.hostname != server_hostname:
            return None
        if self.strict_port and request.port is not None:
            if request.port != server_port:
                return None
        if self.scheme and self.scheme != request.scheme:
            return None

        if self.strict_trailing_slash:
            request_path = request.path
        else:
            request_path = request.path.rstrip("/")

        return re.fullmatch(self.path, request_path)


class RateLimiter:
    """
    A class that can be used to apply rate-limiting to endpoints.

    Rates are defined as human-readable strings, e.g.

        "5/s (5 requests per-second)
        "10/5m" (10 requests per-5 minutes)
        "100/2h" (100 requests per-2 hours)
        "1000/d" (1k requests per-day)
    """

    RE = re.compile("(?P<number>[0-9]+)/(?P<period>[0-9]+)?(?P<unit>[smhd])")

    number: int
    period: int
    next_timestamp: float
    rate_counter: typing.Dict[typing.Any, int]

    def __init__(self, rate: str) -> None:
        match = self.RE.fullmatch(rate)
        if not match:
            raise ValueError(f"Invalid rate format: {rate}")

        rate_data = match.groupdict()

        self.number = int(rate_data["number"])
        self.period = int(rate_data["period"] or 1)
        if rate_data["unit"] == "m":
            self.period *= 60
        elif rate_data["unit"] == "h":
            self.period += 60 * 60
        elif rate_data["unit"] == "d":
            self.period *= 60 * 60 * 24

        self.reset()

    def reset(self) -> None:
        self.next_timestamp = time.time() + self.period
        self.rate_counter = defaultdict(int)

    def get_key(self, request: Request) -> typing.Any:
        """
        Rate limit based on the client's IP-address.
        """
        return request.environ["REMOTE_ADDR"]

    def check(self, request: Request) -> typing.Optional[Response]:
        """
        Check if the given request should be rate limited.

        This method will return a failure response if the request should be
        rate limited.
        """
        time_left = self.next_timestamp - time.time()
        if time_left < 0:
            self.reset()

        key = self.get_key(request)
        if key is not None:
            self.rate_counter[key] += 1
            if self.rate_counter[key] > self.number:
                msg = f"Rate limit exceeded, wait {time_left:.0f} seconds."
                return Response(Status.SLOW_DOWN, msg)

        return None

    def apply(self, wrapped_func: RouteHandler) -> RouteHandler:
        """
        Decorator to apply rate limiting to an individual application route.

        Usage:
            rate_limiter = RateLimiter("10/m")

            @app.route("/endpoint")
            @rate_limiter.apply
            def my_endpoint(request):
                return Response(Status.SUCCESS, "text/gemini", "hello world!")
        """

        def wrapper(request: Request, **kwargs: typing.Any) -> Response:
            response = self.check(request)
            if response:
                return response
            return wrapped_func(request, **kwargs)

        return wrapper


class JetforceApplication:
    """
    Base Jetforce application class with primitive URL routing.

    This is a base class for writing jetforce server applications. It doesn't do
    anything on its own, but it does provide a convenient interface to define
    custom server endpoints using route decorators. If you want to utilize
    jetforce as a library and write your own server in python, this is the class
    that you want to extend. The examples/ directory contains some examples of
    how to accomplish this.
    """

    rate_limiter: typing.Optional[RateLimiter]
    routes: typing.List[typing.Tuple[RoutePattern, RouteHandler]]

    def __init__(self, rate_limiter: typing.Optional[RateLimiter] = None):
        self.rate_limiter = rate_limiter
        self.routes = []

    def __call__(
        self, environ: EnvironDict, send_status: WriteStatusCallable
    ) -> ApplicationResponse:
        try:
            request = Request(environ)
        except Exception:
            send_status(Status.BAD_REQUEST, "Invalid URL")
            return

        if self.rate_limiter:
            response = self.rate_limiter.check(request)
            if response:
                send_status(response.status, response.meta)
                return

        for route_pattern, callback in self.routes[::-1]:
            match = route_pattern.match(request)
            if match:
                callback_kwargs = match.groupdict()
                break
        else:
            callback = self.default_callback
            callback_kwargs = {}

        response = callback(request, **callback_kwargs)
        send_status(response.status, response.meta)

        if isinstance(response.body, (bytes, str, Deferred)):
            yield response.body
        elif response.body:
            yield from response.body

    def route(
        self,
        path: str = ".*",
        scheme: str = "gemini",
        hostname: typing.Optional[str] = None,
        strict_hostname: bool = True,
        strict_trailing_slash: bool = False,
    ) -> typing.Callable[[RouteHandler], RouteHandler]:
        """
        Decorator for binding a function to a route based on the URL path.

            app = JetforceApplication()

            @app.route('/my-path')
            def my_path(request):
                return Response(Status.SUCCESS, 'text/plain', 'Hello world!')
        """
        route_pattern = RoutePattern(
            path, scheme, hostname, strict_hostname, strict_trailing_slash
        )

        def wrap(func: RouteHandler) -> RouteHandler:
            self.routes.append((route_pattern, func))
            return func

        return wrap

    def default_callback(self, request: Request, **_: typing.Any) -> Response:
        """
        Set the error response based on the URL type.
        """
        return Response(Status.PERMANENT_FAILURE, "Not Found")
