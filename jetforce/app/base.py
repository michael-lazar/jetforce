import dataclasses
import re
import typing
from urllib.parse import unquote, urlparse

from twisted.internet.defer import Deferred

ResponseType = typing.Union[str, bytes, Deferred]


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

    def __init__(self, environ: dict):
        self.environ = environ
        self.url = environ["GEMINI_URL"]

        url_parts = urlparse(self.url)
        if not url_parts.hostname:
            raise ValueError("Missing hostname component")

        if not url_parts.scheme:
            # If scheme is missing, infer it to be gemini://
            self.scheme = "gemini"
        else:
            self.scheme = url_parts.scheme

        # gemini://username@host/... is forbidden by the specification
        if self.scheme == "gemini" and url_parts.username:
            raise ValueError("Invalid userinfo component")

        self.hostname = url_parts.hostname
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
    body: typing.Union[None, ResponseType, typing.Iterable[ResponseType]] = None


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

    def match(self, request: Request) -> typing.Optional[re.Match]:
        """
        Check if the given request URL matches this route pattern.
        """
        if self.hostname is None:
            server_hostname = request.environ["HOSTNAME"]
        else:
            server_hostname = self.hostname
        server_port = request.environ["SERVER_PORT"]

        if self.strict_hostname and request.hostname != server_hostname:
            return
        if self.strict_port and request.port is not None:
            if request.port != server_port:
                return
        if self.scheme and self.scheme != request.scheme:
            return

        if self.strict_trailing_slash:
            request_path = request.path
        else:
            request_path = request.path.rstrip("/")

        return re.fullmatch(self.path, request_path)


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

    def __init__(self):
        self.routes: typing.List[
            typing.Tuple[RoutePattern, typing.Callable[[Request, ...], Response]]
        ] = []

    def __call__(
        self, environ: dict, send_status: typing.Callable
    ) -> typing.Iterator[ResponseType]:
        try:
            request = Request(environ)
        except Exception:
            send_status(Status.BAD_REQUEST, "Invalid URL")
            return

        for route_pattern, callback in self.routes[::-1]:
            match = route_pattern.match(request)
            if route_pattern.match(request):
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
    ) -> typing.Callable:
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

        def wrap(func: typing.Callable) -> typing.Callable:
            self.routes.append((route_pattern, func))
            return func

        return wrap

    def default_callback(self, request: Request, **_) -> Response:
        """
        Set the error response based on the URL type.
        """
        return Response(Status.PERMANENT_FAILURE, "Not Found")
