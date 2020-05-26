import typing

from .base import Request, ResponseType, Status


class CompositeApplication:
    """
    Route requests between multiple applications by looking at the URL hostname.

    The primary intention of this class is enable virtual hosting by serving
    two or more applications behind a single jetforce server.
    """

    def __init__(self, application_map: typing.Dict[typing.Optional[str], typing.Any]):
        """
        Initialize the application by providing a mapping of hostname -> app
        key pairs. A hostname of `None` is a special key that can be used as
        a default if none of the others match.

        Example:
            app = CompositeApplication(
                {
                    "cats.com": cats_app,
                    "dogs.com": dogs_app,
                    None: other_animals_app,
                }
            )
        """
        self.application_map = application_map

    def __call__(
        self, environ: dict, send_status: typing.Callable
    ) -> typing.Iterator[ResponseType]:
        try:
            request = Request(environ)
        except Exception:
            send_status(Status.BAD_REQUEST, "Unrecognized URL format")
            return

        if request.hostname in self.application_map:
            environ["HOSTNAME"] = request.hostname
            app = self.application_map[request.hostname]
            yield from app(environ, send_status)

        elif None in self.application_map:
            app = self.application_map[None]
            yield from app(environ, send_status)

        else:
            send_status(Status.PROXY_REQUEST_REFUSED, "Invalid hostname")
