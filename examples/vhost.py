"""
A server that implements virtual hosting for multiple subdomains.

This is a basic example of you how can run multiple apps from the same server
by creating a composite application.

> jetforce-client gemini://apple.localhost --host localhost
> jetforce-client gemini://banana.localhost --host localhost
"""
from jetforce import GeminiServer, JetforceApplication, Response, Status
from jetforce.app.composite import CompositeApplication

apple = JetforceApplication()


@apple.route()
def index(request):
    return Response(Status.SUCCESS, "text/plain", "apple!")


banana = JetforceApplication()


@banana.route()
def index(request):
    return Response(Status.SUCCESS, "text/plain", "banana!")


composite_app = CompositeApplication(
    {"apple.localhost": apple, "banana.localhost": banana}
)


if __name__ == "__main__":
    server = GeminiServer(composite_app)
    server.run()
