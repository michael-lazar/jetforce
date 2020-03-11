"""
This is an example of using virtual hosting to serve URLs for multiple
subdomains from a single jetforce server.
"""
import asyncio

import jetforce
from jetforce import Response, Status

app = jetforce.JetforceApplication()


@app.route(hostname="apple.localhost")
def serve_apple_domain(request):
    return Response(Status.SUCCESS, "text/plain", f"apple\n{request.path}")


@app.route(hostname="banana.localhost")
def serve_banana_domain(request):
    return Response(Status.SUCCESS, "text/plain", f"banana\n{request.path}")


if __name__ == "__main__":
    args = jetforce.command_line_parser().parse_args()
    ssl_context = jetforce.make_ssl_context(
        args.hostname, args.certfile, args.keyfile, args.cafile, args.capath
    )
    server = jetforce.GeminiServer(
        host=args.host, port=args.port, ssl_context=ssl_context, app=app
    )
    asyncio.run(server.run())
