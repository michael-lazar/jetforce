"""
A simple Gemini server that echos back the request to the client.
"""
import asyncio

import jetforce


def echo(environ, send_status):
    url = environ["GEMINI_URL"]
    send_status(jetforce.Status.SUCCESS, "text/gemini")
    yield f"Received path: {url}".encode()


if __name__ == "__main__":
    args = jetforce.command_line_parser().parse_args()
    ssl_context = jetforce.make_ssl_context(
        args.hostname, args.certfile, args.keyfile, args.cafile, args.capath
    )
    server = jetforce.GeminiServer(
        host=args.host,
        port=args.port,
        ssl_context=ssl_context,
        hostname=args.hostname,
        app=echo,
    )
    asyncio.run(server.run())
