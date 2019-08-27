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
    server = jetforce.GeminiServer(
        host=args.host,
        port=args.port,
        certfile=args.certfile,
        keyfile=args.keyfile,
        hostname=args.hostname,
        app=echo,
    )
    asyncio.run(server.run())
