"""
A simple Gemini server that echos back the request to the client.
"""
import asyncio
import typing

import jetforce


def echo(environ: dict, send_status: typing.Callable) -> typing.Iterator[bytes]:
    url = environ["URL"]
    send_status(jetforce.STATUS_SUCCESS, "text/gemini")
    yield f"Received path: {url}".encode()


if __name__ == "__main__":
    parser = jetforce.build_argument_parser()
    args = parser.parse_args()
    server = jetforce.GeminiServer(
        host=args.host,
        port=args.port,
        certfile=args.certfile,
        keyfile=args.keyfile,
        hostname=args.hostname,
        app=echo,
    )
    asyncio.run(server.run())
