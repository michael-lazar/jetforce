"""
A guestbook application that accepts input from guests and stores messages in
a simple text file.
"""
import asyncio
import pathlib
from datetime import datetime

import jetforce
from jetforce import Response, Status

guestbook = pathlib.Path("guestbook.txt")


app = jetforce.JetforceApplication()


@app.route("", strict_trailing_slash=False)
def index(request):
    data = ["Guestbook", "=>/submit Sign the Guestbook", ""]

    guestbook.touch(exist_ok=True)
    with guestbook.open("r") as fp:
        for line in fp:
            line = line.strip()
            if line.startswith("=>"):
                data.append(line[2:])
            else:
                data.append(line)

    data.extend(["", "...", ""])
    return Response(Status.SUCCESS, "text/gemini", "\n".join(data))


@app.route("/submit")
def submit(request):
    if request.query:
        message = request.query[:256]
        created = datetime.utcnow()
        with guestbook.open("a") as fp:
            fp.write(f"\n[{created:%Y-%m-%d %I:%M %p}]\n{message}\n")

        return Response(Status.REDIRECT_TEMPORARY, "")
    else:
        return Response(Status.INPUT, "Enter your message (max 256 characters)")


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
        app=app,
    )
    asyncio.run(server.run())
