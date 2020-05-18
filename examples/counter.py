"""
An endpoint that streams incrementing numbers forever.

This is an example of how a jetforce application can respond with a generator
function instead of plain text/bytes. The server will iterate over the
generator and write the data to the socket in-between each iteration. This can
be useful if you want to serve a large response, like a binary file, without
loading the entire response into memory at once.

The server will schedule your application code to be run inside of a separate
thread, using twisted's built-in thread pool. So even though the counter
function contains a sleep(), it will not block the server from handling other
requests. Try requesting this endpoint over two connections simultaneously.

> jetforce-client gemini://localhost
> jetforce-client gemini://localhost
"""

import time

from jetforce import GeminiServer, JetforceApplication, Response, Status


def counter():
    """
    Generator function that counts to ∞.
    """
    x = 0
    while True:
        time.sleep(1)
        x += 1
        yield f"{x}\r\n"


app = JetforceApplication()


@app.route()
def index(request):
    return Response(Status.SUCCESS, "text/plain", counter())


if __name__ == "__main__":
    server = GeminiServer(app)
    server.run()
