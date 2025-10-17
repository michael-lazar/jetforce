"""
An endpoint that streams numbers counting to 10.

This is an example of how a jetforce application can respond with a generator
function instead of plain text/bytes. The server will iterate over the
generator and write the data to the socket in-between each iteration. This can
be useful if you want to serve a large response, like a binary file, without
loading the entire response into memory at once.
"""

import time

from twisted.internet import reactor
from twisted.internet.task import deferLater
from twisted.internet.threads import deferToThread

from jetforce import GeminiServer, JetforceApplication, Response, Status


def blocking_counter():
    """
    This is the simplest implementation of a blocking, synchronous generator.

    The calls to time.sleep(1) will run in the main twisted event loop and
    block all other requests from processing.
    """
    for x in range(10):
        time.sleep(1)
        yield f"{x}\r\n"


def threaded_counter():
    """
    This counter uses the twisted ThreadPool to invoke sleep() inside of a
    separate thread.

    This avoids blocking the twisted event loop during the sleep() call.
    It adds an overhead of setting up a thread for each iteration. It also
    requires that your code be thread-safe, because more than one thread may
    be running simultaneously in order to process separate requests.
    """

    def delayed_callback(x):
        time.sleep(1)
        return f"{x}\r\n"

    for x in range(10):
        yield deferToThread(delayed_callback, x)


def deferred_counter():
    """
    This counter uses twisted's deferLater() to schedule calling the function
    after a delay of one second.

    This is equivalent to using asyncio.sleep(1). It tells the twisted event
    loop to "go do something else, and come back to run this callback after at
    least one second has elapsed". The advantage is that it's non-blocking and
    you don't need to worry about thread-safety because your callback will
    eventually run in the main event loop.
    """

    def delayed_callback(var):
        return f"{var}\r\n"

    for x in range(10):
        yield deferLater(reactor, 1, delayed_callback, x)


app = JetforceApplication()


@app.route("/blocking")
def blocking(request):
    return Response(Status.SUCCESS, "text/plain", blocking_counter())


@app.route("/threaded")
def threaded(request):
    return Response(Status.SUCCESS, "text/plain", threaded_counter())


@app.route("/deferred")
def deferred(request):
    return Response(Status.SUCCESS, "text/plain", deferred_counter())


if __name__ == "__main__":
    server = GeminiServer(app)
    server.run()
