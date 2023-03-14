"""
A chatroom that will hold client connections open forever and stream messages
in real-time.

This example demonstrates how you can setup a request handler to return a
Deferred object instead of plain text/bytes. The deferred will wait for an
event to trigger it (in this case, a new message being posted to the /submit
endpoint), and at that point it will send the data to the client. An error
callback is also added to the deferred object, which will be triggered if the
client closes the connection prematurely.

This demo requires a gemini client that can stream text to the user without
waiting for the whole request to complete first. The jetforce-client tool can
do this, but most other gemini clients probably won't be able to handle
streaming.
"""
from collections import deque
from datetime import datetime

from twisted.internet.defer import AlreadyCalledError, Deferred

from jetforce import GeminiServer, JetforceApplication, Response, Status


class MessageQueue:
    def __init__(self, filename):
        self.listeners = []

        # Keep the most recent 100 messages in memory for efficiency, and
        # persist *all* messages to a plain text file.
        self.history_log = deque(maxlen=100)
        self.filename = filename
        self.load_history()

    def load_history(self):
        try:
            with open(self.filename) as fp:
                for line in fp:
                    self.history_log.append(line)
        except OSError:
            pass

    def update_history(self, message):
        self.history_log.append(message)
        with open(self.filename, "a") as fp:
            fp.write(message)

    def publish(self, message):
        message = f"[{datetime.utcnow():%Y-%m-%dT%H:%M:%SZ}] {message}\n"
        self.update_history(message)

        # Stream the message to all open client connections
        listeners = self.listeners
        self.listeners = []
        for listener in listeners:
            try:
                listener.callback(message)
            except AlreadyCalledError:
                # The connection has disconnected, ignore it
                pass

    def subscribe(self):
        # Register a deferred response that will trigger whenever the next
        # message is published to the queue
        d = Deferred()
        self.listeners.append(d)
        return d


queue = MessageQueue("/tmp/jetforce_chat.txt")

app = JetforceApplication()


HOMEPAGE = r"""
# Gemini Chat

A live, unmoderated chat room over gemini://

``` It's better than grass!
 _________________________
< It's better than grass! >
 -------------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
```

You can set a username by connecting with a client certificate.
Anonymous users will be identified by their IP address.

=> /history
(view the last 100 messages)

=> /stream
(open a long-running TCP connection that will stream messages in real-time)

=> /submit
(open an input loop to submit messages to the room)
""".strip()


def get_username(request):
    if "REMOTE_USER" in request.environ:
        return request.environ["REMOTE_USER"]
    else:
        return request.environ["REMOTE_ADDR"]


@app.route("", strict_trailing_slash=False)
def index(request):
    return Response(Status.SUCCESS, "text/gemini", HOMEPAGE)


@app.route("/history")
def history(request):
    body = "".join(queue.history_log)
    return Response(Status.SUCCESS, "text/plain", body)


@app.route("/submit")
def submit(request):
    if request.query:
        message = f"<{get_username(request)}> {request.query}"
        queue.publish(message)
    return Response(Status.INPUT, "Enter Message:")


@app.route("/stream")
def stream(request):
    def on_disconnect(failure):
        queue.publish(f"*** {get_username(request)} disconnected")
        return failure

    def stream_forever():
        yield "Connection established...\n"
        while True:
            deferred = queue.subscribe()
            deferred.addErrback(on_disconnect)
            yield deferred

    queue.publish(f"*** {get_username(request)} joined")
    return Response(Status.SUCCESS, "text/plain", stream_forever())


if __name__ == "__main__":
    server = GeminiServer(app)
    server.run()
