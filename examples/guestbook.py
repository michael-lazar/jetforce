"""
A simple guestbook application that accepts and displays text messages.

This is an example of how to return a 10 INPUT request to the client and
retrieve their response by parsing the URL query string.

This example stores the guestbook inside of a persistent sqlite database.
Because each request will run inside of a separate thread, we must create a new
connection object inside of the request handler instead of re-using a global
database connection. This thread-safety can be disabled in sqlite3 by using the
check_same_thread=False argument, but then it's up to you to ensure that only
connection request is writing to the database at any given time.
"""
import sqlite3
from datetime import datetime

from jetforce import GeminiServer, JetforceApplication, Response, Status

DB = "/tmp/guestbook.sqlite"

SCHEMA = """
CREATE TABLE IF NOT EXISTS guestbook (
    ip_address TEXT,
    created_at timestamp,
    message TEXT
)
"""
with sqlite3.connect(DB) as c:
    c.execute(SCHEMA)


app = JetforceApplication()


@app.route("", strict_trailing_slash=False)
def index(request):
    lines = ["Guestbook", "=>/submit Sign the Guestbook"]

    with sqlite3.connect(DB, detect_types=sqlite3.PARSE_DECLTYPES) as c:
        for row in c.execute("SELECT * FROM guestbook ORDER BY created_at"):
            ip_address, created_at, message = row
            line = f"{created_at:%Y-%m-%d} - [{ip_address}] {message}"
            lines.append("")
            lines.append(line)

    lines.extend(["", "...", ""])
    body = "\n".join(lines)

    return Response(Status.SUCCESS, "text/gemini", body)


@app.route("/submit")
def submit(request):
    if request.query:
        message = request.query[:256]
        created = datetime.now()
        ip_address = request.environ["REMOTE_HOST"]
        with sqlite3.connect(DB) as c:
            values = (ip_address, created, message)
            c.execute("INSERT INTO guestbook VALUES (?, ?, ?)", values)
        return Response(Status.REDIRECT_TEMPORARY, "")
    else:
        return Response(Status.INPUT, "Enter your message (max 256 characters)")


if __name__ == "__main__":
    server = GeminiServer(app)
    server.run()
