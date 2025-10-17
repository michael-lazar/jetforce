"""
A simple guestbook application that accepts and displays text messages.

This is an example of how to return a 10 INPUT request to the client and
retrieve their response by parsing the URL query string.

This example stores the guestbook inside of a persistent sqlite database.
"""

import sqlite3
from datetime import datetime

from jetforce import GeminiServer, JetforceApplication, Response, Status

db = sqlite3.connect("/tmp/guestbook.sqlite", detect_types=sqlite3.PARSE_DECLTYPES)

SCHEMA = """
CREATE TABLE IF NOT EXISTS guestbook (
    ip_address TEXT,
    created_at timestamp,
    message TEXT
)
"""
db.execute(SCHEMA)


app = JetforceApplication()


@app.route("", strict_trailing_slash=False)
def index(request):
    lines = ["Guestbook", "=>/submit Sign the Guestbook"]

    for row in db.execute("SELECT * FROM guestbook ORDER BY created_at"):
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
        values = (ip_address, created, message)
        db.execute("INSERT INTO guestbook VALUES (?, ?, ?)", values)
        return Response(Status.REDIRECT_TEMPORARY, "")
    else:
        return Response(Status.INPUT, "Enter your message (max 256 characters)")


if __name__ == "__main__":
    server = GeminiServer(app)
    server.run()
