"""
A guestbook application that accepts user messages using the INPUT response type
and stores messages in a simple SQLite database file.
"""
import asyncio
import sqlite3
import typing
import urllib.parse
from datetime import datetime

import jetforce


class GuestbookApplication(jetforce.BaseApplication):

    db_file = "guestbook.sql"

    def connect_db(self) -> typing.Tuple[sqlite3.Connection, sqlite3.Cursor]:
        db = sqlite3.connect(self.db_file, detect_types=sqlite3.PARSE_DECLTYPES)
        cursor = db.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS guestbook (
              id int PRIMARY KEY,
              message text,
              created timestamp,
              ip_address text);
            """
        )
        db.commit()
        return db, cursor

    def __call__(
        self, environ: dict, send_status: typing.Callable
    ) -> typing.Iterator[bytes]:
        url = environ["URL"]
        url_parts = urllib.parse.urlparse(url)

        error_message = self.block_proxy_requests(url, environ["HOSTNAME"])
        if error_message:
            return send_status(jetforce.STATUS_PROXY_REQUEST_REFUSED, error_message)

        if url_parts.path in ("", "/"):
            send_status(jetforce.STATUS_SUCCESS, "text/gemini")
            yield from self.list_messages()
        elif url_parts.path == "/submit":
            if url_parts.query:
                self.save_message(url_parts.query, environ["REMOTE_ADDR"])
                return send_status(jetforce.STATUS_REDIRECT_TEMPORARY, "/")
            else:
                return send_status(
                    jetforce.STATUS_INPUT, "Enter your message (max 256 characters)"
                )
        else:
            return send_status(jetforce.STATUS_NOT_FOUND, "Invalid address")

    def save_message(self, message: str, ip_address: str) -> None:
        message = message[:256]
        created = datetime.utcnow()

        db, cursor = self.connect_db()
        sql = "INSERT INTO guestbook(message, created, ip_address) VALUES (?, ?, ?)"
        cursor.execute(sql, (message, created, ip_address))
        db.commit()

    def list_messages(self) -> typing.Iterator[bytes]:
        yield "Guestbook\n=>/submit Leave a Message\n".encode()

        db, cursor = self.connect_db()
        cursor.execute("SELECT created, message FROM guestbook ORDER BY created DESC")
        for row in cursor.fetchall():
            yield f"\n[{row[0]:%Y-%m-%d %I:%M %p}]\n{row[1]}\n".encode()

        yield "\n...\n".encode()


if __name__ == "__main__":
    parser = jetforce.build_argument_parser()
    args = parser.parse_args()
    app = GuestbookApplication()
    server = jetforce.GeminiServer(
        host=args.host,
        port=args.port,
        certfile=args.certfile,
        keyfile=args.keyfile,
        hostname=args.hostname,
        app=app,
    )
    asyncio.run(server.run())
