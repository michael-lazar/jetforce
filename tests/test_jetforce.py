import os
import ssl
import socket
import unittest
from threading import Thread

from twisted.internet import reactor
from jetforce import StaticDirectoryApplication, GeminiServer

ROOT_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")


class GeminiTestServer(GeminiServer):

    real_port: int

    def on_bind_interface(self, port):
        """
        Capture the port number that the test server actually binds to.
        """
        sock_ip, sock_port, *_ = port.socket.getsockname()
        self.real_port = sock_port

    def log_access(self, message: str) -> None:
        """Suppress logging"""

    def log_message(self, message: str) -> None:
        """Suppress logging"""


class FunctionalTestCase(unittest.TestCase):
    """
    This class will spin up a complete test jetforce server and serve it
    on a local TCP port in a new thread. The tests will send real gemini
    connection strings to the server and check the validity of the response
    body from end-to-end.
    """

    server: GeminiTestServer
    thread: Thread

    @classmethod
    def setUpClass(cls):
        app = StaticDirectoryApplication(root_directory=ROOT_DIR)
        cls.server = GeminiTestServer(app=app, port=0)
        cls.server.initialize()

        cls.thread = Thread(target=reactor.run, args=(False,))
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        reactor.callFromThread(reactor.stop)
        cls.thread.join(timeout=5)

    @classmethod
    def request(cls, data):
        """
        Send bytes to the server using a TCP/IP socket.
        """
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((cls.server.host, cls.server.real_port)) as sock:
            with context.wrap_socket(sock) as ssock:
                ssock.sendall(data)
                fp = ssock.makefile("rb")
                return fp.read()

    def test_index(self):
        resp = self.request(b"gemini://localhost\r\n")
        self.assertEqual(resp, b"20 text/gemini\r\nJetforce rules!\n")

    def test_invalid_path(self):
        resp = self.request(b"gemini://localhost/invalid\r\n")
        self.assertEqual(resp, b"51 Not Found\r\n")

    def test_invalid_hostname(self):
        resp = self.request(b"gemini://example.com\r\n")
        self.assertEqual(resp, b"53 This server does not allow proxy requests\r\n")

    def test_invalid_port(self):
        resp = self.request(b"gemini://localhost:1111\r\n")
        self.assertEqual(resp, b"53 This server does not allow proxy requests\r\n")

    def test_directory_redirect(self):
        resp = self.request(b"gemini://localhost/cgi-bin\r\n")
        self.assertEqual(resp, b"31 gemini://localhost/cgi-bin/\r\n")

    def test_directory(self):
        resp = self.request(b"gemini://localhost/cgi-bin/\r\n")
        self.assertEqual(resp.splitlines(keepends=True)[0], b"20 text/gemini\r\n")

    def test_cgi_script(self):
        resp = self.request(b"gemini://localhost/cgi-bin/echo.cgi?hello%20world\r\n")
        self.assertEqual(resp, b"20 text/plain\r\nhello%20world\n")


if __name__ == "__main__":
    unittest.main()
