import json
import os
import socket
import ssl
import unittest
from threading import Thread
from unittest import mock

from twisted.internet import reactor

from jetforce import GeminiServer, StaticDirectoryApplication

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
    def request(cls, data: str):
        """
        Send bytes to the server using a TCP/IP socket.
        """
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((cls.server.host, cls.server.real_port)) as sock:
            with context.wrap_socket(sock) as ssock:
                ssock.sendall(data.encode(errors="surrogateescape"))
                fp = ssock.makefile("rb")
                return fp.read().decode(errors="surrogateescape")

    @classmethod
    def parse_cgi_resp(cls, response):
        return json.loads(response.splitlines()[1])

    def test_index(self):
        resp = self.request("gemini://localhost\r\n")
        self.assertEqual(resp, "20 text/gemini\r\nJetforce rules!\n")

    def test_index_trailing_slash(self):
        resp = self.request("gemini://localhost/\r\n")
        self.assertEqual(resp, "20 text/gemini\r\nJetforce rules!\n")

    def test_index_two_slashes(self):
        resp = self.request("gemini://localhost//\r\n")
        self.assertEqual(resp, "20 text/gemini\r\nJetforce rules!\n")

    def test_index_slash_dot(self):
        resp = self.request("gemini://localhost/.\r\n")
        self.assertEqual(resp, "31 gemini://localhost/./\r\n")

    def test_index_slash_dot_slash(self):
        resp = self.request("gemini://localhost/./\r\n")
        self.assertEqual(resp, "20 text/gemini\r\nJetforce rules!\n")

    def test_index_filename(self):
        resp = self.request("gemini://localhost/index.gmi\r\n")
        self.assertEqual(resp, "20 text/gemini\r\nJetforce rules!\n")

    def test_index_filename_escaped(self):
        resp = self.request("gemini://localhost/inde%78.gmi\r\n")
        self.assertEqual(resp, "20 text/gemini\r\nJetforce rules!\n")

    def test_invalid_path(self):
        resp = self.request("gemini://localhost/invalid\r\n")
        self.assertEqual(resp, "51 Not Found\r\n")

    def test_invalid_hostname(self):
        resp = self.request("gemini://example.com\r\n")
        self.assertEqual(resp, "53 This server does not allow proxy requests\r\n")

    def test_invalid_port(self):
        resp = self.request("gemini://localhost:1111\r\n")
        self.assertEqual(resp, "53 This server does not allow proxy requests\r\n")

    def test_invalid_scheme(self):
        resp = self.request("data://localhost\r\n")
        self.assertEqual(resp, "53 This server does not allow proxy requests\r\n")

    def test_invalid_userinfo(self):
        resp = self.request("gemini://nancy@localhost\r\n")
        self.assertEqual(resp, "59 Invalid URL\r\n")

    def test_missing_scheme(self):
        resp = self.request("//localhost\r\n")
        self.assertEqual(resp, "59 Invalid URL\r\n")

    def test_escape_root(self):
        resp = self.request("gemini://localhost/..\r\n")
        self.assertEqual(resp, "51 Not Found\r\n")

    def test_escape_root_directory(self):
        resp = self.request("gemini://localhost/../\r\n")
        self.assertEqual(resp, "51 Not Found\r\n")

    def test_escape_root_directory2(self):
        resp = self.request("gemini://localhost/../.\r\n")
        self.assertEqual(resp, "51 Not Found\r\n")

    def test_escape_root_filename(self):
        resp = self.request("gemini://localhost/../test_jetforce.py\r\n")
        self.assertEqual(resp, "51 Not Found\r\n")

    def test_directory_redirect(self):
        resp = self.request("gemini://localhost/cgi-bin\r\n")
        self.assertEqual(resp, "31 gemini://localhost/cgi-bin/\r\n")

    def test_directory(self):
        resp = self.request("gemini://localhost/cgi-bin/\r\n")
        resp = resp.splitlines(keepends=True)[0]
        self.assertEqual(resp, "20 text/gemini\r\n")

    def test_directory_up(self):
        resp = self.request("gemini://localhost/cgi-bin/..\r\n")
        self.assertEqual(resp, "31 gemini://localhost/cgi-bin/../\r\n")

    def test_directory_up_trailing_slash(self):
        resp = self.request("gemini://localhost/cgi-bin/../\r\n")
        self.assertEqual(resp, "20 text/gemini\r\nJetforce rules!\n")

    def test_non_utf8(self):
        resp = self.request("gemini://localhost/%AE\r\n")
        self.assertEqual(resp, "51 Not Found\r\n")

    def test_cgi(self):
        resp = self.request("gemini://localhost/cgi-bin/debug.py\r\n")
        resp = resp.splitlines(keepends=True)[0]
        self.assertEqual(resp, "20 application/json\r\n")

    def test_cgi_query(self):
        resp = self.request("gemini://localhost/cgi-bin/debug.py?hello%20world\r\n")
        data = self.parse_cgi_resp(resp)
        self.assertEqual(data["QUERY_STRING"], "hello%20world")
        self.assertEqual(data["SCRIPT_NAME"], "/cgi-bin/debug.py")
        self.assertEqual(data["PATH_INFO"], "")

    def test_cgi_root_trailing_slash(self):
        resp = self.request("gemini://localhost/cgi-bin/debug.py/\r\n")
        data = self.parse_cgi_resp(resp)
        self.assertEqual(data["QUERY_STRING"], "")
        self.assertEqual(data["SCRIPT_NAME"], "/cgi-bin/debug.py")
        self.assertEqual(data["PATH_INFO"], "/")

    def test_cgi_path_info(self):
        resp = self.request("gemini://localhost/cgi-bin/debug.py/extra/info\r\n")
        data = self.parse_cgi_resp(resp)
        self.assertEqual(data["QUERY_STRING"], "")
        self.assertEqual(data["SCRIPT_NAME"], "/cgi-bin/debug.py")
        self.assertEqual(data["PATH_INFO"], "/extra/info")

    def test_cgi_path_info_trailing_slash(self):
        resp = self.request("gemini://localhost/cgi-bin/debug.py/extra/info/\r\n")
        data = self.parse_cgi_resp(resp)
        self.assertEqual(data["QUERY_STRING"], "")
        self.assertEqual(data["SCRIPT_NAME"], "/cgi-bin/debug.py")
        self.assertEqual(data["PATH_INFO"], "/extra/info/")

    def test_hostname_punycode(self):
        with mock.patch.object(self.server, "hostname", "xn--caf-dma.localhost"):
            resp = self.request("gemini://xn--caf-dma.localhost\r\n")
            self.assertEqual(resp, "20 text/gemini\r\nJetforce rules!\n")

    def test_hostname_unicode(self):
        with mock.patch.object(self.server, "hostname", "xn--caf-dma.localhost"):
            resp = self.request("gemini://café.localhost\r\n")
            self.assertEqual(resp, "20 text/gemini\r\nJetforce rules!\n")


if __name__ == "__main__":
    unittest.main()
