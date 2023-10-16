import json
import os
import socket
import ssl
from threading import Thread
from unittest import TestCase, mock

import pytest
from twisted.internet import reactor

from jetforce import GeminiServer, StaticDirectoryApplication


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


# Generic static app with a CGI script to echo back environment variables
root_directory = os.path.join(os.path.dirname(__file__), "data")
app = StaticDirectoryApplication(root_directory=root_directory)


SERVERS = {
    "basic": GeminiTestServer(
        app=app,
        port=0,
    ),
    "proxy": GeminiTestServer(
        app=app,
        port=0,
        proxy_protocol=True,
    ),
    "plaintext": GeminiTestServer(
        app=app,
        port=0,
        use_tls=False,
    ),
    "plaintext-proxy": GeminiTestServer(
        app=app,
        port=0,
        proxy_protocol=True,
        use_tls=False,
    ),
}


@pytest.fixture(scope="session", autouse=True)
def _reactor():
    """
    Setup a twisted reactor thread that will run in the background for
    the entire test suite. The reactor is pretty finicky with regards to
    unit tests because it can only be started once per-interpreter, so
    doing it in a session fixture is a workaround. The servers need to be
    initialized before calling reactor.run, which is why I have them declared
    as global state up here instead of class-level variables.
    """
    for server in SERVERS.values():
        server.initialize()

    thread = Thread(target=reactor.run, args=(False,))
    thread.start()
    try:
        yield
    finally:
        reactor.callFromThread(reactor.stop)
        thread.join(timeout=5)


class BaseTestCase(TestCase):
    """
    This class will spin up a complete test jetforce server and serve it
    on a local TCP port in a new thread. The tests will send real gemini
    connection strings to the server and check the validity of the response
    body from end-to-end.
    """

    server: GeminiTestServer

    def create_context(self):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def get_conn_info(self):
        return self.server.host, self.server.real_port

    def parse_cgi_resp(self, response):
        return json.loads(response.splitlines()[1])


class GeminiServerTestCase(BaseTestCase):
    server = SERVERS["basic"]

    def request(self, data: str):
        context = self.create_context()
        conn = self.get_conn_info()
        with socket.create_connection(conn) as sock:
            with context.wrap_socket(sock) as ssock:
                ssock.sendall(data.encode(errors="surrogateescape"))
                fp = ssock.makefile("rb")
                return fp.read().decode(errors="surrogateescape")

    def test_index(self):
        resp = self.request("gemini://localhost\r\n")
        assert resp == "20 text/gemini\r\nJetforce rules!\n"

    def test_index_trailing_slash(self):
        resp = self.request("gemini://localhost/\r\n")
        assert resp == "20 text/gemini\r\nJetforce rules!\n"

    def test_index_two_slashes(self):
        resp = self.request("gemini://localhost//\r\n")
        assert resp == "20 text/gemini\r\nJetforce rules!\n"

    def test_index_slash_dot(self):
        resp = self.request("gemini://localhost/.\r\n")
        assert resp == "31 gemini://localhost/./\r\n"

    def test_index_slash_dot_slash(self):
        resp = self.request("gemini://localhost/./\r\n")
        assert resp == "20 text/gemini\r\nJetforce rules!\n"

    def test_index_filename(self):
        resp = self.request("gemini://localhost/index.gmi\r\n")
        assert resp == "20 text/gemini\r\nJetforce rules!\n"

    def test_index_filename_escaped(self):
        resp = self.request("gemini://localhost/inde%78.gmi\r\n")
        assert resp == "20 text/gemini\r\nJetforce rules!\n"

    def test_invalid_path(self):
        resp = self.request("gemini://localhost/invalid\r\n")
        assert resp == "51 Not Found\r\n"

    def test_invalid_hostname(self):
        resp = self.request("gemini://example.com\r\n")
        assert resp == "53 This server does not allow proxy requests\r\n"

    def test_invalid_port(self):
        resp = self.request("gemini://localhost:1111\r\n")
        assert resp == "53 This server does not allow proxy requests\r\n"

    def test_invalid_scheme(self):
        resp = self.request("data://localhost\r\n")
        assert resp == "53 This server does not allow proxy requests\r\n"

    def test_invalid_userinfo(self):
        resp = self.request("gemini://nancy@localhost\r\n")
        assert resp == "59 Invalid URL\r\n"

    def test_missing_scheme(self):
        resp = self.request("//localhost\r\n")
        assert resp == "59 Invalid URL\r\n"

    def test_escape_root(self):
        resp = self.request("gemini://localhost/..\r\n")
        assert resp == "51 Not Found\r\n"

    def test_escape_root_directory(self):
        resp = self.request("gemini://localhost/../\r\n")
        assert resp == "51 Not Found\r\n"

    def test_escape_root_directory2(self):
        resp = self.request("gemini://localhost/../.\r\n")
        assert resp == "51 Not Found\r\n"

    def test_escape_root_filename(self):
        resp = self.request("gemini://localhost/../test_jetforce.py\r\n")
        assert resp == "51 Not Found\r\n"

    def test_directory_redirect(self):
        resp = self.request("gemini://localhost/files\r\n")
        assert resp == "31 gemini://localhost/files/\r\n"

    def test_directory(self):
        resp = self.request("gemini://localhost/files/\r\n")
        resp = resp.splitlines(keepends=True)[0]
        assert resp == "20 text/gemini\r\n"

    def test_directory_double_slash(self):
        resp = self.request("gemini://localhost/files//\r\n")
        resp = resp.splitlines(keepends=True)[0]
        assert resp == "20 text/gemini\r\n"

    def test_directory_up(self):
        resp = self.request("gemini://localhost/files/..\r\n")
        assert resp == "31 gemini://localhost/files/../\r\n"

    def test_directory_up_trailing_slash(self):
        resp = self.request("gemini://localhost/cgi-bin/../\r\n")
        assert resp == "20 text/gemini\r\nJetforce rules!\n"

    def test_file_double_slash(self):
        resp = self.request("gemini://localhost/files//test.txt\r\n")
        assert resp == "20 text/plain\r\nthis is a file\n"

    def test_file_trailing_slash(self):
        """
        Will return the file, I'm not sure if this is desired behavior or not.
        """
        resp = self.request("gemini://localhost/files/test.txt/\r\n")
        assert resp == "20 text/plain\r\nthis is a file\n"

    def test_file_gzip_mimetype(self):
        resp = self.request("gemini://localhost/files/test.txt.gz\r\n")
        assert resp.startswith("20 application/gzip\r\n")

    def test_non_utf8(self):
        resp = self.request("gemini://localhost/%AE\r\n")
        assert resp == "51 Not Found\r\n"

    def test_cgi(self):
        resp = self.request("gemini://localhost/cgi-bin/debug.py\r\n")
        resp = resp.splitlines(keepends=True)[0]
        assert resp == "20 application/json\r\n"

    def test_cgi_query(self):
        resp = self.request("gemini://localhost/cgi-bin/debug.py?hello%20world\r\n")
        data = self.parse_cgi_resp(resp)
        assert data["QUERY_STRING"] == "hello%20world"
        assert data["SCRIPT_NAME"] == "/cgi-bin/debug.py"
        assert data["PATH_INFO"] == ""

    def test_cgi_root_trailing_slash(self):
        resp = self.request("gemini://localhost/cgi-bin/debug.py/\r\n")
        data = self.parse_cgi_resp(resp)
        assert data["QUERY_STRING"] == ""
        assert data["SCRIPT_NAME"] == "/cgi-bin/debug.py"
        assert data["PATH_INFO"] == "/"

    def test_cgi_path_info(self):
        resp = self.request("gemini://localhost/cgi-bin/debug.py/extra/info\r\n")
        data = self.parse_cgi_resp(resp)
        assert data["QUERY_STRING"] == ""
        assert data["SCRIPT_NAME"] == "/cgi-bin/debug.py"
        assert data["PATH_INFO"] == "/extra/info"

    def test_cgi_path_info_trailing_slash(self):
        resp = self.request("gemini://localhost/cgi-bin/debug.py/extra/info/\r\n")
        data = self.parse_cgi_resp(resp)
        assert data["QUERY_STRING"] == ""
        assert data["SCRIPT_NAME"] == "/cgi-bin/debug.py"
        assert data["PATH_INFO"] == "/extra/info/"

    def test_cgi_path_info_double_slashes(self):
        resp = self.request("gemini://localhost//cgi-bin//debug.py//extra//info//\r\n")
        data = self.parse_cgi_resp(resp)
        assert data["QUERY_STRING"] == ""
        assert data["SCRIPT_NAME"] == "/cgi-bin/debug.py"
        assert data["PATH_INFO"] == "/extra/info/"

    def test_hostname_punycode(self):
        with mock.patch.object(self.server, "hostname", "xn--caf-dma.localhost"):
            resp = self.request("gemini://xn--caf-dma.localhost\r\n")
            assert resp == "20 text/gemini\r\nJetforce rules!\n"

    def test_hostname_unicode(self):
        with mock.patch.object(self.server, "hostname", "xn--caf-dma.localhost"):
            resp = self.request("gemini://café.localhost\r\n")
            assert resp == "20 text/gemini\r\nJetforce rules!\n"

    def test_hostname_case_insensitive(self):
        """
        In the URI spec, the authority component is case-insensitive.
        """
        resp = self.request("gemini://LocalHost\r\n")
        assert resp == "20 text/gemini\r\nJetforce rules!\n"


class ProxyServerTestCase(BaseTestCase):
    server = SERVERS["proxy"]

    def test_proxy_v1(self):
        """
        The remote IP address should be derived from the proxy header.
        """
        context = self.create_context()
        conn = self.get_conn_info()
        with socket.create_connection(conn) as sock:
            sock.send(b"PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n")
            with context.wrap_socket(sock) as ssock:
                ssock.sendall(b"gemini://localhost/cgi-bin/debug.py\r\n")
                fp = ssock.makefile("rb")
                resp = fp.read().decode(errors="surrogateescape")

        data = self.parse_cgi_resp(resp)
        assert data["REMOTE_HOST"] == "192.168.0.1"

    def test_proxy_invalid(self):
        """
        Requests missing the header should be closed before the TLS handshake.
        """
        context = self.create_context()
        conn = self.get_conn_info()
        with pytest.raises(ssl.SSLError):
            with socket.create_connection(conn) as sock:
                with context.wrap_socket(sock) as ssock:
                    ssock.sendall(b"gemini://localhost/cgi-bin/debug.py\r\n")


class PlaintextServerTestCase(BaseTestCase):
    server = SERVERS["plaintext"]

    def test_plaintext(self):
        """
        The remote IP address should be derived from the proxy header.
        """
        conn = self.get_conn_info()
        with socket.create_connection(conn) as sock:
            sock.sendall(b"gemini://localhost/cgi-bin/debug.py\r\n")
            fp = sock.makefile("rb")
            resp = fp.read().decode(errors="surrogateescape")

        data = self.parse_cgi_resp(resp)
        assert "TLS_CIPHER" not in data
        assert "TLS_VERSION" not in data


class PlaintextProxyServerTestCase(BaseTestCase):
    server = SERVERS["plaintext-proxy"]

    def test_proxy_v1(self):
        """
        The remote IP address should be derived from the proxy header.
        """
        conn = self.get_conn_info()
        with socket.create_connection(conn) as sock:
            sock.sendall(
                b"PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n"
                b"gemini://localhost/cgi-bin/debug.py\r\n"
            )
            fp = sock.makefile("rb")
            resp = fp.read().decode(errors="surrogateescape")

        data = self.parse_cgi_resp(resp)
        assert data["REMOTE_HOST"] == "192.168.0.1"

    def test_proxy_invalid(self):
        """
        Requests missing the header should be closed.
        """
        conn = self.get_conn_info()
        with socket.create_connection(conn) as sock:
            sock.sendall(b"gemini://localhost/cgi-bin/debug.py\r\n")
            fp = sock.makefile("rb")
            resp = fp.read().decode(errors="surrogateescape")

        assert resp == ""
