#!/usr/bin/env python3
"""
A diagnostic tool for gemini servers.

This program will barrage your server with a series of requests in
an attempt to uncover unexpected behavior. Not all of these checks
adhere strictly to the gemini specification. Some of them are
general best practices, and some trigger undefined behavior. Results
should be taken with a grain of salt and analyzed on their own merit.
"""
import argparse
import contextlib
import datetime
import ipaddress
import socket
import ssl
import sys
import time
import typing

if sys.version_info < (3, 7):
    sys.exit("Fatal Error: script requires Python 3.7+")

socket.setdefaulttimeout(5)

# ANSI color codes
A_BOLD = 1
FG_BLACK = 30
FG_RED = 31
FG_GREEN = 32
FG_YELLOW = 33
FG_BLUE = 34
FG_MAGENTA = 35
FG_CYAN = 36
FG_WHITE = 37


def colorize(text: str, color: int) -> str:
    """
    Colorize text using ANSI escape codes.
    """
    if sys.stdout.isatty():
        return f"\033[{color}m{text}\033[0m"
    else:
        return text


def log(text: str, style: str = "normal") -> None:
    """
    Print formatted text to stdout with optional styling.
    """
    if style == "title":
        text = colorize(text, A_BOLD)
    if style == "warning":
        text = colorize(f"  {text}", FG_YELLOW)
    elif style == "info":
        text = colorize(f"  {text}", FG_CYAN)
    elif style == "success":
        text = colorize(f"  ✓ {text}", FG_GREEN)
    elif style == "failure":
        text = colorize(f"  x {text}", FG_RED)
    print(text)


def log_error(err: Exception) -> None:
    """
    Helper method for formatting exceptions as error messages.
    """
    if isinstance(err, Warning):
        log(str(err), style="warning")
    else:
        log(str(err), style="failure")


class GeminiResponse:
    def __init__(self, header):
        self.charset: str = "utf-8"
        self.header: str = header
        self.body: str = ""
        self.meta: typing.Optional[str] = None
        self.status: typing.Optional[str] = None
        self.mime: typing.Optional[str] = None


class BaseCheck:
    """
    Abstract base class for implementing server checks.
    """

    description: str = ""

    def __init__(self, args: argparse.Namespace):
        self.args = args

    def run(self) -> None:
        """
        Run the check and log any unhandled exceptions.
        """
        log(f"[{self.__class__.__name__}] {self.__doc__}", style="title")
        try:
            self.check()
        except Exception as e:
            log_error(e)
        log("")

    def check(self) -> None:
        raise NotImplemented

    @property
    def netloc(self):
        if self.args.port == 1965:
            return self.args.host
        else:
            return f"{self.args.host}:{self.args.port}"

    def resolve_host(self, family: socket.AddressFamily) -> tuple:
        """
        Retrieve the IP address and connection information for the host.
        """
        host = self.args.host
        port = self.args.port
        type_ = socket.SOCK_STREAM
        proto = socket.IPPROTO_TCP
        addr_info = socket.getaddrinfo(host, port, family, type_, proto)
        if not addr_info:
            raise UserWarning(f"No {family} address found for host")
        # Gemini IPv6
        return addr_info[0][4]

    @contextlib.contextmanager
    def connection(
        self, context: typing.Optional[ssl.SSLContext] = None
    ) -> ssl.SSLSocket:
        """
        Setup an unverified TLS socket connection with the host.
        """
        if context is None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        with socket.create_connection(
            (self.args.host, self.args.port), timeout=5
        ) as sock:
            with context.wrap_socket(sock, server_hostname = self.netloc) as ssock:
                yield ssock

    def make_request(self, url: str) -> GeminiResponse:
        """
        Send the request verbatim to the server and parse the response bytes.
        """
        log("Requesting URL")
        log(repr(url), style="info")
        with self.connection() as sock:
            sock.sendall(url.encode(errors="surrogateescape"))
            fp = sock.makefile("rb")
            header = fp.readline().decode()

            log("Response header")
            log(repr(header), style="info")

            response = GeminiResponse(header)
            try:
                response.status, response.meta = header.strip().split(maxsplit=1)
            except ValueError:
                return response

            if response.status.startswith("2"):
                meta_parts = [part.strip() for part in response.meta.split(";")]
                response.mime = meta_parts[0]
                for part in meta_parts[1:]:
                    if part.lower().startswith("charset="):
                        response.charset = part[8:]

            response.body = fp.read().decode(response.charset)
            return response

    def assert_success(self, response: GeminiResponse) -> None:
        """
        Helper method to check if a response was successful.
        """
        log("Status should return a success code (20 SUCCESS)")
        style = "success" if response.status == "20" else "failure"
        log(f"Received status of {response.status!r}", style)

    def assert_permanent_failure(self, response: GeminiResponse) -> None:
        """
        Helper method to assert that a response returned a permanent.
        """
        log("Status should return a failure code (5X PERMANENT FAILURE)")
        style = "success" if response.status.startswith("5") else "failure"
        log(f"Received status of {response.status!r}", style)

    def assert_proxy_refused(self, response: GeminiResponse) -> None:
        """
        Helper method to assert that a response returned a permanent.
        """
        log("Status should return a failure code (53 PROXY REQUEST REFUSED)")
        style = "success" if response.status == "53" else "failure"
        log(f"Received status of {response.status!r}", style)

    def assert_bad_request(self, response: GeminiResponse) -> None:
        """
        Helper method to assert that a response returned a permanent.
        """
        log("Status should return a failure code (59 BAD REQUEST)")
        style = "success" if response.status == "59" else "failure"
        log(f"Received status of {response.status!r}", style)


class IPv4Address(BaseCheck):
    """Establish a connection over an IPv4 address"""

    def check(self):
        log(f"Looking up IPv4 address for {self.args.host!r}")
        addr = self.resolve_host(socket.AF_INET)
        log(f"{addr[0]!r}", style="success")
        log(f"Attempting to connect to {addr[0]}:{addr[1]}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(addr)
            sock.close()
        log(f"Successfully established connection", style="success")


class IPv6Address(BaseCheck):
    """Establish a connection over an IPv6 address"""

    def check(self) -> None:
        log(f"Looking up IPv6 address for {self.args.host!r}")
        addr = self.resolve_host(socket.AF_INET6)
        if ipaddress.ip_address(addr[0]).ipv4_mapped:
            raise UserWarning("Found IPv4-mapped address, skipping check")
        log(f"{addr[0]!r}", style="success")
        log(f"Attempting to connect to [{addr[0]}]:{addr[1]}")
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.connect(addr)
            sock.close()
        log(f"Successfully established connection", style="success")


class TLSVersion(BaseCheck):
    """Server must negotiate at least TLS v1.2, ideally TLS v1.3"""

    def check(self) -> None:
        log(f"Checking client library")
        log(f"{ssl.OPENSSL_VERSION!r}", style="info")
        log("Determining highest supported TLS version")
        with self.connection() as sock:
            version = sock.version()
            if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                log(f"Negotiated {version}", style="failure")
            elif version == "TLSv1.2":
                log(f"Negotiated {version}", style="warning")
            else:
                log(f"Negotiated {version}", style="success")


class TLSClaims(BaseCheck):
    """Certificate claims must be valid"""

    def check(self) -> None:
        try:
            # $ pip install cryptography
            import cryptography
            from cryptography.hazmat.backends import default_backend
            from cryptography.x509.oid import NameOID, ExtensionOID
        except ImportError:
            raise UserWarning("cryptography library not installed, skipping check")

        with self.connection() as sock:
            # Python refuses to parse a certificate unless the issuer is validated.
            # Because many gemini servers use self-signed certs, we need to use
            # a third-party library to parse the certs from their binary form.
            der_x509 = sock.getpeercert(binary_form=True)
            cert = default_backend().load_der_x509_certificate(der_x509)
            now = datetime.datetime.utcnow()

            log('Checking "Not Valid Before" timestamp')
            style = "success" if cert.not_valid_before <= now else "failure"
            log(f"{cert.not_valid_before} UTC", style)

            log('Checking "Not Valid After" timestamp')
            style = "success" if cert.not_valid_after >= now else "failure"
            log(f"{cert.not_valid_after} UTC", style)

            log("Checking subject claim matches server hostname")
            subject = []
            for cn in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                subject.append(("commonName", cn.value))

            subject_alt_name = []
            try:
                ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
            except cryptography.x509.ExtensionNotFound:
                pass
            else:
                for dns in ext.value.get_values_for_type(cryptography.x509.DNSName):
                    subject_alt_name.append(("DNS", dns))
                for ip_address in ext.value.get_values_for_type(
                    cryptography.x509.IPAddress
                ):
                    subject_alt_name.append(("IP Address", ip_address))

            cert_dict = {
                "subject": (tuple(subject),),
                "subjectAltName": tuple(subject_alt_name),
            }
            log(f"{cert_dict!r}", style="info")
            ssl.match_hostname(cert_dict, self.args.host)
            log(f"Hostname {self.args.host!r} matches claim", style="success")


class TLSVerified(BaseCheck):
    """Certificate should be self-signed or have a trusted issuer"""

    def check(self) -> None:
        log("Connecting over verified SSL socket")
        context = ssl.create_default_context()
        try:
            with socket.create_connection((self.args.host, self.args.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.args.host) as ssock:
                    ssock.sendall(f"gemini://{self.netloc}\r\n".encode())
        except Exception as e:
            if getattr(e, "verify_code", None) == 18:
                log("Self-signed TLS certificate detected", style="warning")
            else:
                raise
        else:
            log("Established trusted TLS connection", style="success")


class TLSRequired(BaseCheck):
    """Non-TLS requests should be refused"""

    def check(self) -> None:
        log("Sending non-TLS request")
        try:
            with socket.create_connection((self.args.host, self.args.port)) as sock:
                sock.sendall(f"gemini://{self.netloc}\r\n".encode())
                fp = sock.makefile("rb")
                header = fp.readline().decode()
                if header:
                    log(f"Received unexpected response {header!r}", style="failure")
                else:
                    log(f"Connection closed by server", style="success")
        except Exception as e:
            # A connection error is a valid response
            log(f"{e!r}", style="success")


class ConcurrentConnections(BaseCheck):
    """Server should support concurrent connections"""

    def check(self) -> None:
        url = f"gemini://{self.netloc}/\r\n"

        log(f"Attempting to establish two connections")
        with self.connection() as sock:
            log("Opening socket 1", style="info")
            sock.send(url[0].encode())
            with self.connection() as sock2:
                log("Opening socket 2", style="info")
                sock2.sendall(url.encode())
                log("Closing socket 2", style="info")
            sock.sendall(url[1:].encode())
            log("Closing socket 1", style="info")

        log(f"Concurrent connections supported", style="success")


class Homepage(BaseCheck):
    """Request the gemini homepage"""

    def check(self) -> None:
        url = f"gemini://{self.netloc}/\r\n"
        response = self.make_request(url)

        self.assert_success(response)

        log('Mime type should be "text/gemini"')
        style = "success" if response.mime == "text/gemini" else "failure"
        log(f"{response.mime!r}", style)

        log('Header should end with "\\r\\n"')
        style = "success" if response.header.endswith("\r\n") else "failure"
        log(f"{response.header[-2:]!r}", style)

        log("Body should be non-empty")
        style = "success" if response.body else "failure"
        log(f"{response.body[:50]!r}", style)

        log("Body should terminate with a newline")
        style = "success" if response.body.endswith("\n") else "failure"
        log(f"{response.body[-1:]!r}", style)

        log('Body should use "\\r\\n" line endings')
        bad_line = None
        for line in response.body.splitlines(True):
            if not line.endswith("\r\n"):
                bad_line = line
                break
        if bad_line is None:
            log("All lines end with '\\r\\n'", style="success")
        else:
            log(f"Invalid line ending {bad_line!r}", style="failure")


class HomepageRedirect(BaseCheck):
    """A URL with no trailing slash should redirect to the canonical resource"""

    def check(self) -> None:
        url = f"gemini://{self.netloc}\r\n"
        response = self.make_request(url)

        log("Status should return code 31 (REDIRECT PERMANENT)")
        style = "success" if response.status == "31" else "failure"
        log(f"{response.status!r}", style)

        log('Meta should redirect to location "gemini://[hostname]/"')
        style = "success" if response.meta == f"gemini://{self.netloc}/" else "failure"
        log(f"{response.meta!r}", style)

        log('Header should end with "\\r\\n"')
        style = "success" if response.header.endswith("\r\n") else "failure"
        log(f"{response.header[-2:]!r}", style)

        log("Body should be empty")
        style = "success" if response.body == "" else "failure"
        log(f"{response.body[:50]!r}", style)


class PageNotFound(BaseCheck):
    """Request a gemini URL that does not exist"""

    def check(self) -> None:
        url = f"gemini://{self.netloc}/09pdsakjo73hjn12id78\r\n"
        response = self.make_request(url)

        log("Status should return code 51 (NOT FOUND)")
        style = "success" if response.status == "51" else "failure"
        log(f"{response.status!r}", style)

        log('Header should end with "\\r\\n"')
        style = "success" if response.header.endswith("\r\n") else "failure"
        log(f"{response.header[-2:]!r}", style)

        log("Body should be empty")
        style = "success" if response.body == "" else "failure"
        log(f"{response.body[:50]!r}", style)


class RequestMissingCR(BaseCheck):
    """A request without a <CR> should timeout"""

    def check(self) -> None:
        url = f"gemini://{self.netloc}/\n"
        try:
            response = self.make_request(url)
        except Exception as e:
            log("No response should be received")
            log(f"{e}", style="success")
        else:
            log("No response should be received")
            log(f"{response.status!r}", style="failure")


class URLIncludePort(BaseCheck):
    """Send the URL with the port explicitly defined"""

    def check(self) -> None:
        url = f"gemini://{self.args.host}:{self.args.port}/\r\n"
        response = self.make_request(url)
        self.assert_success(response)


class URLSchemeMissing(BaseCheck):
    """A URL without a scheme should be inferred as gemini"""

    def check(self) -> None:
        url = f"//{self.netloc}/\r\n"
        response = self.make_request(url)
        self.assert_success(response)


class URLByIPAddress(BaseCheck):
    """Send the URL using the IPv4 address"""

    def check(self) -> None:
        addr = self.resolve_host(socket.AF_INET)
        url = f"gemini://{addr[0]}:{addr[1]}/\r\n"
        response = self.make_request(url)

        log("Verify that the status matches your desired behavior")
        log(f"{response.status!r}", style="info")


class URLInvalidUTF8Byte(BaseCheck):
    """Send a URL containing a non-UTF8 byte sequence"""

    def check(self) -> None:
        non_utf8_character = "\udcdc"  # Surrogate-escaped byte sequence
        url = f"gemini://{self.netloc}/{non_utf8_character}\r\n"

        try:
            response = self.make_request(url)
        except Exception:
            response = None

        log("Connection should either drop, or return 59 (BAD REQUEST)")
        if response is None:
            log("Connection closed without response", style="success")
        else:
            style = "success" if response.status == "59" else "failure"
            log(f"{response.status!r}", style)


class URLMaxSize(BaseCheck):
    """Send a 1024 byte URL, the maximum allowed size"""

    def check(self) -> None:
        # Per the spec, the <CR><LF> are not included in the total size
        base_url = f"gemini://{self.netloc}/"
        buffer = "0" * (1024 - len(base_url.encode("utf-8")))
        url = base_url + buffer + "\r\n"

        response = self.make_request(url)
        log("Status should return code 51 (NOT FOUND)")
        style = "success" if response.status == "51" else "failure"
        log(f"{response.status!r}", style)


class URLAboveMaxSize(BaseCheck):
    """Send a 1025 byte URL, above the maximum allowed size"""

    def check(self) -> None:
        # Per the spec, the <CR><LF> are not included in the total size
        base_url = f"gemini://{self.netloc}/"
        buffer = "0" * (1025 - len(base_url.encode("utf-8")))
        url = base_url + buffer + "\r\n"

        try:
            response = self.make_request(url)
        except Exception:
            response = None

        log("Connection should either drop, or return 59 (BAD REQUEST)")
        if response is None:
            log("Connection closed without response", style="success")
        else:
            style = "success" if response.status == "59" else "failure"
            log(f"{response.status!r}", style)


class URLWrongPort(BaseCheck):
    """A URL with an incorrect port number should be rejected"""

    def check(self) -> None:
        url = f"gemini://{self.args.host}:443/\r\n"
        response = self.make_request(url)
        self.assert_proxy_refused(response)


class URLWrongHost(BaseCheck):
    """A URL with a foreign hostname should be rejected"""

    def check(self) -> None:
        url = f"gemini://wikipedia.org/\r\n"
        response = self.make_request(url)
        self.assert_proxy_refused(response)


class URLSchemeHTTP(BaseCheck):
    """Send a URL with an HTTP scheme"""

    def check(self) -> None:
        url = f"http://{self.netloc}/\r\n"
        response = self.make_request(url)
        self.assert_proxy_refused(response)


class URLSchemeHTTPS(BaseCheck):
    """Send a URL with an HTTPS scheme"""

    def check(self) -> None:
        url = f"https://{self.netloc}/\r\n"
        response = self.make_request(url)
        self.assert_proxy_refused(response)


class URLSchemeGopher(BaseCheck):
    """Send a URL with a Gopher scheme"""

    def check(self) -> None:
        url = f"gopher://{self.netloc}/\r\n"
        response = self.make_request(url)
        self.assert_proxy_refused(response)


class URLEmpty(BaseCheck):
    """Empty URLs should not be accepted by the server"""

    def check(self) -> None:
        url = f"\r\n"
        response = self.make_request(url)
        self.assert_bad_request(response)


class URLRelative(BaseCheck):
    """Relative URLs should not be accepted by the server"""

    def check(self) -> None:
        url = f"/\r\n"
        response = self.make_request(url)
        self.assert_bad_request(response)


class URLInvalid(BaseCheck):
    """Random text should not be accepted by the server"""

    def check(self) -> None:
        url = f"Hello Gemini!\r\n"
        response = self.make_request(url)
        self.assert_bad_request(response)


class URLDotEscape(BaseCheck):
    """A URL should not be able to escape the root using dot notation"""

    def check(self) -> None:
        url = f"gemini://{self.netloc}/../../\r\n"
        response = self.make_request(url)
        self.assert_permanent_failure(response)


# TODO: Test sending a transient client certificate
# TODO: Test with client pinned to TLS v1.1
CHECKS = [
    IPv4Address,
    IPv6Address,
    TLSVersion,
    TLSClaims,
    TLSVerified,
    TLSRequired,
    ConcurrentConnections,
    Homepage,
    HomepageRedirect,
    PageNotFound,
    RequestMissingCR,
    URLIncludePort,
    URLSchemeMissing,
    URLByIPAddress,
    URLInvalidUTF8Byte,
    URLMaxSize,
    URLAboveMaxSize,
    URLWrongPort,
    URLWrongHost,
    URLSchemeHTTP,
    URLSchemeHTTPS,
    URLSchemeGopher,
    URLEmpty,
    URLRelative,
    URLInvalid,
    URLDotEscape,
]


def build_epilog():
    epilog = ["list of checks:"]
    for check in CHECKS:
        epilog.append(colorize(f"  [{check.__name__}]", A_BOLD))
        epilog.append(f"    {check.__doc__}")
    return "\n".join(epilog)


parser = argparse.ArgumentParser(
    usage="%(prog)s host [port] [--help]",
    description=__doc__,
    epilog=build_epilog(),
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("host", help="server hostname to connect to")
parser.add_argument(
    "port",
    nargs="?",
    type=int,
    default=1965,
    help="server port to connect to (default: 1965)",
)
parser.add_argument("--checks", help="comma separated list of checks to apply")
parser.add_argument(
    "--delay",
    type=float,
    default=2,
    help="seconds to sleep between checks (default: 2)",
)


def run():
    args = parser.parse_args()
    if args.checks:
        check_names = {cls.__name__: cls for cls in CHECKS}
        check_list = []
        for name in args.checks.split(","):
            name = name.strip()
            if name not in check_names:
                raise ValueError(f"unknown check {name!r}")
            check_list.append(check_names[name])
    else:
        check_list = CHECKS

    log(f"Running gemini server diagnostics check against {args.host}:{args.port}")
    log("...\n")
    for check in check_list:
        time.sleep(args.delay)
        check(args).run()
    log("Done!")


if __name__ == "__main__":
    run()
