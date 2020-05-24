"""
Main entry point for running ``jetforce`` from the command line.

This will launch a gemini server running the StaticFileServer application.
"""
# Black does not do a good job of formatting argparse code, IMHO.
# fmt: off
import argparse
import sys

from .__version__ import __version__
from .app.static import StaticDirectoryApplication
from .server import GeminiServer

if sys.version_info < (3, 7):
    sys.exit("Fatal Error: jetforce requires Python 3.7+")


# noinspection PyTypeChecker
parser = argparse.ArgumentParser(
    prog="jetforce",
    description="An Experimental Gemini Protocol Server",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument(
    "-V", "--version",
    action="version",
    version="jetforce " + __version__
)
group = parser.add_argument_group("server configuration")
group.add_argument(
    "--host",
    help="Server address to bind to",
    default="127.0.0.1"
)
group.add_argument(
    "--port",
    help="Server port to bind to",
    type=int,
    default=1965
)
group.add_argument(
    "--hostname",
    help="Server hostname",
    default="localhost"
)
group.add_argument(
    "--tls-certfile",
    dest="certfile",
    help="Server TLS certificate file",
    metavar="FILE",
)
group.add_argument(
    "--tls-keyfile",
    dest="keyfile",
    help="Server TLS private key file",
    metavar="FILE",
)
group.add_argument(
    "--tls-cafile",
    dest="cafile",
    help="A CA file to use for validating clients",
    metavar="FILE",
)
group.add_argument(
    "--tls-capath",
    dest="capath",
    help="A directory containing CA files for validating clients",
    metavar="DIR",
)
group = parser.add_argument_group("fileserver configuration")
group.add_argument(
    "--dir",
    help="Root directory on the filesystem to serve",
    default="/var/gemini",
    metavar="DIR",
    dest="root_directory",
)
group.add_argument(
    "--cgi-dir",
    help="CGI script directory, relative to the server's root directory",
    default="cgi-bin",
    metavar="DIR",
    dest="cgi_directory",
)
group.add_argument(
    "--index-file",
    help="If a directory contains a file with this name, "
         "that file will be served instead of auto-generating an index page",
    default="index.gmi",
    metavar="FILE",
    dest="index_file",
)


def main():
    args = parser.parse_args()
    app = StaticDirectoryApplication(
        root_directory=args.root_directory,
        index_file=args.index_file,
        cgi_directory=args.cgi_directory,
    )
    server = GeminiServer(
        app=app,
        host=args.host,
        port=args.port,
        hostname=args.hostname,
        certfile=args.certfile,
        keyfile=args.keyfile,
        cafile=args.cafile,
        capath=args.capath,
    )
    server.run()


if __name__ == "__main__":
    main()
