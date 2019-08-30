# Jetforce

An experimental TCP server for the new, under development Gemini Protocol.
Learn more [here](https://gopher.commons.host/gopher://zaibatsu.circumlunar.space/1/~solderpunk/gemini).

![Rocket Launch](resources/rocket.jpg)

## Features

- A built-in static file server with support for gemini directories and
  CGI scripts.
- Lightweight, single-file framework with zero external dependencies.  
- Modern python codebase with type hinting and black style formatting.
- Supports concurrent connections using an asynchronous event loop.
- Extendable components that loosely implement the [WSGI](https://en.wikipedia.org/wiki/Web_Server_Gateway_Interface)
  server/application pattern.

## Installation

Requires Python 3.7+

The latest release can be installed from [PyPI](https://pypi.org/project/Jetforce/):

```bash
$ pip install jetforce
```

Or, clone the repository and run the script directly:

```bash
$ git clone https://github.com/michael-lazar/jetforce
$ cd jetforce
$ python3 jetforce.py
```

## Usage

Use the ``--help`` flag to view command-line options:

```bash
$ jetforce --help
usage: jetforce [-h] [--host HOST] [--port PORT] [--hostname HOSTNAME]
                [--tls-certfile FILE] [--tls-keyfile FILE] [--tls-cafile FILE]
                [--tls-capath DIR] [--dir DIR] [--cgi-dir DIR]
                [--index-file FILE]

An Experimental Gemini Protocol Server

optional arguments:
  -h, --help           show this help message and exit
  --host HOST          Server address to bind to (default: 127.0.0.1)
  --port PORT          Server port to bind to (default: 1965)
  --hostname HOSTNAME  Server hostname (default: localhost)
  --tls-certfile FILE  Server TLS certificate file (default: None)
  --tls-keyfile FILE   Server TLS private key file (default: None)
  --tls-cafile FILE    A CA file to use for validating clients (default: None)
  --tls-capath DIR     A directory containing CA files for validating clients
                       (default: None)
  --dir DIR            Root directory on the filesystem to serve (default:
                       /var/gemini)
  --cgi-dir DIR        CGI script directory, relative to the server's root
                       directory (default: cgi-bin)
  --index-file FILE    If a directory contains a file with this name, that
                       file will be served instead of auto-generating an index
                       page (default: index.gmi)
```

### Hostname

Because the gemini protocol sends the whole URL in the request, it's necessary
to declare the hostname that your server is expecting to receive traffic under.
Jetforce will reject any request that doesn't match your hostname with a status
of ``Proxy Request Refused``.

### TLS Certificates

The gemini specification *requires* that all connections be sent over TLS.

If you do not provide a TLS certificate file using the ``--tls-certfile`` flag,
jetforce will automatically generate a temporary cert for you to use. This is
great for making development easier, but before you expose your server to the
public internet you should configure something more permanent. You can generate
your own self-signed server certificate, or obtain one from a Certificate
Authority like [Let's Encrypt](https://letsencrypt.org).

Here's the OpenSSL command that jetforce uses to generate a self-signed cert:

```
$ openssl req -newkey rsa:2048 -nodes -keyout {hostname}.key \
    -nodes -x509 -out {hostname}.crt -subj "/CN={hostname}"
```

Jetforce also supports verified client TLS certificates. You can specify your
client CA with the ``--tls-cafile`` or ``--tls-capath`` flags. Verified
connections will have the ``REMOTE_USER`` variable added to their environment,
which contains the client certificate's CN attribute. Instructions on how to
generate TLS client certificates are outside of the scope of this readme, but
you can find many helpful tutorials
[online](https://portal.mozz.us/?url=gemini%3A%2F%2Fmozz.us%2Fjournal%2F2019-08-21.txt).

There are currently no plans to support unverified (transient) client
certificates. This is due to a technical limitation of the python standard
library's ``ssl`` module, which is described in detail 
[here](https://portal.mozz.us/?url=gemini%3A%2F%2Fmozz.us%2Fjournal%2F2019-08-21.txt).

### Static Files

Jetforce will serve static files in the ``/var/gemini/`` directory:

- Files ending with **.gmi** will be interpreted as the *text/gemini* type
- If a directory is requested, jetforce will look for a file in that directory
  with the name of **index.gmi**
  - If it exists, the index file will be returned
  - Otherwise, jetforce will generate a directory listing

### CGI Scripts

Jetforce implements a slightly modified version of the official CGI
specification. Because Gemini is a less complex than HTTP, the CGI interface is
also inherently easier and more straightforward to use.

The main difference in jetforce's implementation is that the CGI script is
expected to write the entire gemini response *verbatim* to stdout:

1. The status code and meta on the first line
2. The optional response body on subsequent lines

The script is not allowed to respond with HTTP headers like ``Content-Type``,
or any other special CGI headers like internal file redirects.

Some of the HTTP specific environment variables like ``REQUEST_METHOD`` are not
used, because they don't make sense in the context of a Gemini request.

## License

This project is licensed under the [Floodgap Free Software License](https://www.floodgap.com/software/ffsl/license.html).

> The Floodgap Free Software License (FFSL) has one overriding mandate: that software
> using it, or derivative works based on software that uses it, must be free. By free
> we mean simply "free as in beer" -- you may put your work into open or closed source
> packages as you see fit, whether or not you choose to release your changes or updates
> publicly, but you must not ask any fee for it.
