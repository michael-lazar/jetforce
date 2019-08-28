# Jetforce

An experimental TCP server for the new, under development Gemini Protocol.
Learn more about Project Gemini
[here](https://gopher.commons.host/gopher://zaibatsu.circumlunar.space/1/~solderpunk/gemini).

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
usage: jetforce [-h] [--host HOST] [--port PORT] [--tls-certfile FILE]
                [--tls-keyfile FILE] [--hostname HOSTNAME] [--dir DIR]
                [--cgi-dir DIR] [--index-file FILE]

An Experimental Gemini Protocol Server

optional arguments:
  -h, --help           show this help message and exit
  --host HOST          Server address to bind to (default: 127.0.0.1)
  --port PORT          Server port to bind to (default: 1965)
  --tls-certfile FILE  Server TLS certificate file (default: None)
  --tls-keyfile FILE   Server TLS private key file (default: None)
  --hostname HOSTNAME  Server hostname (default: localhost)
  --dir DIR            Local directory to serve (default: /var/gemini)
  --cgi-dir DIR        CGI script directory, relative to the server's root
                       directory (default: cgi-bin)
  --index-file FILE    If a directory contains a file with this name, that
                       file will be served instead of auto-generating an index
                       page (default: index.gmi)

If the TLS cert/keyfile is not provided, a self-signed certificate will
automatically be generated and saved to your temporary directory.
```

### TLS Certificates

The gemini specification *requires* that all connections be sent over TLS.
Before you deploy jetforce, you should either generate your own self-signed
certificate, or obtain one from a Certificate Authority like
[Let's Encrypt](https://letsencrypt.org).

In order to make local development easier, if you do not specify the certificate
arguments, jetforce will automatically generate a temporary ad-hoc TLS certificate
to use. Here's the OpenSSL command that jetforce uses internally:


```
$ openssl req -newkey rsa:2048 -nodes -keyout {hostname}.key \
    -nodes -x509 -out {hostname}.crt -subj "/CN={hostname}"
```

There are currently no plans to support transient self-signed client certificates.
This is due to a techinical limitation of the python standard library's ``ssl``
module, which is described in detail 
[here](https://portal.mozz.us/?url=gemini%3A%2F%2Fmozz.us%2Fjournal%2F2019-08-21.txt).

Support for verified client certificates will be added in a future version.

### Hostname

Because the gemini protocol sends the *whole* URL in the request, it's required
that you declare the hostname that your server is expecting to receive traffic
under. Jetforce will reject any request that doesn't match your hostname with a
status of ``Proxy Request Refused``.

Using python, you can modify this behavior to do fancy things like building a
proxy server for HTTP requests. See [http_proxy.py](examples/http_proxy.py) for
an example of how this is done.

### Serving Files

Jetforce serves files from the ``/var/gemini/`` directory by default:

- Files with the **.gmi** extension will be interpreted as *text/gemini*.
- Other files will have their *mimetype* guessed based on their file extension.
- Directories will look for a file with the name **index.gmi**.
- If an index file does not exist, a directory listing will be generated.

### CGI Scripts

Jetforce implements a slightly modified version of the official CGI
specification. Because Gemini is a less complex than HTTP, the CGI interface is
also inherently easier and more straightforward to use.

The main difference in this implementation is that the CGI script is expected
to write the entire gemini response *verbetim* to stdout:

1. The status code and meta on the first line
2. Any additional response body on subsequent lines

Unlike HTTP's CGI, there are no request/response headers or other special
fields to perform actions like redirects.

## License

This project is licensed under the [Floodgap Free Software License](https://www.floodgap.com/software/ffsl/license.html).

> The Floodgap Free Software License (FFSL) has one overriding mandate: that software
> using it, or derivative works based on software that uses it, must be free. By free
> we mean simply "free as in beer" -- you may put your work into open or closed source
> packages as you see fit, whether or not you choose to release your changes or updates
> publicly, but you must not ask any fee for it.
