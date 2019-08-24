# Jetforce

An experimental python server for the new, under development Gemini Protocol.

Learn more about Project Gemini [here](https://gopher.commons.host/gopher://zaibatsu.circumlunar.space/1/~solderpunk/gemini).

![Rocket Launch](resources/rocket.jpg)

## Features

- A modern python codebase with type hinting and black formatting.
- A built-in static file server with support for gemini directory files.
- Lightweight, single-file framework with zero dependencies.
- Supports concurrent connections using an asynchronous event loop.
- Extendable - loosely implements the [WSGI](https://en.wikipedia.org/wiki/Web_Server_Gateway_Interface)
  server/application pattern.

## Installation

Requires Python 3.7+ and OpenSSL.

The latest release can be installed from [PyPI](https://pypi.org/project/Jetforce/)

```
$ pip install jetforce
```

Or, simply clone the repository and run the script directly

```
$ git clone https://github.com/michael-lazar/jetforce
$ cd jetforce
$ ./jetforce.py
```

## Usage

Use the ``--help`` flag to view command-line options:


```
$ jetforce --help
usage: jetforce [-h] [--host HOST] [--port PORT] [--tls-certfile FILE]
                [--tls-keyfile FILE] [--hostname HOSTNAME] [--dir DIR]
                [--index-file INDEX_FILE]

An Experimental Gemini Protocol Server

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           Address to bind server to (default: 127.0.0.1)
  --port PORT           Port to bind server to (default: 1965)
  --tls-certfile FILE   TLS certificate file (default: None)
  --tls-keyfile FILE    TLS private key file (default: None)
  --hostname HOSTNAME   Server hostname (default: localhost)
  --dir DIR             Path on the filesystem to serve (default: /var/gemini)
  --index-file INDEX_FILE
                        The gemini directory index file (default: index.gmi)

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

#### TLS Client Certificates

There are currently no plans to support transient self-signed client certificates.
This is due to a techinical limitation of the python standand library's ``ssl``
module, which is described in detail 
[here](https://portal.mozz.us/?url=gemini%3A%2F%2Fmozz.us%2Fjournal%2F2019-08-21.txt).

Support for verified client certificates will be added in a future version.

### Hostname

Because the gemini protocol sends the *whole* URL in the request, it's required
that you declare which hostname your server is expecting to receive traffic under.
Jetforce will respond to any request containing a URL that don't match your hostname
with a status of ``Proxy Request Refused``.

Using python, you can modify this behavior to do fancy things like building a proxy
server for HTTP requests. See [server_http_proxy.py](examples/server_http_proxy.py) for
an example of how to accomplish this.

### Serving Files

Jetforce serves files from the ``/var/gemini/`` directory by default:

- Files with the **.gmi** extension will be interpreted as *text/gemini*.
- Other files will have their *mimetype* guessed based on their file extension.
- Directories will look for a file with the name **index.gmi**.
- If an index file does not exist, a directory listing will be generated.

CGI scripts are not currently supported. This feature might be added in a future version.

## License

This project is licensed under the [Floodgap Free Software License](https://www.floodgap.com/software/ffsl/license.html).

> The Floodgap Free Software License (FFSL) has one overriding mandate: that software
> using it, or derivative works based on software that uses it, must be free. By free
> we mean simply "free as in beer" -- you may put your work into open or closed source
> packages as you see fit, whether or not you choose to release your changes or updates
> publicly, but you must not ask any fee for it.
