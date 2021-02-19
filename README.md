# Jetforce

An experimental TCP server for the new, under development Gemini Protocol.
Learn more about Gemini [here](https://portal.mozz.us/).

![Rocket Launch](logo.jpg)

[![pypi](https://img.shields.io/pypi/v/jetforce.svg?label=version)](https://pypi.python.org/pypi/jetforce/)
[![version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://pypi.python.org/pypi/jetforce/)
[![build](https://github.com/michael-lazar/jetforce/workflows/Jetforce/badge.svg)](https://github.com/michael-lazar/jetforce/actions?query=workflow%3AJetforce)

## Table of Contents

* [Features](#features)
* [Installation](#installation)  
* [Usage](#usage)  
* [Deployment](#deployment)
* [Releases](#releases)
* [License](#license)  

## Features

- A built-in static file server with support for gemini directories and CGI scripts.
- A complete framework for writing robust gemini applications like [astrobotany](https://github.com/michael-lazar/astrobotany).
- A lean, modern codebase with type hints and black formatting.
- A solid foundation built on top of the [twisted](https://twistedmatrix.com/trac/) asynchronous networking engine.

## Installation

Requires Python 3.7 or newer.

The latest stable release can be installed from [PyPI](https://pypi.org/project/Jetforce/):

```bash
$ pip install jetforce
```

Or, install from source:

```bash
$ git clone https://github.com/michael-lazar/jetforce
$ cd jetforce
$ python setup.py install
```

Or, install into a python virtual environment:

```bash
# Create a project directory somewhere
$ mkdir /opt/jetforce

# Activate a virtual environment and install jetforce
$ python3 -m virtualenv /opt/jetforce/venv
$ source /opt/jetforce/venv/bin/activate
$ pip install jetforce

# The launch script will be installed here
$ /opt/jetforce/venv/bin/jetforce
```

## Usage

Use the ``--help`` flag to view command-line options:

```bash
usage: jetforce [-h] [-V] [--host HOST] [--port PORT] [--hostname HOSTNAME]
                [--tls-certfile FILE] [--tls-keyfile FILE] [--tls-cafile FILE]
                [--tls-capath DIR] [--dir DIR] [--cgi-dir DIR] [--index-file FILE]
                [--default-lang DEFAULT_LANG] [--rate-limit RATE_LIMIT]

An Experimental Gemini Protocol Server

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit

server configuration:
  --host HOST           Server address to bind to (default: 127.0.0.1)
  --port PORT           Server port to bind to (default: 1965)
  --hostname HOSTNAME   Server hostname (default: localhost)
  --tls-certfile FILE   Server TLS certificate file (default: None)
  --tls-keyfile FILE    Server TLS private key file (default: None)
  --tls-cafile FILE     A CA file to use for validating clients (default: None)
  --tls-capath DIR      A directory containing CA files for validating clients (default:
                        None)

fileserver configuration:
  --dir DIR             Root directory on the filesystem to serve (default: /var/gemini)
  --cgi-dir DIR         CGI script directory, relative to the server's root directory
                        (default: cgi-bin)
  --index-file FILE     If a directory contains a file with this name, that file will be
                        served instead of auto-generating an index page (default: index.gmi)
  --default-lang DEFAULT_LANG
                        A lang parameter that will be used for all text/gemini responses
                        (default: None)
  --rate-limit RATE_LIMIT
                        Enable IP rate limiting, e.g. '60/5m' (60 requests per 5 minutes)
                        (default: None)
```

### Setting the ``hostname``

The server's hostname should be set to the *DNS* name that you expect to
receive traffic from. For example, if your jetforce server is running on
"gemini://cats.com", you should set the hostname to "cats.com". Any URLs
that do not match this hostname will be refused by the server, including
URLs that use a direct IP address such as "gemini://174.138.124.169".

IDNs (domain names that contain unicode characters) should be defined using
their ASCII punycode representation. For example, the domain name
*café.mozz.us* should be represented as ``--hostname xn--caf-dma.mozz.us``.

### Setting the ``host``

The server's host should be set to the local socket that you want to
bind to:

- ``--host "127.0.0.1"`` - Accept local connections only
- ``--host "0.0.0.0"`` - Accept remote connections over IPv4
- ``--host "::"`` - Accept remote connections over IPv6
- ``--host ""`` - Accept remote connections over any interface (IPv4 + IPv6)

### TLS Certificates

The gemini specification *requires* that all connections be sent over TLS.

If you do not provide a TLS certificate file using the ``--tls-certfile`` flag,
jetforce will automatically generate a temporary cert for you to use. This is
great for making development easier, but before you expose your server to the
public internet you should setup something more permanent. You can generate
your own self-signed server certificate, or obtain one from a Certificate
Authority like [Let's Encrypt](https://letsencrypt.org).

Here's an example `openssl` command that you can use to generate a self-signed certificate:

```
$ openssl req -newkey rsa:2048 -nodes -keyout {hostname}.key \
    -nodes -x509 -out {hostname}.crt -subj "/CN={hostname}"
```

Jetforce also supports TLS client certificates (both self-signed and CA authorised).
Requests that are made with client certificates will include additional
CGI/environment variables with information about the TLS connection.

You can specify a CA for client validation with the ``--tls-cafile`` or ``--tls-capath``
flags. Connections validated by the CA will have the ``TLS_CLIENT_AUTHORISED`` environment
variable set to True. Instructions on how to generate CA's are outside of the scope of
this readme, but you can find many helpful tutorials
[online](https://www.makethenmakeinstall.com/2014/05/ssl-client-authentication-step-by-step/).

### Static Files

Jetforce will serve static files in the ``/var/gemini/`` directory by default.
Files ending with ***.gmi** will be interpreted as the *text/gemini* type. If
a directory is requested, jetforce will look for a file named **index.gmi** in that
directory to return. Otherwise, a directory file listing will be automatically
generated.

### Virtual Hosting

For the sake of keeping the command line arguments straightforward and easy
to understand, configuring virtual hosting is not supported via the command
line. However, it is readily available using only a few lines of python and a
custom launch script. Check out [examples/vhost.py](examples/vhost.py) for more
information.

Jetforce does not (yet) support virtual hosting at the TLS-layer using SNI.
This means that you cannot return different server TLS certificates for
different domains. The suggested workaround is to use a single certificate with
multiple ``subjectAltName`` attributes. There is also an
[sni_callback()](https://github.com/michael-lazar/jetforce/blob/9ac80a986c6ed8a62951c857315ca04b6d127c32/jetforce/tls.py#L140)
hook in the server codebase that can be subclassed to implement custom TLS
behavior.

### CGI

Jetforce supports a simplified version of CGI scripting. It doesn't
exactly follow the [RFC 3875](https://tools.ietf.org/html/rfc3875)
specification for CGI, but it gets the job done for the purposes of Gemini.

Any executable file placed in the server's ``cgi-bin/`` directory will be
considered a CGI script. When a CGI script is requested by a gemini client,
the jetforce server will execute the script and pass along information about
the request using environment variables.

The CGI script must then write the gemini response to the *stdout* stream.
This includes the status code and meta string on the first line, and the
optional response body on subsequent lines. The bytes generated by the 
CGI script will be forwarded *verbatim* to the gemini client, without any
additional modification by the server.

#### CGI Environment Variables

| Name | Example Value |
| --- | --- |
| GATEWAY_INTERFACE | ``CGI/1.1`` (for compatibility with RFC 3875) |
| SERVER_PROTOCOL | ``GEMINI`` |
| SERVER_SOFTWARE | ``jetforce/0.0.7`` |
| GEMINI_URL | ``gemini://mozz.us/cgi-bin/example.cgi/extra?hello%20world`` |
| SCRIPT_NAME | ``/cgi-bin/example.cgi`` |
| PATH_INFO | ``/extra`` |
| QUERY_STRING | ``hello%20world`` |
| SERVER_NAME | ``mozz.us`` |
| SERVER_PORT | ``1965`` |
| REMOTE_HOST | ``10.10.0.2`` |
| REMOTE_ADDR | ``10.10.0.2`` |
| TLS_CIPHER | ``TLS_AES_256_GCM_SHA384`` |
| TLS_VERSION | ``TLSv1.3`` |


#### CGI Environment Variables - Authenticated

Additional CGI variables will be included only when the client connection uses a TLS client certificate:

| Name | Example Value |
| --- | --- |
| AUTH_TYPE | ``CERTIFICATE`` |
| REMOTE_USER | ``mozz123`` (the certificate subject CN attribute) |
| TLS_CLIENT_HASH | ``SHA256:86341FB480BFE333C343530D75ABF99D1437F69338F36C684C8831B63C993A96`` |
| TLS_CLIENT_NOT_BEFORE | ``2020-04-05T04:18:22Z`` |
| TLS_CLIENT_NOT_AFTER | ``2021-04-05T04:18:22Z`` |
| TLS_CLIENT_SERIAL_NUMBER | ``73629018972631`` |
| TLS_CLIENT_AUTHORISED | ``0`` (not authorised) / ``1`` (authorised) † |

† Requires the server to be configured with a CA for validating client certificates.

## Deployment

Jetforce is intended to be run behind a process manager that handles
*daemonizing* the script, redirecting output to system logs, etc. I prefer
to use [systemd](https://www.freedesktop.org/wiki/Software/systemd/) for this
because it's installed on my operating system and easy to set up.

Here's how I configure my server over at **gemini://mozz.us**:

```
# /etc/systemd/system/jetforce.service
[Unit]
Description=Jetforce Server

[Service]
Type=simple
Restart=always
RestartSec=5
Environment="PYTHONUNBUFFERED=1"
ExecStart=/usr/local/bin/jetforce \
    --host 0.0.0.0 \
    --port 1965 \
    --hostname mozz.us \
    --dir /var/gemini \
    --tls-certfile /etc/letsencrypt/live/mozz.us/fullchain.pem \
    --tls-keyfile /etc/letsencrypt/live/mozz.us/privkey.pem \
    --tls-cafile /etc/pki/tls/jetforce_client/ca.cer

[Install]
WantedBy=default.target
```

- ``--host 0.0.0.0`` allows the server to accept external connections from any
  IP address over IPv4.
- ``PYTHONUNBUFFERED=1`` disables buffering `stderr` and is sometimes necessary
  for logging to work.
- ``--tls-certfile`` and ``--tls-keyfile`` point to my WWW server's Let's Encrypt
  certificate chain.
- ``--tls-cafile`` points to a self-signed CA that I created in order to test
  accepting client TLS connections. 

With this service installed, I can start and stop the server using

```
systemctl start jetforce
systemctl stop jetforce
```

And I can view the server logs using

```
journalctl -u jetforce -f
```

*WARNING*

You are exposing a server to the internet. You (yes you!) are responsible for
securing your server and setting up appropriate access permissions. This likely means
*not* running jetforce as the root user. Security best practices are outside of the
scope of this document and largely depend on your individual threat model.

## Releases

To view the project's release history, see the [CHANGELOG](CHANGELOG.md) file.

## License

This project is licensed under the [Floodgap Free Software License](https://www.floodgap.com/software/ffsl/license.html).

> The Floodgap Free Software License (FFSL) has one overriding mandate: that software
> using it, or derivative works based on software that uses it, must be free. By free
> we mean simply "free as in beer" -- you may put your work into open or closed source
> packages as you see fit, whether or not you choose to release your changes or updates
> publicly, but you must not ask any fee for it.
