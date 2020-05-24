# Jetforce

An experimental TCP server for the new, under development Gemini Protocol.
Learn more about Gemini [here](https://portal.mozz.us/).

![Rocket Launch](logo.jpg)

## Features

- A built-in static file server with support for gemini directories and CGI scripts.
- A python application framework that loosely mimics the [WSGI](https://en.wikipedia.org/wiki/Web_Server_Gateway_Interface) interface design.
- A lean, modern python codebase with type hints and black formatting.
- A solid foundation built on top of the [twisted](https://twistedmatrix.com/trac/) asynchronous networking engine.

## Installation

Requires Python 3.7+

The latest release can be installed from [PyPI](https://pypi.org/project/Jetforce/):

```bash
$ pip install jetforce
```

Or, install from source:

```bash
$ git clone https://github.com/michael-lazar/jetforce
$ cd jetforce
$ python setup.py install
```

## Usage

Use the ``--help`` flag to view command-line options:

```bash
$ jetforce --help
usage: jetforce [-h] [-V] [--host HOST] [--port PORT] [--hostname HOSTNAME]
                [--tls-certfile FILE] [--tls-keyfile FILE] [--tls-cafile FILE]
                [--tls-capath DIR] [--dir DIR] [--cgi-dir DIR]
                [--index-file FILE]

An Experimental Gemini Protocol Server

optional arguments:
  -h, --help           show this help message and exit
  -V, --version        show program's version number and exit
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

### Setting the ``hostname``

The server's hostname should be set to the *DNS* name that you expect to
receive traffic from. For example, if your jetforce server is running on
"gemini://cats.com", you should set the hostname to "cats.com". Any URLs
that do not match this hostname will be refused by the server, including
URLs that use a direct IP address such as "gemini://174.138.124.169".

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

Jetforce also supports TLS client certificates (both self-signed and CA verified).
Connections made with a client certificate will have additional metadata included
in the request environment. ``REMOTE_USER`` will contain the subject common name,
and ``TLS_CLIENT_HASH`` will contain a fingerprint that can be used for TOFU pinning.

You can specify a CA for client validation with the ``--tls-cafile`` or ``--tls-capath``
flags. Connections validated by the CA will have the ``TLS_CLIENT_VERIFIED`` environment
variable set to True. Instructions on how to generate CA's are outside of the scope of
this readme, but you can find many helpful tutorials
[online](https://www.makethenmakeinstall.com/2014/05/ssl-client-authentication-step-by-step/).

### Static Files

Jetforce will serve static files in the ``/var/gemini/`` directory:

- Files ending with **.gmi** will be interpreted as the *text/gemini* type
- If a directory is requested, jetforce will look for a file in that directory
  with the name of **index.gmi**
  - If it exists, the index file will be returned
  - Otherwise, jetforce will generate a directory listing

### CGI Scripts

Jetforce supports a simplified version of CGI scripting. It doesn't
exactly follow the [RFC 3875](https://tools.ietf.org/html/rfc3875)
specification for CGI, but it gets the job done for the purposes of Gemini.

Any executable file placed in the server's ``cgi-bin/`` directory will be
considered a CGI script. When a CGI script is requested by a gemini client,
the jetforce server will execute the script and pass along information about
the request using environment variables:

| Variable Name | Example |
| --- | --- |
| GATEWAY_INTERFACE | GCI/1.1 |
| GEMINI_URL | gemini://mozz.us/cgi-bin/debug.cgi?foobar
| HOSTNAME | mozz.us |
| PATH_INFO | /cgi-bin/debug.cgi |
| QUERY_STRING | foobar |
| REMOTE_ADDR | 10.10.0.2 |
| REMOTE_HOST | 10.10.0.2 |
| SCRIPT_NAME | /usr/local/www/mozz/gemini/cgi-bin/debug.cgi |
| SERVER_NAME | mozz.us |
| SERVER_PORT | 1965 |
| SERVER_PROTOCOL | GEMINI |
| SERVER_SOFTWARE | jetforce/0.0.7 |

The CGI script must then write the gemini response to the *stdout* stream.
This includes the status code and meta string on the first line, and the
optional response body on subsequent lines. The bytes generated by the 
CGI script will be forwarded *verbatim* to the gemini client, without any
additional modification by the server.

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

The internet can be a scary place. You (yes you!) are responsible for securing your
server and setting up appropriate access permissions. This likely means *not*
running jetforce as the root user. Security best practices are outside of the scope
of this document and largely depend on your individual threat model.


## License

This project is licensed under the [Floodgap Free Software License](https://www.floodgap.com/software/ffsl/license.html).

> The Floodgap Free Software License (FFSL) has one overriding mandate: that software
> using it, or derivative works based on software that uses it, must be free. By free
> we mean simply "free as in beer" -- you may put your work into open or closed source
> packages as you see fit, whether or not you choose to release your changes or updates
> publicly, but you must not ask any fee for it.
