# Jetforce Changelog

### Unreleased

#### Changes

- Added a 10 second timeout on incoming connections to receive the
  gemini request line. This fixes an issue with broken clients
  leaving connections hanging open and using up file descriptors.
- Changed the default ``--path`` argument from `/var/gemini/` to the
  current directory.

#### Maintenance

- Dropped support for python 3.7 and 3.8.
- Added support for python 3.12, 3.13, and 3.14.
- Updated the repo to use `uv` and other modern tooling.

### v0.10.1 (2023-10-16)

#### Fixes

- Fixed regression that prevented TLS client certificates and other
  TLS environment variables from being initialized.

### v0.10.0 (2023-10-15)

#### Features

- Added support for the HAProxy "PROXY" protocol via the
  `--proxy-protocol` flag. This allows the server to determine the
  real client IP address when operating behind a reverse proxy such
  as nginx or stunnel.
- Added support for running a server without TLS via the `--no-tls`
  flag.

#### Fixes

- Fixed incorrect mimetype/charset in responses for compressed files
  ending in ``.gz`` and ``.bz2``.
- The "meta" component in jetforce's request logs is now surrounded
  by double quotation marks, to allow for unambiguous log parsing.
  Any quotation marks inside of the meta string itself will be escaped
  with a single backslash, (e.g. ``\"``).

#### Changes

- Updated required twisted version to >= 21.7.0.
- Added support for python 3.11.

### v0.9.1 (2022-07-08)

#### Fixes

- Fix ``strict_trailing_slash`` argument being applied as
  `strict_port` when specified on a route decorator.
- Add support for python 3.10.

### v0.9.0 (2021-05-12)

#### Fixes

- Fix not including trailing slashes in $PATH_INFO for CGI scripts.
- Fix not sending the complete certificate chain for TLS certificates
  that include a chain.
- Fix incorrect type signature for the EnvironDict type class.

#### Changes

- Make the application ``Request`` class overridable.

### v0.8.2 (2021-03-21)

#### Fixes

- Fix trailing ``]`` at the end of auto-generated directory names.

### v0.8.1 (2021-01-06)

#### Changes

- Remove new type hint syntax that was causing an error in python 3.7.

### v0.8.0 (2021-01-06)

#### Changes

- Added support for international domain names using IDN encoding.
- Several improvements to internal python type hinting coverage.
- Added a ``py.typed`` file to indicate project support for type hints.
- Optimized TCP packets when streaming directory listings.
- Optimized TCP packets when streaming large CGI responses.
- Improved error handling to catch invalid responses from CGI scripts.
- Fixed a bug where TLS_CLIENT_AUTHORISED would sometimes be set to
  ``True``/``False`` instead of ``1``/``0``.
- Fixed error handling edge case when the client killed the connection
  before all data has been sent. A `CancelledError` exception will now
  be raised internally instead of a ``ConnectionClosed`` exception.

### v0.7.0 (2020-12-06)

#### Spec Changes

- Requests containing URLs without a scheme are no longer accepted.
- The server will stop redirecting the root URL "gemini://example.com" to
  "gemini://example.com/". These URLs are canonically the same per the url RFC
  definition and should both return successful responses.
- The CGI variable TLS_CLIENT_HASH now formats the certificate hash as
  "SHA256:\<HASH\>" where \<HASH\> is uppercase hexidecimal. The old base64
  fingerprint will still be available as TLS_CLIENT_HASH_B64 to help migrate
  existing CGI scripts, but it's recommended that you support the new hash
  format moving forward.

### v0.6.0 (2020-07-30)

#### Bugfixes

- The default mimetype for unknown file extensions will now be sent as
  "application/octet-stream" instead of "text/plain". The expectation is that
  it would be safer for a client to download an unknown file rather than
  attempting to display it inline as text.
- Fixed a bug that prevented loading the default mimetype definitions from
  /etc/mime.types and other system-level files.

#### Features

- The static file server now has a ``--rate-limit`` flag that can be used
  to define per-IP address rate limiting for requests. Requests that exceed
  the specified rate will receive a 44 SLOW DOWN error response.
- Server access logs are now directed to ``stdout`` instead of ``stderr``.
  Error traceback and other messages will still be directed to ``stderr``.
- File chunking size has been optimized for streaming large static files.

#### Examples

- Added an example that demonstrates how to use the new ``RateLimiter`` class
  (examples/rate_limit.py).

### v0.5.0 (2020-07-14)

#### Spec Changes

- URLs with a userinfo component will now be rejected with a status of 59.
- The status code definitions have been updated to match the recent changes
  to the gemini spec:
    - 21 ``SUCCESS_END_OF_SESSION`` -> (removed)
    - 61 ``TRANSIENT_CERTIFICATE_REQUESTED`` -> ``CERTIFICATE_NOT_AUTHORISED``
    - 62 ``AUTHORISED_CERTIFICATE_REQUIRED`` -> ``CERTIFICATE_NOT_VALID``
    - 63 ``CERTIFICATE_NOT_ACCEPTED`` -> (removed)
    - 64 ``FUTURE_CERTIFICATE_REJECTED`` -> (removed)
    - 65 ``EXPIRED_CERTIFICATE_REJECTED`` -> (removed)

#### Bugfixes

- Jetforce will now always terminate the TCP connection without waiting for a
  TLS close_notify alert response from the client. This fixes a bug where some
  clients would appear to hang after receiving the content from the server.

#### Features

- The jetforce-client tool now supports writing TLS keys to a logfile to
  facilitate debugging TLS connections using tools like Wireshark.
- If an application response handler returns a twisted.Deferred object, the
  errback will now be invoked when the TCP connection is closed.
- Error stack traces are no longer shown when the client prematurely closes
  the connection.

#### Examples

- Added a new example that demonstrates streaming data to client connections
  (examples/chatroom.py).
- Added a new example that demonstrates extending the static file server with
  common patterns like redirects and authenticated directories
  (examples/redirect.py).

### v0.4.0 (2020-06-09)

#### Features

- Added a ``--default-lang`` command line argument to the static file server.
  This setting will define a language parameter that will be attached to the
  meta for all text/gemini responses. For example, ``--default-lang=en`` will
  set the response meta to ``"text/gemini; lang=en"``.
- Added support for the "11 SENSITIVE INPUT" status code.
- The response header now uses a <space> instead of a <tab> to separate the
  status code from the meta text.

### v0.3.2 (2020-06-02)

#### Bugfixes

- The static file server will now URL-encode spaces (%20) and other reserved
  characters in filenames.
- The ``Request`` class will now apply URL decoding to the following components
  of the request, in addition to the query params:
    - ``request.path``
    - ``request.params``
    - ``request.fragment``

### v0.3.1 (2020-06-01)

#### Bugfixes

- The client certificate fingerprint hash is now encoded using a URL-safe
  version of the base64
  algorithm [urlsafe_b64encode()](https://docs.python.org/3/library/base64.html#base64.urlsafe_b64encode).
  This is intended to make it simpler for applications and CGI scripts to
  use the certificate fingerprint in URL paths.

### v0.3.0 (2020-05-21)

This release brings some major improvements and necessary refactoring of the
jetforce package. Please read the release notes carefully and exercise caution
when upgrading from previous versions of jetforce.

#### For users of the static file server

If you are running jetforce only as a static file & CGI server (i.e. you
are using the command-line and haven't written any custom python applications),
you should not need to make any changes.

There have been some minor updates to the CGI variables, and new CGI variables
have been added with additional TLS information. Check out the README for more
information on CGI variables.

This package now has third-party python dependencies. If you installed jetforce
through pip, you should already be fine. If you were running the ``jetforce.py``
script directly from the git repository, you will likely either want to switch
to installing from pip (recommended), or setup a virtual environment and run
``python setup.py install``. This will install the dependencies and stick a
``jetforce`` executable into your system path.

#### jetforce-diagnostics

The ``jetforce-diagnostics`` script is no longer included as part of jetforce.
It has been moved to its own repository at
[gemini-diagnostics](https://github.com/michael-lazar/gemini-diagnostics).

#### Code Structure

The underlying TCP server framework has been switched from asyncio+ssl to
twisted+PyOpenSSL. This change was necessary to allow support for self-signed
client certificates. The new framework provides more access to hook into the
OpenSSL library and implement non-standard TLS behavior.

I tried to isolate the framework changes to the ``GeminiServer`` layer. This
means that if you subclassed from the ``JetforceApplication``, you will likely
not need to change anything in your application code. Launching a jetforce
server from inside of python code has been simplified (no more setting up the
asyncio event loop!).

```
server = GeminiServer(app)
server.run()
```

Check out the updated examples in the *examples/* directory for more details.

#### TLS Client Certificates

Jetforce will now accept self-signed and unvalidated client certificates. The
``capath`` and ``cafile`` arguments can still be provided, and will attempt to
validate the certificate using of the underlying OpenSSL library. The result
of this validation will be saved in the ``TLS_CLIENT_AUTHORISED`` environment
variable so that each application can decide how it wants to accept/reject the
connection.

In order to facilitate TOFU verification schemes, a fingerprint of the client
certificate is now computed and saved in the ``TLS_CLIENT_HASH`` environment
variable.

#### Other Changes

- A client certificate can now have an empty ``commonName`` field.
- ``JetforceApplication.route()`` - named capture groups in regex patterns will
  now be passed as keyword arguments to the wrapped function. See
  examples/pagination.py for an example of how to use this feature.
- ``CompositeApplication`` - A class is now included to support composing
  multiple applications behind the same jetforce server. See examples/vhost.py
  for an example of how to use this feature.
- CGI variables - ``SCRIPT_NAME`` and ``PATH_INFO`` have been changed to match
  their intended usage as defined in RFC 3875.
- CGI variables - ``TLS_CIPHER`` and ``TLS_VERSION`` have been added and
  contain information about the established TLS connection.
- Applications can now optionally return ``Deferred`` objects instead of bytes,
  in order to support applications built on top of asynchronous coroutines.

### v0.2.3 (2020-05-24)

- Fix a security vulnerability that allowed maliciously crafted URLs to break
  out of the root server directory.

### v0.2.2 (2020-03-31)

- Fix a regression in path matching for the static directory application.

### v0.2.1 (2020-03-31)

- A hostname can now be specified in the route pattern, to facilitate running
  multiple vhosts on a single jetforce server.
- Route patterns now use ``re.fullmatch()`` and will no longer trigger on
  partial matches.
- Jetforce will no longer raise an exception when attempting to log dropped
  connections or other malformed requests.
- Added the following CGI variables for client certificates:
  TLS_CLIENT_NOT_BEFORE, TLS_CLIENT_NOT_AFTER, TLS_CLIENT_SERIAL_NUMBER

### v0.2.0 (2020-01-21)

#### Features

- Added support for python 3.8.
- Added a new server diagnostics tool, ``jetforce-diagnostics``.
- Added ability to binding to IPv6 addresses (if supported by your OS):
    - For IPv4        : ``--host "0.0.0.0"``
    - For IPv6        : ``--host "::"``
    - For IPv4 + IPv6 : ``--host ""``
- Various improvements have been made to the project documentation.

#### Bugfixes

- A URL missing a scheme will now be interpreted as "gemini://".
- A request to the root URL without a trailing slash will now return a
  ``31 PERMANENT REDIRECT``.
- Requests containing an invalid or unparsable URL format will now return a
  status of ``59 BAD REQUEST`` instead of ``50 PERMANENT FAILURE``.
- Files starting with ``~`` will now be included in directory listings.
- Requests containing an incorrect scheme, hostname, or port will now return a
  ``53 PROXY REFUSED`` instead of a ``50 PERMANENT FAILURE``.
- The port number in the URL (if provided) is now validated against the
  server's port number.
- OS errors when attempting to read a file will return a ``51 NOT FOUND``
  status instead of a ``42 CGI Error``. This is a precaution to prevent leaking
  sensitive information about the server's filesystem.
- For security, unhandled exceptions will now display a generic error message
  instead of the plain exception string.

### v0.1.0 (2019-09-22)

- The server will now return a redirect if a directory is requested but the URL
  does not end in a trailing slash. This is intended to reduce duplicate
  selectors and make it easier for clients to resolve relative links.
- Added a ``-V`` / ``--version`` argument to display the version and exit.
- The server now returns an error code of ``50 PERMENANT FAILURE`` by default
  if the URL does not match the server's scheme or hostname.
- Timestamps in log messages are now displayed in the server's local timezone.
  As before, the UTC offset is included as "+HHMM" to avoid ambiguity.

### v0.0.7 (2019-08-30)

- Added support for a primitive version of CGI scripting.
- Added support for TLS client certificate verification.
- The directory index file has been changed from ".gemini" to "index.gmi".
- Files with the ".gemini" extension are now recognized as *text/gemini*.
- Several minor improvements to the internal codebase and API.

### v0.0.6 (2019-08-22)

- Significant refactoring of the base application interface.
- Added built-in support for URL routing based on the request path.
- Added support for accepting input using query strings.
- Files with the ".gmi" extension are now recognized as *text/gemini*.
- Added a new examples/ directory with the following applications
    - A bare bones echo server
    - A guestbook application
    - An HTTP/HTTPS proxy server

### v0.0.5 (2019-08-12)

Updates to conform to the v0.9.1 Gemini specification

- The request line is now expected to be a full URL instead of a PATH.
- Response status codes have been updated to match the new specification.
- The server now requires a "hostname" be specified via a command line argument.
- Request URLs that contain other protocols / hosts are disallowed.
- A simple gemini client, ``jetforce-client``, is now included.
