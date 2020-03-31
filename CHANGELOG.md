# Jetforce Changelog

### Unreleased

### v0.2.2 (2012-03-31)

- Fix a regression in path matching for the static directory application.
  
### v0.2.1 (2012-03-31)

- A hostname can now be specified in the route pattern, to facilitate running
  multiple vhosts on a single jetforce server.
- Route patterns now use ``re.fullmatch()`` and will no longer trigger on
  partial matches.
- Jetforce will no longer raise an exception when attempting to log dropped
  connections or other malformed requests.
- Added the following CGI variables for client certificates:
  TLS_CLIENT_NOT_BEFORE, TLS_CLIENT_NOT_AFTER, TLS_CLIENT_SERIAL_NUMBER

### v0.2.0 (2012-01-21)

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
