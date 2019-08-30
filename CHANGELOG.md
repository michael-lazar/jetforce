# Jetforce Changelog

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
