# Jetforce Changelog

### v0.0.5 (2019-08-12)

Updates to conform to the v0.9.1 Gemini specification

- The request line is now expected to be a full URL instead of a PATH.
- Response status codes have been updated to match the new specification.
- The server now requires a "hostname" be specified via a command line argument.
- Request URLs that contain other protocols / hosts are disallowed.
- A simple gemini client, ``jetforce-client``, is now included.
