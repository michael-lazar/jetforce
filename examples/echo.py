"""
A bare-bones server that with echo back the request to the client.

This example demonstrates the simplest proof-of-concept of how you can write
your own application from scratch instead of sub-classing from the provided
JetforceApplication. The server/application interface is almost identical to
WSGI defined in PEP-3333 [1].

Unless you're feeling adventurous, you probably want to stick to the
JetforceApplication instead of going this low-level.

[1] https://www.python.org/dev/peps/pep-3333/#id20
"""

import jetforce


def app(environ, send_status):
    """
    Arguments:
        environ: A dictionary containing information about the request
        send_status: A callback function that takes two parameters: The
            response status (int) and the response meta text (str).

    Returns: A generator containing the response body.
    """
    send_status(10, "text/gemini")
    yield f"Received path: {environ['GEMINI_URL']}"


if __name__ == "__main__":
    server = jetforce.GeminiServer(app)
    server.run()
