# Jetforce

An experimental python server for the new, under development Gemini Protocol.

Learn more about Project Gemini [here](https://gopher.commons.host/gopher://zaibatsu.circumlunar.space/1/~solderpunk/gemini).

![Rocket Launch](resources/rocket.jpg)

## Features

- A modern python codebase with type hinting and black formatting.
- A built-in static file server with support for gemini directory files.
- Lightweight, single-file framework with zero dependencies.
- Supports concurrent connections using an asynchronous event loop.
- Extendable - loosely implements the [WSGI](https://en.wikipedia.org/wiki/Web_Server_Gateway_Interface) server/application pattern.

## Installation

Requires Python 3.7+ and OpenSSL. The latest release of Jetforce can be downloaded from [PyPI](https://pypi.org/project/Jetforce/):

```bash
$ pip install jetforce
```

Or, you can download the repository and run the script directly:

```bash
$ git clone https://github.com/michael-lazar/jetforce
$ cd jetforce
$ ./jetforce.py
```
