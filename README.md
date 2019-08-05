# Jetforce

A python server framework for the new, under development Gemini Protocol.

Learn more about Project Gemini from its author, ~solderpunk, [here](https://gopher.commons.host/gopher://zaibatsu.circumlunar.space/1/~solderpunk/gemini).

## Features

- A modern Python 3 codebase with type hinting and black formatting.
- Lightweight, single-file web framework with zero dependencies.
- A built-in static file server with support for *.gemini* directory map files.
- Supports concurrent connections using an asynchronous event loop.
- Extendable - loosely implements the [WSGI](https://en.wikipedia.org/wiki/Web_Server_Gateway_Interface) server/application pattern.

## Installation

Requires Python 3.6+ and OpenSSL

### pip

```bash
$ pip install jetforce
```

### git

```bash
$ git clone https://github.com/michael-lazar/jetforce
$ cd jetforce
$ python jetforce.py
```
