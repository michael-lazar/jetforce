<h1 align="center">Jetforce</h1>

<p align="center">An experimental python server for the new, under development Gemini Protocol.</p>

<p align="center">Learn more about Project Gemini from its designer, ~solderpunk, <a href="https://gopher.commons.host/gopher://zaibatsu.circumlunar.space/1/~solderpunk/gemini">here</a>.</p>

<p align="center"><img alt="rocket launch" src="resources/rocket.jpg"/></p>

<p align="center">
  <a href="https://pypi.python.org/pypi/jetforce/">
    <img alt="pypi" src="https://img.shields.io/pypi/v/jetforce.svg?label=version"/>
  </a>
  <a href="https://github.com/michael-lazar/jetforce/LICENSE">
    <img alt="GitHub" src="https://img.shields.io/github/license/michael-lazar/jetforce">
  </a>
  <a href="https://github.com/psf/black">
    <img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg">
  </a>
  <a href="https://saythanks.io/to/michael-lazar">
    <img alt="say-thanks" src="https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg"/>
  </a>
</p>

## Features

- A modern python 3 codebase with type hinting and black formatting.
- Lightweight, single-file web framework with zero dependencies.
- A built-in static file server with support for *.gemini* directory map files.
- Supports concurrent connections using an asynchronous event loop.
- Extendable - loosely implements the [WSGI](https://en.wikipedia.org/wiki/Web_Server_Gateway_Interface) server/application pattern.

## Demo

A live demonstration of the Jetforce server is available on gemini at the following URL:

---

<p align="center">
<b><a href="gemini://mozz.us">gemini://mozz.us</a></b><br>
</p>

---


## Installation

Requires Python 3.7+ and OpenSSL

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

  ## TODO
  
 - Finish documentation :)
