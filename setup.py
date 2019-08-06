import codecs

import setuptools


def long_description():
    with codecs.open("README.md", encoding="utf8") as f:
        return f.read()


setuptools.setup(
    name="Jetforce",
    version="0.0.2",
    url="https://github.com/michael-lazar/jetforce",
    license="GPL-3.0",
    author="Michael Lazar",
    author_email="lazar.michael22@gmail.com",
    description="An Experimental Gemini Server",
    long_description=long_description(),
    py_modules=["jetforce"],
    entry_points={"console_scripts": ["jetforce=jetforce:run_server"]},
    python_requires=">=3.7",
    keywords="gemini server tcp gopher asyncio",
    classifiers=[
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
