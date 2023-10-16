import codecs

import setuptools


def long_description() -> str:
    with codecs.open("README.md", encoding="utf8") as f:
        return f.read()


setuptools.setup(
    name="Jetforce",
    version="0.10.0",
    url="https://github.com/michael-lazar/jetforce",
    license="Other/Proprietary License",
    author="Michael Lazar",
    author_email="lazar.michael22@gmail.com",
    description="An Experimental Gemini Server",
    install_requires=[
        "twisted>=21.7.0",
        # Requirements below are used by twisted[security]
        "service_identity",
        "idna",
        "pyopenssl",
    ],
    extras_require={
        "test": [
            "pytest",
            "mypy",
            "types-pyOpenSSL",
        ],
    },
    long_description=long_description(),
    long_description_content_type="text/markdown",
    packages=["jetforce", "jetforce.app"],
    package_data={"jetforce": ["py.typed"]},
    py_modules=["jetforce_client"],
    entry_points={
        "console_scripts": [
            "jetforce=jetforce.__main__:main",
            "jetforce-client=jetforce_client:run_client",
        ]
    },
    python_requires=">=3.7",
    keywords="gemini server tcp gopher asyncio",
    classifiers=[
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    zip_safe=False,
)
