import os

from setuptools import setup


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name="freenas_manager",
    version="0.0.1",
    author="Damian Yurzola",
    author_email="damian@yurzola.net",
    description=("Manage freenas uptime"),
    license="MIT",
    keywords="example documentation tutorial",
    # url = 'http://TBD',
    install_requires=[
        "requests",
        "click",
        "parse",
        "python-nmap",
        "pynetgear",
        "loguru",
    ],
    long_description=read("README.md"),
    classifiers=["Development Status :: 3 - Alpha", "Topic :: Utilities"],
)
