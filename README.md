pysasl
======

Pure Python SASL client and server library. Currently, this library only
supports `PLAIN`, `LOGIN`, and `CRAM-MD5`. The design of the library is
intended to be agnostic of the protocol or event system.

Tested on Python 2.6, 2.7 and 3.4.

Installation
============

Available in [PyPi](https://pypi.python.org/):

```bash
pip install pysasl
```

## Running Tests

Install into a virtual environment:

```bash
virtualenv env
source env/bin/activate

python setup.py develop
pip install -r test/requirements.txt
```

Run the tests and report coverage metrics:

```bash
nosetests -v --with-xcover
```
