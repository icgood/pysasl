pysasl
======

Pure Python SASL client and server library. Currently, this library only
supports `PLAIN`, `LOGIN`, and `CRAM-MD5`. The design of the library is
intended to be agnostic of the protocol or event system.

Tested on Python 2.6, 2.7 and 3.4.

[![Build Status](https://travis-ci.org/icgood/pysasl.svg)](https://travis-ci.org/icgood/pysasl)
[![Coverage Status](https://coveralls.io/repos/icgood/pysasl/badge.svg)](https://coveralls.io/r/icgood/pysasl)

Installation
============

Available in [PyPi](https://pypi.python.org/):

```
pip install pysasl
```

### Running Tests

Install into a virtual environment:

```
virtualenv env
source env/bin/activate

python setup.py develop
pip install -r test/requirements.txt
```

Run the tests and report coverage metrics:

```
nosetests -v --with-xcover
```

Server-side Usage
=================

Server-side SASL has three basic requirements:

* Must advertise supported mechanisms,
* Must issue authentication challenges to the client and read responses,
* Must determine if credentials are considered valid.

#### Advertising Mechanisms

Implementations may decide on any sub-set of mechanisms to advertise. To get a
dictionary of all SASL mechanisms supported by `pysasl`:

```python
from pysasl import ServerMechanism
available = ServerMechanism.get_available(True)
```

The `True` argument indicates that the session is secure, and so mechanisms
that transfer credentials in clear-text should be returned as well (default is
`False`).

The end result of choosing advertised credentials should be a dictionary that
looks something like this:

```python
from pysasl.plain import PlainMechanism
from pysasl.crammd5 import CramMD5Mechanism

available = {'PLAIN': PlainMechanism(),
             'CRAM-MD5', CramMD5Mechanism()}
```

#### Issuing Challenges

Once a mechanism has been chosen by the client, enter a loop of issuing
challenges to the client:

```python
from pysasl import IssueChallenge

mech = available['PLAIN']

responses = []
while True:
    try:
        result = mech.server_attempt(responses)
    except IssueChallenge as exc:
        chal = exc.challenge
        sock.send(chal.challenge + b'\r\n')
        chal.response = sock.recv(1024).rstrip(b'\r\n')
        responses.append(chal)
    else:
        break
```

#### Checking Credentials

Once the challenge-response loop has been completed and we are left with the
`result` object, we can access information from the attempt:

```python
print('Authenticated as:', result.authcid)
print('Authorization ID:', result.authzid)

# To compare to a known password...
assert result.check_secret('s3kr3t')
# Or to compare hashes...
assert password_hash == hash(result.secret)
```

Some mechanisms (e.g. `CRAM-MD5`) will not support direct access to the secret.
In this case, `result.secret` will be `None` and you must use
`result.check_secret()` instead.
