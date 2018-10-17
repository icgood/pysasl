pysasl
======

Pure Python SASL client and server library. The design of the library is
intended to be agnostic of the protocol or network library.

The library currently offers `PLAIN`, `LOGIN`, and `CRAM-MD5` mechanisms by
default. The `EXTERNAL` mechanism can be chosen as well, and the `XOAUTH2`
mechanism is available for client-side auth.

[![Build Status](https://travis-ci.org/icgood/pysasl.svg)](https://travis-ci.org/icgood/pysasl)
[![Coverage Status](https://coveralls.io/repos/icgood/pysasl/badge.svg?branch=master)](https://coveralls.io/r/icgood/pysasl?branch=master)
[![PyPI](https://img.shields.io/pypi/v/pysasl.svg)](https://pypi.python.org/pypi/pysasl)
[![PyPI](https://img.shields.io/pypi/pyversions/pysasl.svg)](https://pypi.python.org/pypi/pysasl)
[![PyPI](https://img.shields.io/pypi/l/pysasl.svg)](https://pypi.python.org/pypi/pysasl)

#### [API Documentation](http://pysasl.readthedocs.org/)

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
py.test --cov=pysasl
```

Usage
=====

## Server-side

Server-side SASL has three basic requirements:

* Must advertise supported mechanisms,
* Must issue authentication challenges to the client and read responses,
* Must determine if credentials are considered valid.

#### Advertising Mechanisms

Implementations may decide on any sub-set of mechanisms to advertise. Make this
choice when instantiating the [`SASLAuth`][1] object:

```python
from pysasl import SASLAuth
auth1 = SASLAuth()  # or...
auth2 = SASLAuth([b'PLAIN', b'LOGIN'])
```

To get the names of all available mechanisms:

```python
mechanisms = [mech.name for mech in auth1.server_mechanisms]
mech = auth1.get(b'PLAIN')
```

#### Issuing Challenges

Once a mechanism has been chosen by the client, enter a loop of issuing
challenges to the client:

```python
def server_side_authentication(sock, mech):
    challenges = []
    while True:
        try:
            return mech.server_attempt(challenges)
        except ServerChallenge as chal:
            challenges.append(chal)
            sock.send(chal.get_challenge() + b'\r\n')
            chal.set_response(sock.recv(1024).rstrip(b'\r\n'))
```

It's worth noting that implemenations are not quite that simple. Most will
expect all transmissions to base64-encoded, often with a prefix before the
server challenges such as `334` or `+`. See the appropriate RFC for your
protocol, such as [RFC 4954 for SMTP][3] or [RFC 3501 for IMAP][4].

#### Checking Credentials

Once the challenge-response loop has been completed and we are left with the
a [`AuthenticationCredentials`][2] object, we can access information from the
attempt:

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

## Client-side

The goal of client-side authentication is to respond to server challenges until
the authentication attempt either succeeds or fails.

#### Choosing a Mechanism

The first step is to pick a SASL mechanism. The protocol should allow the server
to advertise to the client which mechanisms are available to it:

```python
from pysasl import SASLAuth
auth = SASLAuth(advertised_mechanism_names)
mechanisms = [mech.name for mech in auth.client_mechanisms]
mech = auth.get(b'PLAIN')
```

The resulting mechanisms will be the intersection of those advertised by the
server and those supported by pysasl.

#### Issuing Responses

Once a mechanism is chosen, we enter of a loop of responding to server
challenges:

```python
from pysasl import AuthenticationCredentials
def client_side_authentication(sock, mech, username, password):
    creds = AuthenticationCredentials(username, password)
    responses = []
    while True:
        resp = mech.client_attempt(creds, responses)
        sock.send(resp.get_response() + b'\r\n')
        data = sock.recv(1024).rstrip(b'\r\n')
        if data == 'SUCCESS':
            return True
        elif data == 'FAILURE':
            return False
        resp.set_challenge(data)
        responses.append(resp)
```

As you might expect, a real protocol probably won't return `SUCCESS` or
`FAILURE`, that will depend entirely on the details of the protocol.

## Supporting Initial Responses

Some protocols (e.g. SMTP) support the client ability to send an initial
response before the first server challenge, for mechanisms that support it.
A perfectly valid authentication can then have no challenges at all:

```
AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk
235 2.7.0 Authentication successful
```

In this case, both client-side and server-side authentication should be
handled a bit differently. For example for server-side:

```python
except ServerChallenge as chal:
    challenges.append(chal)
    if initial_response:
        chal.set_response(initial_response)
        initial_response = None
    else:
        sock.send(chal.get_challenge() + b'\r\n')
        chal.set_response(sock.recv(1024).rstrip(b'\r\n'))
```

And for client-side, just call `resp = mech.client_attempt(creds, [])`
to get the initial response before starting the transmission. All
mechanisms should either return an initial response or an empty string
when given an empty list for the second argument.

[1]: http://pysasl.readthedocs.org/en/latest/#pysasl.SASLAuth
[2]: http://pysasl.readthedocs.org/en/latest/#pysasl.AuthenticationCredentials
[3]: https://tools.ietf.org/html/rfc4954
[4]: https://tools.ietf.org/html/rfc3501#section-6.2.2
