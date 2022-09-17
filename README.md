pysasl
======

Pure Python SASL client and server library. The design of the library is
intended to be agnostic of the protocol or network library.

The library currently offers `PLAIN`, `LOGIN`, and `CRAM-MD5` mechanisms by
default. The `EXTERNAL` and `XOAUTH2` mechanisms are also available for special
circumstances.

There are currently no plans to implement security layer negotiation support.

[![build](https://github.com/icgood/pysasl/actions/workflows/python-package.yml/badge.svg)](https://github.com/icgood/pysasl/actions/workflows/python-package.yml)
[![Coverage Status](https://coveralls.io/repos/icgood/pysasl/badge.svg?branch=main)](https://coveralls.io/r/icgood/pysasl?branch=main)
[![PyPI](https://img.shields.io/pypi/v/pysasl.svg)](https://pypi.python.org/pypi/pysasl)
[![PyPI](https://img.shields.io/pypi/pyversions/pysasl.svg)](https://pypi.python.org/pypi/pysasl)
[![PyPI](https://img.shields.io/pypi/l/pysasl.svg)](https://pypi.python.org/pypi/pysasl)

#### [API Documentation](https://icgood.github.io/pysasl/)

Installation
============

Available in [PyPi](https://pypi.python.org/):

```
pip install pysasl
```

### Running Tests

Install into a virtual environment:

```
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements-dev.txt
```

Run the tests and report coverage metrics:

```
invoke
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

auth1 = SASLAuth.defaults()  # equivalent to...
auth2 = SASLAuth.named([b'PLAIN', b'LOGIN'])
```

To get the names of all available mechanisms:

```python
mechanisms = [mech.name for mech in auth1.server_mechanisms]
mech = auth1.get_server(b'PLAIN')
```

#### Issuing Challenges

Once a mechanism has been chosen by the client, enter a loop of issuing
challenges to the client:

```python
def server_side_authentication(sock, mech):
    challenges = []
    while True:
        try:
            creds, _ = mech.server_attempt(challenges)
            return creds
        except ServerChallenge as chal:
            sock.send(chal.data + b'\r\n')
            resp = sock.recv(1024).rstrip(b'\r\n')
            challenges.append(ChallengeResponse(chal.data, resp))
```

It's worth noting that implementations are not quite that simple. Most will
expect all transmissions to base64-encoded, often with a prefix before the
server challenges such as `334` or `+`. See the appropriate RFC for your
protocol, such as [RFC 4954 for SMTP][3] or [RFC 3501 for IMAP][4].

#### Checking Credentials

Once the challenge-response loop has been completed and we are left with the
a [`ServerCredentials`][2] object, we can access information from the
attempt:

```python
from pysasl.identity import ClearIdentity, HashedIdentity

print('Authenticated as:', result.authcid)
print('Authorization ID:', result.authzid)

# To compare to a known cleartext password...
identity = ClearIdentity('myuser', 's3kr3t')
assert result.verify(identity)

# Or to compare hashes...
from pysasl.hashing import BuiltinHash
identity = HashedIdentity('myuser, '1baa33d03d0...', hash=BuiltinHash())
assert result.verify(identity)

# Or use passlib hashing...
from passlib.apps import custom_app_context
identity = HashedIdentity('myuser', '$6$rounds=656000$...', hash=custom_app_context)
assert result.verify(identity)
```

## Client-side

The goal of client-side authentication is to respond to server challenges until
the authentication attempt either succeeds or fails.

#### Choosing a Mechanism

The first step is to pick a SASL mechanism. The protocol should allow the server
to advertise to the client which mechanisms are available to it:

```python
from pysasl import SASLAuth

auth = SASLAuth.named(advertised_mechanism_names)
mech = auth.client_mechanisms[0]
```

Any mechanism name that is not recognized will be ignored.

#### Issuing Responses

Once a mechanism is chosen, we enter of a loop of responding to server
challenges:

```python
from pysasl.creds.client import ClientCredentials

def client_side_authentication(sock, mech, username, password):
    creds = ClientCredentials(username, password)
    challenges = []
    while True:
        resp = mech.client_attempt(creds, challenges)
        sock.send(resp + b'\r\n')
        data = sock.recv(1024).rstrip(b'\r\n')
        if data == 'SUCCESS':
            return True
        elif data == 'FAILURE':
            return False
        challenges.append(ServerChallenge(data))
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
challenges = []
if initial_response:
    challenges.append(ChallengeResponse(b'', initial_response))
```

And for client-side, just call `resp = mech.client_attempt(creds, [])`
to get the initial response before starting the transmission. All
mechanisms should either return an initial response or an empty string
when given an empty list for the second argument.

[1]: https://icgood.github.io/pysasl/pysasl.html#pysasl.SASLAuth
[2]: https://icgood.github.io/pysasl/pysasl.creds.html#pysasl.creds.server.ServerCredentials
[3]: https://tools.ietf.org/html/rfc4954
[4]: https://tools.ietf.org/html/rfc3501#section-6.2.2
