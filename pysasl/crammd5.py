# Copyright (c) 2014 Ian C. Good
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

from __future__ import absolute_import

import re
import hmac
import hashlib
import email.utils

from . import (ServerMechanism, ClientMechanism, ServerChallenge,
               ClientResponse, AuthenticationError, UnexpectedAuthChallenge,
               AuthenticationCredentials)

__all__ = ['CramMD5Mechanism']


class CramMD5Result(AuthenticationCredentials):

    __slots__ = ['challenge', 'digest']

    def __init__(self, username, challenge, digest):
        super(CramMD5Result, self).__init__(username, '')
        self.challenge = challenge
        self.digest = digest

    @property
    def secret(self):
        raise NotImplementedError()

    def check_secret(self, secret):
        if not isinstance(secret, bytes):
            secret = secret.encode('utf-8')
        expected_hmac = hmac.new(secret, self.challenge, hashlib.md5)
        expected = expected_hmac.hexdigest().encode('ascii')
        try:
            return hmac.compare_digest(expected, self.digest)
        except AttributeError:  # pragma: no cover
            return expected == self.digest


class CramMD5Mechanism(ServerMechanism, ClientMechanism):
    """Implements the CRAM-MD5 authentication mechanism.

    Warning:
        Although secure during transport, offering this mechanism can be
        dangerous, as it can have implications about how the credentials are
        stored server-side.

    """

    _pattern = re.compile(br'^(.*) ([^ ]+)$')

    @property
    def name(self):
        return b'CRAM-MD5'

    @property
    def priority(self):
        return 10

    def server_attempt(self, challenges):
        if not challenges:
            challenge = email.utils.make_msgid().encode('utf-8')
            raise ServerChallenge(challenge)
        challenge = challenges[0].challenge
        response = challenges[0].response

        match = re.match(self._pattern, response)
        if not match:
            raise AuthenticationError('Invalid CRAM-MD5 response')
        username, digest = match.groups()

        username_str = username.decode('utf-8')
        return CramMD5Result(username_str, challenge, digest)

    def client_attempt(self, creds, responses):
        if len(responses) < 1:
            return ClientResponse(b'')
        elif len(responses) > 1:
            raise UnexpectedAuthChallenge()
        challenge = responses[0].challenge
        authcid = creds.authcid.encode('utf-8')
        secret = creds.secret.encode('utf-8')
        digest = hmac.new(secret, challenge, hashlib.md5).hexdigest()
        response = b' '.join((authcid, digest.encode('ascii')))
        return ClientResponse(response)
