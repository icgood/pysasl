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

from . import (ServerMechanism, ClientMechanism, ServerChallenge,
               ClientResponse, AuthenticationError, AuthenticationCredentials,
               UnexpectedAuthChallenge)

__all__ = ['PlainMechanism']


class PlainMechanism(ServerMechanism, ClientMechanism):
    """Implements the PLAIN authentication mechanism.

    .. attribute:: name

       The SASL name for this mechanism.

    .. attribute:: insecure

       This mechanism is *not* considered secure for non-encrypted sessions.

    """

    name = b'PLAIN'
    insecure = True
    _pattern = re.compile(br'^([^\x00]*)\x00([^\x00]+)\x00([^\x00]*)$')

    def server_attempt(self, challenges):
        if not challenges:
            raise ServerChallenge(b'')

        response = challenges[0].response
        match = re.match(self._pattern, response)
        if not match:
            raise AuthenticationError('Invalid PLAIN response')
        zid, cid, secret = match.groups()

        cid_str = cid.decode('utf-8')
        secret_str = secret.decode('utf-8')
        zid_str = zid.decode('utf-8')
        return AuthenticationCredentials(cid_str, secret_str, zid_str)

    def client_attempt(self, creds, responses):
        if len(responses) > 1:
            raise UnexpectedAuthChallenge()
        authzid = (creds.authzid or '').encode('utf-8')
        authcid = creds.authcid.encode('utf-8')
        secret = creds.secret.encode('utf-8')
        response = b'\0'.join((authzid, authcid, secret))
        return ClientResponse(response)
