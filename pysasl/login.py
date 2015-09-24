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

from . import (ServerMechanism, ClientMechanism, ServerChallenge,
               ClientResponse, AuthenticationCredentials,
               UnexpectedAuthChallenge)

__all__ = ['LoginMechanism']


class LoginMechanism(ServerMechanism, ClientMechanism):
    """Implements the LOGIN authentication mechanism.

    """

    #: The SASL name for this mechanism.
    name = b'LOGIN'

    #: This mechanism is considered insecure for non-encrypted sessions.
    insecure = True

    @classmethod
    def server_attempt(cls, challenges):
        if len(challenges) < 1:
            raise ServerChallenge(b'Username:')
        if len(challenges) < 2:
            raise ServerChallenge(b'Password:')
        username = challenges[0].response.decode('utf-8')
        password = challenges[1].response.decode('utf-8')
        return AuthenticationCredentials(username, password)

    @classmethod
    def client_attempt(cls, creds, responses):
        if len(responses) < 1:
            return ClientResponse(b'')
        if len(responses) < 2:
            username = creds.authcid.encode('utf-8')
            return ClientResponse(username)
        if len(responses) < 3:
            password = creds.secret.encode('utf-8')
            return ClientResponse(password)
        raise UnexpectedAuthChallenge()
