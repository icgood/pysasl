# Copyright (c) 2015 Ian C. Good
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

from . import (ClientMechanism, ClientResponse, UnexpectedAuthChallenge)

__all__ = ['OAuth2Mechanism']


class OAuth2Mechanism(ClientMechanism):
    """Implements the `XOAUTH2`_ authentication mechanism, used by `Oauth 2.0`_
    systems to authenticate using access tokens.

    This mechanism is only available for client-side authentication.

    .. _XOAUTH2: https://developers.google.com/gmail/xoauth2_protocol
    .. _OAuth 2.0: http://tools.ietf.org/html/draft-ietf-oauth-v2-22

    """

    #: The SASL name for this mechanism.
    name = b'XOAUTH2'

    @classmethod
    def client_attempt(cls, creds, responses):
        if len(responses) > 1:
            raise UnexpectedAuthChallenge()
        elif len(responses) > 0:
            return ClientResponse(b'')
        user = creds.authcid.encode('utf-8')
        token = creds.secret.encode('utf-8')
        response = b''.join((b'user=', user, b'\x01auth=Bearer', token,
                             b'\x01\x01'))
        return ClientResponse(response)
