from __future__ import absolute_import

from . import (ClientMechanism, ClientResponse, UnexpectedAuthChallenge)

__all__ = ['OAuth2Mechanism']


class OAuth2Mechanism(ClientMechanism):
    """Implements the `XOAUTH2`_ authentication mechanism, used by `Oauth 2.0`_
    systems to authenticate using access tokens.

    This mechanism is only available for client-side authentication.

    Attributes:
        name: The SASL name for this mechanism.
        priority: Determines the sort ordering of this mechanism.
        insecure: This mechanism is considered secure for non-encrypted
            sessions.

    .. _XOAUTH2: https://developers.google.com/gmail/xoauth2_protocol
    .. _OAuth 2.0: http://tools.ietf.org/html/draft-ietf-oauth-v2-22

    """

    name = b'XOAUTH2'
    priority = None
    insecure = False

    def client_attempt(self, creds, responses):
        if len(responses) > 1:
            raise UnexpectedAuthChallenge()
        elif len(responses) > 0:
            return ClientResponse(b'')
        user = creds.authcid.encode('utf-8')
        token = creds.secret.encode('utf-8')
        response = b''.join((b'user=', user, b'\x01auth=Bearer', token,
                             b'\x01\x01'))
        return ClientResponse(response)
