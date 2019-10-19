
from typing import Sequence

from . import (AuthenticationCredentials, ClientMechanism, UnexpectedChallenge,
               ServerChallenge, ChallengeResponse)

__all__ = ['OAuth2Mechanism']


class OAuth2Mechanism(ClientMechanism):
    """Implements the `XOAUTH2`_ authentication mechanism, used by `Oauth 2.0`_
    systems to authenticate using access tokens.

    This mechanism is only available for client-side authentication.

    .. _XOAUTH2: https://developers.google.com/gmail/xoauth2_protocol
    .. _OAuth 2.0: http://tools.ietf.org/html/draft-ietf-oauth-v2-22

    """

    name = b'XOAUTH2'

    def client_attempt(self, creds: AuthenticationCredentials,
                       challenges: Sequence[ServerChallenge]) \
            -> ChallengeResponse:
        if len(challenges) == 0:
            challenge = b''
        elif len(challenges) == 1:
            challenge = challenges[0].data
        else:
            raise UnexpectedChallenge()
        user = creds.authcid.encode('utf-8')
        token = creds.secret.encode('utf-8')
        response = b''.join((b'user=', user, b'\x01auth=Bearer', token,
                             b'\x01\x01'))
        return ChallengeResponse(challenge, response)
