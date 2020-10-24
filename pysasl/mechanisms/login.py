
from typing import Tuple, Sequence

from .. import (ServerMechanism, ClientMechanism, ServerChallenge,
                ChallengeResponse, UnexpectedChallenge)
from ..creds import AuthenticationCredentials

__all__ = ['LoginMechanism']


class LoginMechanism(ServerMechanism, ClientMechanism):
    """Implements the LOGIN authentication mechanism."""

    name = b'LOGIN'

    def server_attempt(self, responses: Sequence[ChallengeResponse]) \
            -> Tuple[AuthenticationCredentials, None]:
        try:
            first = responses[0]
        except (IndexError, ValueError) as exc:
            raise ServerChallenge(b'Username:') from exc
        try:
            second = responses[1]
        except (IndexError, ValueError) as exc:
            raise ServerChallenge(b'Password:') from exc
        username = first.response.decode('utf-8')
        password = second.response.decode('utf-8')
        return AuthenticationCredentials(username, password), None

    def client_attempt(self, creds: AuthenticationCredentials,
                       challenges: Sequence[ServerChallenge]) \
            -> ChallengeResponse:
        if len(challenges) == 0:
            return ChallengeResponse(b'', b'')
        elif len(challenges) == 1:
            username = creds.authcid.encode('utf-8')
            return ChallengeResponse(challenges[0].data, username)
        elif len(challenges) == 2:
            password = creds.secret.encode('utf-8')
            return ChallengeResponse(challenges[1].data, password)
        raise UnexpectedChallenge()
