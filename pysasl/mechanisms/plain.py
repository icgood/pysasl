
import re
from typing import Tuple, Sequence

from .. import (ServerMechanism, ClientMechanism, ServerChallenge,
                ChallengeResponse, AuthenticationError, UnexpectedChallenge)
from ..creds import AuthenticationCredentials

__all__ = ['PlainMechanism']


class PlainMechanism(ServerMechanism, ClientMechanism):
    """Implements the PLAIN authentication mechanism."""

    _pattern = re.compile(br'^([^\x00]*)\x00([^\x00]+)\x00([^\x00]*)$')

    name = b'PLAIN'

    def server_attempt(self, responses: Sequence[ChallengeResponse]) \
            -> Tuple[AuthenticationCredentials, None]:
        try:
            first = responses[0]
        except IndexError as exc:
            raise ServerChallenge(b'') from exc

        match = re.match(self._pattern, first.response)
        if not match:
            raise AuthenticationError('Invalid PLAIN response')
        zid, cid, secret = match.groups()

        cid_str = cid.decode('utf-8')
        secret_str = secret.decode('utf-8')
        zid_str = zid.decode('utf-8')
        return AuthenticationCredentials(cid_str, secret_str, zid_str), None

    def client_attempt(self, creds: AuthenticationCredentials,
                       challenges: Sequence[ServerChallenge]) \
            -> ChallengeResponse:
        if len(challenges) == 0:
            challenge = b''
        elif len(challenges) == 1:
            challenge = challenges[0].data
        else:
            raise UnexpectedChallenge()
        authzid = (creds.authzid or '').encode('utf-8')
        authcid = creds.authcid.encode('utf-8')
        secret = creds.secret.encode('utf-8')
        response = b'\0'.join((authzid, authcid, secret))
        return ChallengeResponse(challenge, response)
