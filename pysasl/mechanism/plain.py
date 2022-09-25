
import re
from typing import Union, Tuple, Sequence

from . import (ServerMechanism, ClientMechanism, ServerChallenge,
               ChallengeResponse)
from ..config import default_config, SASLConfig
from ..creds.client import ClientCredentials
from ..creds.plain import PlainCredentials
from ..exception import InvalidResponse, UnexpectedChallenge

__all__ = ['PlainMechanism']


class PlainMechanism(ServerMechanism, ClientMechanism):
    """Implements the PLAIN authentication mechanism."""

    _pattern = re.compile(br'^([^\x00]*)\x00([^\x00]+)\x00([^\x00]*)$')

    __slots__: Sequence[str] = []

    def __init__(self, name: Union[str, bytes] = b'PLAIN',
                 config: SASLConfig = default_config) -> None:
        super().__init__(name, config)

    def server_attempt(self, responses: Sequence[ChallengeResponse]) \
            -> Tuple[PlainCredentials, None]:
        try:
            first = responses[0]
        except IndexError as exc:
            raise ServerChallenge(b'') from exc

        match = re.match(self._pattern, first.response)
        if not match:
            raise InvalidResponse()
        zid, cid, secret = match.groups()

        cid_str = cid.decode('utf-8')
        secret_str = secret.decode('utf-8')
        zid_str = zid.decode('utf-8') or cid_str
        return PlainCredentials(cid_str, secret_str, zid_str), None

    def client_attempt(self, creds: ClientCredentials,
                       challenges: Sequence[ServerChallenge]) \
            -> ChallengeResponse:
        if len(challenges) == 0:
            challenge = b''
        elif len(challenges) == 1:
            challenge = challenges[0].data
        else:
            raise UnexpectedChallenge()
        authzid = creds.authzid.encode('utf-8')
        authcid = creds.authcid.encode('utf-8')
        secret = creds.secret.encode('utf-8')
        response = b'\0'.join((authzid, authcid, secret))
        return ChallengeResponse(challenge, response)
