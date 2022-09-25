
from typing import Union, Tuple, Sequence

from . import (ServerMechanism, ClientMechanism, ServerChallenge,
               ChallengeResponse)
from ..config import default_config, SASLConfig
from ..creds.client import ClientCredentials
from ..creds.external import ExternalCredentials
from ..exception import UnexpectedChallenge

__all__ = ['ExternalMechanism']


class ExternalMechanism(ServerMechanism, ClientMechanism):
    """Implements the EXTERNAL authentication mechanism.

    See Also:
        `RFC 4422 Appendix A <https://tools.ietf.org/html/rfc4422#appendix-A>`_

    """

    def __init__(self, name: Union[str, bytes] = b'EXTERNAL',
                 config: SASLConfig = default_config) -> None:
        super().__init__(name, config)

    def server_attempt(self, responses: Sequence[ChallengeResponse]) \
            -> Tuple[ExternalCredentials, None]:
        try:
            first = responses[0]
        except IndexError as exc:
            raise ServerChallenge(b'') from exc
        authzid_str = first.response.decode('utf-8')
        return ExternalCredentials(authzid_str), None

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
        return ChallengeResponse(challenge, authzid)
