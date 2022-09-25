
import re
from typing import Union, Tuple, Sequence

from . import (ServerMechanism, ClientMechanism, ServerChallenge,
               ChallengeResponse)
from ..config import default_config, SASLConfig
from ..creds.client import ClientCredentials
from ..creds.external import ExternalCredentials
from ..exception import InvalidResponse, UnexpectedChallenge

__all__ = ['OAuth2Mechanism']


class OAuth2Mechanism(ServerMechanism, ClientMechanism):
    """Implements the `XOAUTH2`_ authentication mechanism, used by `OAuth 2.0`_
    systems to authenticate using access tokens.

    .. _XOAUTH2: https://developers.google.com/gmail/xoauth2_protocol
    .. _OAuth 2.0: https://tools.ietf.org/html/rfc6749

    """

    _pattern = re.compile(br'^user=(.*?)\x01auth=[bB][eE][aA][rR][eE][rR] '
                          br'(.*?)\x01\x01$')

    def __init__(self, name: Union[str, bytes] = b'XOAUTH2',
                 config: SASLConfig = default_config) -> None:
        super().__init__(name, config)

    def server_attempt(self, responses: Sequence[ChallengeResponse]) \
            -> Tuple[ExternalCredentials, None]:
        try:
            first = responses[0]
        except IndexError as exc:
            raise ServerChallenge(b'') from exc

        match = re.match(self._pattern, first.response)
        if not match:
            raise InvalidResponse()
        user, token = match.groups()

        user_str = user.decode('utf-8')
        token_str = token.decode('utf-8')
        return ExternalCredentials(user_str, token_str), None

    def client_attempt(self, creds: ClientCredentials,
                       challenges: Sequence[ServerChallenge]) \
            -> ChallengeResponse:
        if len(challenges) == 0:
            challenge = b''
        elif len(challenges) == 1:
            challenge = challenges[0].data
        else:
            raise UnexpectedChallenge()
        if challenge != b'':
            response = b''
        else:
            user = creds.authcid.encode('utf-8')
            token = creds.secret.encode('utf-8')
            response = b''.join((b'user=', user, b'\x01auth=Bearer ', token,
                                 b'\x01\x01'))
        return ChallengeResponse(challenge, response)
