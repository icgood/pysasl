
import re
import hmac
import hashlib
import email.utils
from typing import Union, Optional, Tuple, Sequence

from . import (ServerMechanism, ClientMechanism, ServerChallenge,
               ChallengeResponse)
from ..creds.client import ClientCredentials
from ..creds.server import ServerCredentials
from ..exception import InvalidResponse, MechanismUnusable, UnexpectedChallenge
from ..identity import Identity
from ..prep import saslprep

__all__ = ['CramMD5Result', 'CramMD5Mechanism']


class CramMD5Result(ServerCredentials):
    """Because this mechanism uses hash algorithms to compare secrets, the
    :meth:`~CramMD5Mechanism.server_attempt` method returns this sub-class
    which overrides the :meth:`.verify` method.

    """

    __slots__: Sequence[str] = ['_username', '_challenge', '_digest']

    def __init__(self, username: str, challenge: bytes, digest: bytes) -> None:
        super().__init__()
        self._username = username
        self._challenge = challenge
        self._digest = digest

    @property
    def authcid(self) -> str:
        return self._username

    @property
    def authzid(self) -> str:
        return self._username

    def verify(self, identity: Optional[Identity]) -> bool:
        if identity is None:
            return False
        clear_secret = identity.get_clear_secret()
        if clear_secret is None:
            raise MechanismUnusable('CRAM-MD5')
        secret_b = clear_secret.encode('utf-8')
        expected_hmac = hmac.new(secret_b, self._challenge, hashlib.md5)
        expected_digest = expected_hmac.hexdigest().encode('ascii')
        return identity.compare_authcid(self.authcid) \
            and hmac.compare_digest(expected_digest, self._digest)


class CramMD5Mechanism(ServerMechanism, ClientMechanism):
    """Implements the CRAM-MD5 authentication mechanism.

    Warning:
        Although secure during transport, offering this mechanism can be
        dangerous, as it can have implications about how the credentials are
        stored server-side.

    """

    _pattern = re.compile(br'^(.*) ([^ ]+)$')

    def __init__(self, name: Union[str, bytes] = b'CRAM-MD5') -> None:
        super().__init__(name)

    def server_attempt(self, responses: Sequence[ChallengeResponse]) \
            -> Tuple[CramMD5Result, None]:
        try:
            first = responses[0]
        except IndexError as exc:
            challenge = email.utils.make_msgid().encode('utf-8')
            raise ServerChallenge(challenge) from exc

        match = re.match(self._pattern, first.response)
        if not match:
            raise InvalidResponse()
        username, digest = match.groups()

        username_str = username.decode('utf-8')
        result = CramMD5Result(username_str, first.challenge, digest)
        return result, None

    def client_attempt(self, creds: ClientCredentials,
                       challenges: Sequence[ServerChallenge]) \
            -> ChallengeResponse:
        if len(challenges) < 1:
            return ChallengeResponse(b'', b'')
        elif len(challenges) > 1:
            raise UnexpectedChallenge()
        challenge = challenges[0].data
        authcid = saslprep(creds.authcid).encode('utf-8')
        secret = saslprep(creds.secret).encode('utf-8')
        digest = hmac.new(secret, challenge, hashlib.md5).hexdigest()
        response = b' '.join((authcid, digest.encode('ascii')))
        return ChallengeResponse(challenge, response)
