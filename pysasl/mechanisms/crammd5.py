
import re
import hmac
import hashlib
import email.utils
from typing import Optional, Tuple, Sequence

from .. import (ServerMechanism, ClientMechanism, ServerChallenge,
                ChallengeResponse, AuthenticationError, UnexpectedChallenge)
from ..creds import StoredSecret, AuthenticationCredentials

try:
    from passlib.utils import saslprep  # type: ignore
except ImportError:  # pragma: no cover
    def saslprep(source: str) -> str:
        return source

__all__ = ['CramMD5Result', 'CramMD5Mechanism']


class CramMD5Result(AuthenticationCredentials):
    """Because this mechanism uses hash algorithms to compare secrets, the
    :meth:`~CramMD5Mechanism.server_attempt` method returns this sub-class
    which overrides the :meth:`.check_secret` method.

    """

    __slots__ = ['_challenge', '_digest']

    def __init__(self, username: str, challenge: bytes,
                 digest: bytes) -> None:
        super().__init__(username, '')
        self._challenge = challenge
        self._digest = digest

    @property
    def has_secret(self) -> bool:
        return False

    @property
    def challenge(self) -> bytes:
        """The challenge string issued by the server."""
        return self._challenge

    @property
    def digest(self) -> bytes:
        """The digest computed by the client."""
        return self._digest

    @property
    def secret(self) -> str:
        """The secret string is not available in this mechanism.

        Raises:
            :exc:`AttributeError`

        """
        raise AttributeError('secret')

    def check_secret(self, secret: Optional[StoredSecret], **other) -> bool:
        if secret is not None:
            secret_b = saslprep(secret.raw).encode('utf-8')
            expected_hmac = hmac.new(secret_b, self.challenge, hashlib.md5)
            expected = expected_hmac.hexdigest().encode('ascii')
            return hmac.compare_digest(expected, self.digest)
        return False


class CramMD5Mechanism(ServerMechanism, ClientMechanism):
    """Implements the CRAM-MD5 authentication mechanism.

    Warning:
        Although secure during transport, offering this mechanism can be
        dangerous, as it can have implications about how the credentials are
        stored server-side.

    """

    _pattern = re.compile(br'^(.*) ([^ ]+)$')

    name = b'CRAM-MD5'

    def server_attempt(self, responses: Sequence[ChallengeResponse]) \
            -> Tuple[CramMD5Result, None]:
        try:
            first = responses[0]
        except IndexError as exc:
            challenge = email.utils.make_msgid().encode('utf-8')
            raise ServerChallenge(challenge) from exc

        match = re.match(self._pattern, first.response)
        if not match:
            raise AuthenticationError('Invalid CRAM-MD5 response')
        username, digest = match.groups()

        username_str = username.decode('utf-8')
        return CramMD5Result(username_str, first.challenge, digest), None

    def client_attempt(self, creds: AuthenticationCredentials,
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
