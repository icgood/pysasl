
from typing import Any, Optional, Tuple, Sequence, NoReturn

from .. import (ServerMechanism, ClientMechanism, ServerChallenge,
                ChallengeResponse, UnexpectedChallenge,
                ExternalVerificationRequired)
from ..creds import StoredSecret, AuthenticationCredentials

__all__ = ['ExternalResult', 'ExternalMechanism']


class ExternalResult(AuthenticationCredentials):
    """External credentials do not contain authentication credentials, only an
    :attr:`.identity` to authorize as.

    """

    def __init__(self, authzid: Optional[str] = None, *,
                 authcid_type: Optional[str] = None) -> None:
        authcid = authzid or ''
        super().__init__(authcid, '', authzid, authcid_type=authcid_type)

    @property
    def has_secret(self) -> bool:
        return False

    @property
    def secret(self) -> str:
        raise AttributeError('secret')

    def check_secret(self, secret: Optional[StoredSecret],
                     **other: Any) -> NoReturn:
        """This implementation does not use *secret* and instead raises
        :exc:`~pysasl.ExternalVerificationRequired` immediately.

        Raises:
            :exc:`~pysasl.ExternalVerificationRequired`

        """
        raise ExternalVerificationRequired()


class ExternalMechanism(ServerMechanism, ClientMechanism):
    """Implements the EXTERNAL authentication mechanism.

    See Also:
        `RFC 4422 Appendix A <https://tools.ietf.org/html/rfc4422#appendix-A>`_

    """

    name = b'EXTERNAL'

    def server_attempt(self, responses: Sequence[ChallengeResponse]) \
            -> Tuple[ExternalResult, None]:
        try:
            first = responses[0]
        except IndexError as exc:
            raise ServerChallenge(b'') from exc
        authzid_str = first.response.decode('utf-8')
        return ExternalResult(authzid_str), None

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
        return ChallengeResponse(challenge, authzid)
