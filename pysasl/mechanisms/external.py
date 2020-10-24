
from typing import Optional, Tuple, Sequence

from .. import (ServerMechanism, ClientMechanism, ServerChallenge,
                ChallengeResponse, UnexpectedChallenge)
from ..creds import StoredSecret, AuthenticationCredentials

__all__ = ['ExternalResult', 'ExternalMechanism']


class ExternalResult(AuthenticationCredentials):
    """Because this mechanism does not use authentication identity or secret
    strings, the :meth:`~ExternalMechanism.server_attempt` method returns this
    sub-class which only allows the :attr:`.authzid` attribute.

    """

    def __init__(self, authzid: Optional[str] = None) -> None:
        super(ExternalResult, self).__init__('', '', authzid)

    @property
    def has_secret(self) -> bool:
        return False

    @property
    def authcid(self) -> str:
        """The authentication identity string is an alias of the
        :attr:`.authzid` string for this mechanism, except it will return an
        empty string instead of ``None``.

        """
        return self.authzid or ''

    @property
    def secret(self) -> str:
        """The secret string is not available for this mechanism.

        Raises:
            AttributeError

        """
        raise AttributeError('secret')

    def check_secret(self, secret: Optional[StoredSecret], **other) -> bool:
        """This method always returns True for this mechanism, unless
        overridden by a subclass to provide external enforcement rules.

        """
        return True


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
