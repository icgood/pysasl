
from typing import Optional, Sequence, NoReturn
from typing_extensions import Final

from .server import ServerCredentials
from ..exception import AuthenticationError
from ..identity import Identity

__all__ = ['ExternalVerificationRequired', 'ExternalCredentials']


class ExternalVerificationRequired(AuthenticationError):
    """The credentials are structurally valid but require external
    verification.

    If *token* is ``None``, the credentials provided no additional information
    for verification. Otherwise, *token* should be verified and authorized for
    *identity*.

    Args:
        identity: The identity resolved from the credentials.
        token: A bearer token, if required for verification.

    """

    __slots__: Sequence[str] = ['identity', 'token']

    def __init__(self, identity: Optional[Identity],
                 token: Optional[str] = None) -> None:
        super().__init__()
        self.identity: Final = identity
        self.token: Final = token


class ExternalCredentials(ServerCredentials):
    """Credentials that require external verification, rather than by a
    traditional hashing algorithm.

    Args:
        authzid: Authorization ID string.
        token: A bearer token, if required for verification.

    """

    __slots__: Sequence[str] = ['_authzid', '_token']

    def __init__(self, authzid: str, token: Optional[str] = None) -> None:
        super().__init__()
        self._authzid = authzid
        self._token = token

    @property
    def authcid(self) -> str:
        return ''

    @property
    def authzid(self) -> str:
        return self._authzid

    def verify(self, identity: Optional[Identity]) -> NoReturn:
        """This method always throws :exc:`ExternalVerificationRequired`. For
        applications to support these types of credentials, they must catch
        this exception and use it to authenticate and authorize the request.

        Args:
            identity: The identity being authenticated.

        Raises:
            ExternalVerificationRequired: Always thrown.

        """
        raise ExternalVerificationRequired(identity, self._token)

    def __repr__(self) -> str:
        return f'ExternalCredentials({self.authzid}, ...)'
