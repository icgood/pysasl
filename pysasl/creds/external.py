
from typing import Optional, Sequence

from .server import ServerCredentials
from ..exception import ExternalVerificationRequired
from ..identity import Identity

__all__ = ['ExternalCredentials']


class ExternalCredentials(ServerCredentials):
    """Credentials that require external verification, rather than by a
    traditional hashing algorithm.

    Args:
        authzid: Authorization ID string, if applicable.
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

    def verify(self, identity: Optional[Identity]) -> bool:
        raise ExternalVerificationRequired(self._token)

    def __repr__(self) -> str:
        return f'ExternalCredentials({self.authzid}, ...)'
