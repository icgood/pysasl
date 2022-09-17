
from typing import Optional

from . import Credentials

__all__ = ['ClientCredentials']


class ClientCredentials(Credentials):
    """Credentials that are provided by the user and transmitted to the server
    for authentication..

    Args:
        authcid: The authentication identity, e.g. a login username.
        secret: The secret string, e.g. password.
        authzid: The authorization identity, or an empty string.

    """

    __slots__ = ['_authcid', '_secret', '_authzid']

    def __init__(self, authcid: str, secret: str,
                 authzid: Optional[str] = None) -> None:
        super().__init__()
        self._authcid = authcid
        self._secret = secret
        self._authzid = authzid or ''

    @property
    def authcid(self) -> str:
        return self._authcid

    @property
    def secret(self) -> str:
        """The secret string, e.g. password."""
        return self._secret

    @property
    def authzid(self) -> str:
        return self._authzid

    def __repr__(self) -> str:
        return f'ClientCredentials({self.authcid!r}, ..., {self.authzid!r})'
