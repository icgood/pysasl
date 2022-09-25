
import secrets
from typing import Optional

from .server import ServerCredentials
from ..identity import Identity
from ..prep import default_prep, Preparation

__all__ = ['PlainCredentials']


class PlainCredentials(ServerCredentials):
    """Implementation of :class:`~pysasl.creds.server.ServerCredentials` for
    typical SASL mechanisms like
    :class:`~pysasl.mechanism.plain.PlainMechanism` where the mechanism
    operates on the *secret* string in cleartext.

    Args:
        authcid: Authentication ID string (the username).
        secret: Secret string (the password).
        authzid: Authorization ID string, if provided.
        prepare: The preparation algorithm function.

    """

    __slots__ = ['_authcid', '_secret', '_authzid', '_prepare']

    def __init__(self, authcid: str, secret: str, authzid: str = '', *,
                 prepare: Preparation = default_prep) -> None:
        super().__init__()
        self._authcid = authcid
        self._secret = secret
        self._authzid = authzid or prepare(authcid)
        self._prepare = prepare

    @property
    def authcid(self) -> str:
        return self._authcid

    @property
    def authzid(self) -> str:
        return self._authzid

    def verify(self, identity: Optional[Identity]) -> bool:
        if identity is not None:
            prepare = self._prepare
            self_authcid = prepare(self.authcid)
            other_authcid = prepare(identity.authcid)
            return secrets.compare_digest(self_authcid, other_authcid)  \
                and identity.compare_secret(self._secret)
        return False

    def __repr__(self) -> str:
        return f'PlainCredentials({self.authcid!r}, ..., {self.authzid!r})'
