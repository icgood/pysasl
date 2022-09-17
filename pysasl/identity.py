
import secrets
from abc import abstractmethod
from typing import Optional, Sequence
from typing_extensions import Protocol

from .hashing import HashInterface, Cleartext
from .prep import prepare

__all__ = ['Identity', 'ClearIdentity', 'HashedIdentity']


class Identity(Protocol):
    """Represents an server-side identity that credentials will be
    authenticated against.

    """

    __slots__: Sequence[str] = []

    @property
    @abstractmethod
    def authcid(self) -> str:
        """The authentication identity, e.g. a login username."""
        ...

    @abstractmethod
    def compare_secret(self, secret: str) -> bool:
        """Compare the identity's secret with the given *secret*. The
        comparison must account for things like hashing or token algorithms.

        Args:
            secret: The authentication secret string value.

        """
        ...

    @abstractmethod
    def get_clear_secret(self) -> Optional[str]:
        """Return the cleartext secret string if it is available. This value
        has already been prepared with a :class:`~pysasl.prep.Preparation`
        function.

        """
        ...


class ClearIdentity(Identity):
    """An :class:`Identity` that stores the secret string in cleartext.

    Args:
        authcid: The authentication identity, e.g. a login username.
        secret: The cleartext secret string.

    """

    __slots__: Sequence[str] = ['_authcid', '_secret']

    def __init__(self, authcid: str, secret: str) -> None:
        super().__init__()
        self._authcid = authcid
        self._secret = prepare(secret)

    @property
    def authcid(self) -> str:
        return self._authcid

    def compare_secret(self, secret: str) -> bool:
        return secrets.compare_digest(self._secret, prepare(secret))

    def get_clear_secret(self) -> str:
        """Return the cleartext secret string."""
        return self._secret

    def __repr__(self) -> str:
        return f'ClearIdentity({self.authcid!r}, ...)'


class HashedIdentity(Identity):
    """An :class:`Identity` where the secret has been hashed for storage.

    Args:
        authcid: The authentication identity, e.g. a login username.
        digest: The hashed secret string, using :attr:`.hash`.
        hash: The hash algorithm to use to verify the secret.

    """

    __slots__: Sequence[str] = ['_authcid', '_digest', '_hash']

    def __init__(self, authcid: str, digest: str, *,
                 hash: HashInterface) -> None:
        super().__init__()
        self._authcid = authcid
        self._digest = digest
        self._hash = hash

    @classmethod
    def create(cls, authcid: str, secret: str, *,
               hash: HashInterface) -> 'HashedIdentity':
        """Prepare and hash the given *secret*, returning a
        :class:`HashedIdentity`.

        Args:
            authcid: The authentication identity, e.g. a login username.
            secret: The cleartext secret string.
            hash: The hash algorithm to use to verify the secret.

        """
        digest = hash.hash(prepare(secret))
        return cls(authcid, digest, hash=hash)

    @property
    def authcid(self) -> str:
        return self._authcid

    @property
    def digest(self) -> str:
        """The hashed secret string, using :attr:`.hash`."""
        return self._digest

    @property
    def hash(self) -> HashInterface:
        """The hash implementation to use to verify the secret."""
        return self._hash

    def compare_secret(self, secret: str) -> bool:
        return self._hash.verify(prepare(secret), self._digest)

    def get_clear_secret(self) -> Optional[str]:
        """Return the cleartext secret string, only if :attr:`.hash` is
        :class:`~pysasl.hashing.Cleartext`.

        """
        if isinstance(self.hash, Cleartext):
            return self.digest
        else:
            return None

    def __repr__(self) -> str:
        return f'HashedIdentity({self.authcid}, ..., hash={self._hash!r})'
