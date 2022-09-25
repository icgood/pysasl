
import secrets
from abc import abstractmethod
from typing import Optional, Sequence
from typing_extensions import Protocol

from .hashing import HashInterface, Cleartext
from .prep import default_prep, Preparation

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
        prepare: The preparation algorithm function.

    """

    __slots__: Sequence[str] = ['_authcid', '_secret', '_prepare']

    def __init__(self, authcid: str, secret: str, *,
                 prepare: Preparation = default_prep) -> None:
        super().__init__()
        self._authcid = authcid
        self._secret = prepare(secret)
        self._prepare = prepare

    @property
    def authcid(self) -> str:
        return self._authcid

    def compare_secret(self, secret: str) -> bool:
        return secrets.compare_digest(self._secret, self._prepare(secret))

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
        prepare: The preparation algorithm function.

    """

    __slots__: Sequence[str] = ['_authcid', '_digest', '_hash', '_prepare']

    def __init__(self, authcid: str, digest: str, *,
                 hash: HashInterface,
                 prepare: Preparation = default_prep) -> None:
        super().__init__()
        self._authcid = authcid
        self._digest = digest
        self._hash = hash
        self._prepare = prepare

    @classmethod
    def create(cls, authcid: str, secret: str, *,
               hash: HashInterface,
               prepare: Preparation = default_prep) -> 'HashedIdentity':
        """Prepare and hash the given *secret*, returning a
        :class:`HashedIdentity`.

        Args:
            authcid: The authentication identity, e.g. a login username.
            secret: The cleartext secret string.
            hash: The hash algorithm to use to verify the secret.
            prepare: The preparation algorithm function.

        """
        digest = hash.hash(prepare(secret))
        return cls(authcid, digest, hash=hash, prepare=prepare)

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
        return self._hash.verify(self._prepare(secret), self._digest)

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
