
import secrets
from abc import abstractmethod
from typing import Optional, Sequence
from typing_extensions import Protocol, Self

from .hashing import HashInterface, Cleartext
from .prep import saslprep, Preparation

__all__ = ['Identity', 'ClearIdentity', 'HashedIdentity']


class Identity(Protocol):
    """Represents an server-side identity that credentials will be
    authenticated against.

    """

    __slots__: Sequence[str] = []

    @abstractmethod
    def compare_authcid(self, authcid: str) -> bool:
        """Compare the identity's authcid with the given *authcid*.

        Args:
            authcid: The authentication identity string value.

        """
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
        """Return the cleartext secret string if it is available."""
        ...


class ClearIdentity(Identity):
    """An :class:`Identity` that stores the secret string in cleartext.

    Args:
        authcid: The authentication identity, e.g. a login username.
        secret: The authentication secret string value, e.g. a login password.
        prepare: The string preparation function.

    """

    __slots__ = ['_authcid', '_secret', '_prepare']

    def __init__(self, authcid: str, secret: str, *,
                 prepare: Preparation = saslprep) -> None:
        super().__init__()
        self._authcid = authcid
        self._secret = secret
        self._prepare = prepare

    def _compare(self, this: str, that: str) -> bool:
        prepare = self._prepare
        prepared_this = prepare(this).encode('utf-8')
        prepared_that = prepare(that).encode('utf-8')
        return secrets.compare_digest(prepared_this, prepared_that)

    def compare_authcid(self, authcid: str) -> bool:
        return self._compare(self._authcid, authcid)

    def compare_secret(self, secret: str) -> bool:
        return self._compare(self._secret, secret)

    def get_clear_secret(self) -> str:
        """Return the cleartext secret string."""
        return self._secret

    def __repr__(self) -> str:
        return f'ClearIdentity({self._authcid!r}, ...)'


class HashedIdentity(Identity):
    """An :class:`Identity` where the secret has been hashed for storage.

    Args:
        authcid: The authentication identity, e.g. a login username.
        digest: The hashed secret string, using :attr:`.hash`.
        hash: The hash algorithm to use to verify the secret.
        prepare: The string preparation function.

    """

    __slots__ = ['_authcid', '_digest', '_hash', '_prepare']

    def __init__(self, authcid: str, digest: str, *,
                 hash: HashInterface,
                 prepare: Preparation = saslprep) -> None:
        super().__init__()
        self._authcid = authcid
        self._digest = digest
        self._hash = hash
        self._prepare = prepare

    @classmethod
    def create(cls, authcid: str, secret: str, *,
               hash: HashInterface,
               prepare: Preparation = saslprep) -> Self:
        """Prepare and hash the given *secret*, returning a
        :class:`HashedIdentity`.

        Args:
            authcid: The authentication identity, e.g. a login username.
            secret: The cleartext secret string.
            hash: The hash algorithm to use to verify the secret.
            prepare: The string preparation function.

        """
        digest = hash.hash(prepare(secret))
        return cls(authcid, digest, hash=hash, prepare=prepare)

    @property
    def digest(self) -> str:
        """The hashed secret string, using :attr:`.hash`."""
        return self._digest

    @property
    def hash(self) -> HashInterface:
        """The hash implementation to use to verify the secret."""
        return self._hash

    def _compare(self, this: str, that: str) -> bool:
        prepare = self._prepare
        prepared_this = prepare(this).encode('utf-8')
        prepared_that = prepare(that).encode('utf-8')
        return secrets.compare_digest(prepared_this, prepared_that)

    def compare_authcid(self, authcid: str) -> bool:
        return self._compare(self._authcid, authcid)

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
        return f'HashedIdentity({self._authcid}, ..., hash={self._hash!r})'
