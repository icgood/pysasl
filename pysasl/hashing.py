"""Provides an abstraction and several implementations for the ability to hash
and verify secrets.

"""

import os
import base64
import hashlib
import secrets
from abc import abstractmethod
from typing import TypeVar, Any, Optional, Sequence, Dict
from typing_extensions import Protocol, Final

try:
    from passlib.context import CryptContext
    from passlib.apps import custom_app_context
except ImportError as _exc:  # pragma: no cover
    CryptContext = None
    custom_app_context = None
    _passlib_import_exc = _exc

__all__ = ['HashT', 'HashInterface', 'BuiltinHash', 'Cleartext', 'get_hash']

#: Type variable for a :class:`HashInterface`.
HashT = TypeVar('HashT', bound='HashInterface')


class HashInterface(Protocol):
    """Defines a basic interface for hash implementations. This is specifically
    designed to be compatible with :mod:`passlib` hashes.

    """

    __slots__: Sequence[str] = []

    @abstractmethod
    def copy(self: HashT, **kwargs: Any) -> HashT:
        """Return a copy of the hash implementation. The *kwargs* may be used
        by some hashes to modify settings on the hash.

        Args:
            self: The hash object being copied.
            kwargs: Updated settings for the returned hash.

        """
        ...

    @abstractmethod
    def hash(self, secret: str) -> str:
        """Hash the *value* and return the digest.

        Args:
            secret: The string to hash.

        """
        ...

    @abstractmethod
    def verify(self, secret: str, hash: str) -> bool:
        """Check the *secret* against the given *hash*.

        Args:
            secret: The string to check.
            hash: The hashed digest string.

        """
        ...


class BuiltinHash(HashInterface):
    """Implements :class:`HashInterface` using the :func:`hashlib.pbkdf2_hmac`
    function and random salt.

    Args:
        hash_name: The hash name.
        salt_len: The length of the random salt.
        rounds: The number of hash rounds.

    """

    __slots__: Sequence[str] = ['hash_name', 'salt_len', 'rounds']

    def __init__(self, *, hash_name: str = 'sha256', salt_len: int = 16,
                 rounds: int = 1000000) -> None:
        super().__init__()
        self.hash_name: Final = hash_name
        self.salt_len: Final = salt_len
        self.rounds: Final = rounds

    def _set_unless_none(self, kwargs: Dict[str, Any],
                         key: str, val: Any) -> None:
        if val is not None:
            kwargs[key] = val

    def copy(self, *, hash_name: Optional[str] = None,
             salt_len: Optional[int] = None,
             rounds: Optional[int] = None,
             **kwargs: Any) -> 'BuiltinHash':
        """Return a copy of the hash implementation, possibly with updated
        parameters.

        Args:
            hash_name: The updated hash name.
            salt_len: The updated length of the random salt.
            rounds: The updated number of hash rounds.
            kwargs: Additional keyword arguments are ignored.

        """
        copy_kwargs: Dict[str, Any] = {'hash_name': self.hash_name,
                                       'salt_len': self.salt_len,
                                       'rounds': self.rounds}
        new_kwargs: Dict[str, Any] = {}
        self._set_unless_none(new_kwargs, 'hash_name', hash_name)
        self._set_unless_none(new_kwargs, 'salt_len', salt_len)
        self._set_unless_none(new_kwargs, 'rounds', rounds)
        if new_kwargs:
            copy_kwargs.update(new_kwargs)
            return BuiltinHash(**copy_kwargs)
        else:
            return self

    def _hash(self, secret: str, salt: bytes) -> bytes:
        value_b = secret.encode('utf-8')
        digest = hashlib.pbkdf2_hmac(
            self.hash_name, value_b, salt, self.rounds)
        return salt + digest

    def hash(self, secret: str, salt: Optional[bytes] = None) -> str:
        """Hash the *secret* and return the digest.

        Args:
            secret: The string to hash.
            salt: A salt value to use instead of a random value.

        """
        if salt is None:  # pragma: no cover
            salt = os.urandom(self.salt_len)
        digest = self._hash(secret, salt)
        return self.encode_digest(digest)

    def verify(self, secret: str, hash: str) -> bool:
        digest_b = self.decode_digest(hash)
        salt = digest_b[0:self.salt_len]
        value_digest = self._hash(secret, salt)
        return secrets.compare_digest(value_digest, digest_b)

    @classmethod
    def encode_digest(cls, digest: bytes) -> str:
        """Encode the digest into a string. This uses :func:`~base64.b64encode`
        by default, but can be overridden by subclasses.

        Args:
            digest: The raw digest bytestring.

        """
        return base64.b64encode(digest).decode('ascii')

    @classmethod
    def decode_digest(cls, digest: str) -> bytes:
        """Decode the digest from a string. This uses :func:`~base64.b64decode`
        by default, but can be overridden by subclasses.

        Args:
            digest: The encoded digest string.

        """
        return base64.b64decode(digest)

    def __repr__(self) -> str:
        return 'BuiltinHash(hash_name=%r, salt_len=%r, rounds=%r)' % \
            (self.hash_name, self.salt_len, self.rounds)


class Cleartext(HashInterface):
    """Implements :class:`HashInterface` with no hashing performed."""

    __slots__: Sequence[str] = []

    def copy(self, **kwargs: Any) -> 'Cleartext':
        return self

    def hash(self, secret: str) -> str:
        return secret

    def verify(self, secret: str, hash: str) -> bool:
        return secrets.compare_digest(secret, hash)

    def __repr__(self) -> str:
        return 'Cleartext()'


def get_hash(*, no_passlib: bool = False,
             passlib_config: Optional[str] = None) \
        -> HashInterface:  # pragma: no cover
    """Provide a secure, default :class:`HashInterface` implementation.

    If :mod:`passlib` is not available, a custom hash is always used based on
    :func:`hashlib.pbkdf2_hmac`. The *passlib_config* parameter is ignored.

    If :mod:`passlib` is available, a :class:`~passlib.context.CryptContext` is
    loaded from the *passlib_config* parameter. If *passlib_config* is
    ``None``, then :attr:`passlib.apps.custom_app_context` is returned.

    Args:
        no_passlib: If true, do not use :mod:`passlib` even if available.
        passlib_config: A passlib config file.

    """
    context: HashInterface
    if no_passlib:
        return BuiltinHash()
    elif passlib_config is not None:
        if CryptContext is not None:
            context = CryptContext.from_path(passlib_config)
        else:
            raise _passlib_import_exc
    elif custom_app_context is not None:
        context = custom_app_context.copy()
    else:
        context = BuiltinHash()
    return context
