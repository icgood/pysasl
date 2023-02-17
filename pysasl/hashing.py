"""Provides an abstraction and several implementations for the ability to hash
and verify secrets.

"""

import os
import hashlib
import secrets
from abc import abstractmethod
from base64 import b64encode, b64decode
from typing import TypeVar, Any, Optional, Sequence, Dict
from typing_extensions import Literal, Protocol, Final, TypeAlias

try:
    from passlib.context import CryptContext
except ImportError as _exc:  # pragma: no cover
    _passlib_import_exc: Optional[ImportError] = _exc
else:
    _passlib_import_exc = None

__all__ = ['HashT', 'HashInterface', 'BuiltinHash', 'Cleartext', 'get_hash']

_Pbkdf2Hashes: TypeAlias = Literal['sha1', 'sha256', 'sha512']

#: Type variable for a :class:`HashInterface`.
HashT = TypeVar('HashT', bound='HashInterface')


class HashInterface(Protocol):
    """Defines a basic interface for hash implementations. This is specifically
    designed to be compatible with :mod:`passlib` hashes.

    """

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

    The constructor arguments are the values used when encoding. When decoding,
    these values are read from the `digest format
    <https://passlib.readthedocs.io/en/stable/lib/passlib.hash.pbkdf2_digest.html?highlight=hmac#format-algorithm>`_.

    Args:
        hash_name: The hash name.
        salt_len: The length of the random salt.
        rounds: The number of hash rounds.

    See Also:
        :class:`passlib.hash.pbkdf2_sha256`

    """

    __slots__: Sequence[str] = ['hash_name', 'salt_len', 'rounds',
                                '_pbkdf2_hash']

    def __init__(self, *, hash_name: _Pbkdf2Hashes = 'sha256',
                 salt_len: int = 16, rounds: int = 500000) -> None:
        super().__init__()
        self.hash_name: Final = hash_name
        self.salt_len: Final = salt_len
        self.rounds: Final = rounds
        self._pbkdf2_hash = self._to_pbkdf2_hash(hash_name)

    def _set_unless_none(self, kwargs: Dict[str, Any],
                         key: str, val: Any) -> None:
        if val is not None:
            kwargs[key] = val

    @classmethod
    def _to_pbkdf2_hash(cls, hash_name: _Pbkdf2Hashes) -> str:
        if hash_name == 'sha1':
            return 'pbkdf2'
        else:
            return 'pbkdf2-' + hash_name

    @classmethod
    def _from_pbkdf2_hash(cls, pbkdf2_hash: str) -> str:
        if pbkdf2_hash == 'pbkdf2':
            return 'sha1'
        elif pbkdf2_hash.startswith('pbkdf2-'):
            _, hash_name = pbkdf2_hash.split('-', 1)
            return hash_name
        raise ValueError(f'Invalid hash name: {pbkdf2_hash}')

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

    @classmethod
    def _hash(cls, hash_name: str, rounds: int, secret: str, salt: bytes) \
            -> bytes:
        value_b = secret.encode('utf-8')
        return hashlib.pbkdf2_hmac(hash_name, value_b, salt, rounds)

    def hash(self, secret: str, salt: Optional[bytes] = None) -> str:
        """Hash the *secret* and return the digest.

        Args:
            secret: The string to hash.
            salt: A salt value to use instead of a random value.

        """
        if salt is None:  # pragma: no cover
            salt = os.urandom(self.salt_len)
        rounds = self.rounds
        digest = self._hash(self.hash_name, rounds, secret, salt)
        b64_salt = b64encode(salt).decode('ascii')
        b64_digest = b64encode(digest).decode('ascii')
        return f'${self._pbkdf2_hash}${rounds}${b64_salt}${b64_digest}'

    def verify(self, secret: str, hash: str) -> bool:
        prefix, pbkdf2_hash, rounds_str, b64_salt, b64_digest = \
            hash.split('$', 4)
        if prefix != '':
            raise ValueError('Invalid hash prefix')
        hash_name = self._from_pbkdf2_hash(pbkdf2_hash)
        rounds = int(rounds_str)
        salt = b64decode(b64_salt)
        digest = b64decode(b64_digest)
        secret_digest = self._hash(hash_name, rounds, secret, salt)
        return secrets.compare_digest(digest, secret_digest)

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


def get_hash(*, passlib_config: Optional[str] = None) \
        -> HashInterface:  # pragma: no cover
    """Provide a secure, default :class:`HashInterface` implementation.

    If *passlib_config* is given, a :class:`~passlib.context.CryptContext` is
    loaded from it. Otherwise, the returned implementation depends on whether
    :mod:`passlib` is available.

    If :mod:`passlib` is available, a :class:`~passlib.context.CryptContext` is
    created with a set of `active hashes
    <https://passlib.readthedocs.io/en/stable/lib/passlib.hash.html#active-hashes>`_,
    defaulting to ``pbkdf2_sha256`` for new digests.

    If :mod:`passlib` is not available, a :class:`BuiltinHash` with default
    settings is created. This is intended to be compatible with the
    :mod:`passlib` default if it is installed later.

    Args:
        passlib_config: A passlib config file.

    See Also:
        :meth:`passlib.context.CryptContext.from_path`

    """
    context: HashInterface
    if passlib_config is not None:
        if _passlib_import_exc is not None:
            raise _passlib_import_exc
        context = CryptContext.from_path(passlib_config)
    elif CryptContext is not None:
        context = CryptContext(
            schemes=['argon2', 'bcrypt_sha256', 'phpass', 'pbkdf2_sha1',
                     'pbkdf2_sha256', 'pbkdf2_sha512', 'scram', 'scrypt'],
            default='pbkdf2_sha256')
    else:
        context = BuiltinHash()
    return context
