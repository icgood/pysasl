
from typing import Optional
from typing_extensions import Final

from .hashing import HashInterface, Cleartext

__all__ = ['StoredSecret', 'AuthenticationCredentials']


class StoredSecret:
    """Represents a secret that has been hashed for storage. An unhashed secret
    may be verified by using the same hash implementation and comparing the
    result.

    Args:
        raw: Stored secret hash string, using *hash*.
        hash: The hash implementation to use to verify the secret.

    """

    def __init__(self, raw: str, *,
                 hash: HashInterface = Cleartext()) -> None:
        super().__init__()
        self.raw: Final = raw
        self.hash: Final = hash

    def verify(self, secret: str) -> bool:
        """Compare the result of hashing *secret* against *stored*, returning
        True if the hashes match.

        Args:
            secret: Secret string, unhashed.

        """
        return self.hash.verify(secret, self.raw)

    def __repr__(self) -> str:
        return f'StoredSecret(..., hash={self.hash!r})'


class AuthenticationCredentials:
    """Object returned by :meth:`~ServerMechanism.server_attempt` and passed in
    to :meth:`~ClientMechanism.client_attempt` containing information about the
    authentication credentials in use.

    Args:
        authcid: Authentication ID string (the username).
        secret: Secret string (the password).
        authzid: Authorization ID string, if applicable.

    """

    __slots__ = ['_authcid', '_secret', '_authzid']

    def __init__(self, authcid: str, secret: str,
                 authzid: Optional[str] = None) -> None:
        super(AuthenticationCredentials, self).__init__()
        self._authcid = authcid
        self._secret = secret
        self._authzid = authzid or None

    @property
    def has_secret(self) -> bool:
        """True if the :attr:`.secret` attribute is valid for this credentials
        type.

        If this returns False, the :attr:`.secret` attribute should raise
        :exc:`AttributeError`.

        """
        return True

    @property
    def authcid(self) -> str:
        """The authentication identity string used in the attempt."""
        return self._authcid

    @property
    def secret(self) -> str:
        """Contains the secret string used in the authentication attempt,
        if available. Use :meth:`.check_secret` instead, when possible.

        """
        return self._secret

    @property
    def authzid(self) -> Optional[str]:
        """The authorization identity string used in the attempt, or ``None``
        if this field is empty or unused.

        """
        return self._authzid

    @property
    def identity(self) -> str:
        """The canonical identity being assumed by the authentication attempt.
        This is :attr:`.authzid` if available, :attr:`.authcid` otherwise.

        Consider a UNIX system where ``root`` is the superuser and only it may
        assume the identity of other users. With an :attr:`.authcid` of
        ``root`` and an :attr:`.authzid` of ``terry``, the authorization would
        succeed and :attr:`.identity` would be ``terry``. With an
        :attr:`.authcid` of ``greg``, authorization would fail because ``greg``
        is not the superuser and cannot assume the :attr:`.identity` of
        ``terry``.

        """
        if self.authzid is not None:
            return self.authzid
        else:
            return self.authcid

    def check_secret(self, secret: Optional[StoredSecret], **other) -> bool:
        """Checks if the secret string used in the authentication attempt
        matches the "known" secret string. Some mechanisms will override this
        method to control how this comparison is made.

        Args:
            secret: The secret to compare against what was used in the
                authentication attempt.
            other: Allows subclasses to accept additional keywords as needed.

        Returns:
            True if the given secret matches the authentication attempt.

        """
        if secret is not None:
            return secret.verify(self.secret)
        return False
