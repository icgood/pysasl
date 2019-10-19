
import hmac
from abc import abstractmethod, ABCMeta
from collections import OrderedDict
from typing import ClassVar, Optional, Iterable, Tuple, Mapping, Sequence

from pkg_resources import iter_entry_points

__all__ = ['AuthenticationError', 'UnexpectedChallenge', 'ServerChallenge',
           'AuthenticationCredentials', 'BaseMechanism', 'ServerMechanism',
           'ClientMechanism', 'SASLAuth']


class AuthenticationError(Exception):
    """Indicates that authentication failed due to a protocol error unrelated
    to any provided credentials.

    """

    __slots__: Sequence[str] = []


class UnexpectedChallenge(AuthenticationError):
    """During client-side authentication, the SASL mechanism received an
    authentication challenge from the server that it did not expect.

    """

    __slots__: Sequence[str] = []

    def __init__(self) -> None:
        super().__init__('Unexpected auth challenge')


class ServerChallenge(Exception):
    """Raised by :meth:`~ServerMechanism.server_attempt` to provide server
    challenges.

    Args:
        data: The challenge string that should be sent to the client.

    """

    __slots__ = ['_data']

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._data = data

    @property
    def data(self) -> bytes:
        """The server challenge that should be sent to the client."""
        return self._data


class ChallengeResponse:
    """A challenge-response exchange between server and client.

    Args:
        challenge: The server challenge string.
        response: The client response string.

    """

    __slots__ = ['_challenge', '_response']

    def __init__(self, challenge: bytes, response: bytes) -> None:
        super().__init__()
        self._challenge = challenge
        self._response = response

    @property
    def challenge(self) -> bytes:
        """The server challenge string."""
        return self._challenge

    @property
    def response(self) -> bytes:
        """The client response string."""
        return self._response


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

    def check_secret(self, secret: str) -> bool:
        """Checks if the secret string used in the authentication attempt
        matches the "known" secret string. Some mechanisms will override this
        method to control how this comparison is made.

        Args:
            secret: The secret string to compare against what was used in the
                authentication attempt.

        Returns:
            True if the given secret matches the authentication attempt.

        """
        return hmac.compare_digest(secret, self.secret)


class BaseMechanism(metaclass=ABCMeta):
    """Base class for all server- and client-side SASL mechanisms.

    Attributes:
        name: The SASL name for this mechanism.

    """

    __slots__: Sequence[str] = []

    name: ClassVar[bytes] = b''


class ServerMechanism(BaseMechanism, metaclass=ABCMeta):
    """Base class for implementing SASL mechanisms that support server-side
    credential verification.

    """

    __slots__: Sequence[str] = []

    @abstractmethod
    def server_attempt(self, responses: Sequence[ChallengeResponse]) \
            -> Tuple[AuthenticationCredentials, Optional[bytes]]:
        """For SASL server-side credential verification, receives responses
        from the client and issues challenges until it has everything needed to
        verify the credentials.

        If a challenge is necessary, a :class:`ServerChallenge` exception will
        be raised. The response to this challenge must then be added to
        *responses* in the next call to :meth:`.server_attempt`.

        Args:
            responses: The challenge-response exchanges thus far.

        Returns:
            A tuple of the authentication credentials received from the client
            once no more challenges are necessary, and an optional final
            response string from the server used by some mechanisms.

        Raises:
            ServerChallenge: The server challenge needing a client response.

        """
        ...


class ClientMechanism(BaseMechanism, metaclass=ABCMeta):
    """Base class for implementing SASL mechanisms that support client-side
    credential verification.

    """

    __slots__: Sequence[str] = []

    @abstractmethod
    def client_attempt(self, creds: AuthenticationCredentials,
                       challenges: Sequence[ServerChallenge]) \
            -> ChallengeResponse:
        """For SASL client-side credential verification, produce responses to
        send to the server and react to its challenges until the server returns
        a final success or failure.

        Args:
            creds: The credentials to attempt authentication with.
            challenges: The server challenges received.

        Returns:
            The response to the most recent server challenge.

        Raises:
            UnexpectedChallenge: The server has issued a challenge the client
                mechanism does not recognize.

        """
        ...


class SASLAuth:
    """Manages the mechanisms available for authentication attempts.

    Args:
        mechanisms: List of available SASL mechanism objects.

    """

    __slots__ = ['mechanisms']

    def __init__(self, mechanisms: Iterable[BaseMechanism]) -> None:
        super().__init__()
        self.mechanisms: Mapping[bytes, BaseMechanism] = \
            OrderedDict((mech.name, mech) for mech in mechanisms)

    @classmethod
    def defaults(cls) -> 'SASLAuth':
        """Uses the default built-in authentication mechanisms, ``PLAIN`` and
        ``LOGIN``.

        Returns:
            A new :class:`SASLAuth` object.

        """
        return cls.named([b'PLAIN', b'LOGIN'])

    @classmethod
    def named(cls, names: Iterable[bytes]) -> 'SASLAuth':
        """Uses the built-in authentication mechanisms that match a provided
        name.

        Args:
            names: The authentication mechanism names.

        Returns:
            A new :class:`SASLAuth` object.

        Raises:
            KeyError: A mechanism name was not recognized.

        """
        builtin = dict(cls._get_builtin_mechanisms())
        return SASLAuth(builtin[name] for name in names)

    @classmethod
    def _get_builtin_mechanisms(cls) -> Iterable[Tuple[bytes, BaseMechanism]]:
        for entry_point in iter_entry_points('pysasl.mechanisms'):
            mech_cls = entry_point.load()
            yield (mech_cls.name, mech_cls())

    @property
    def server_mechanisms(self) -> Sequence[ServerMechanism]:
        """List of available :class:`ServerMechanism` objects."""
        return [mech for mech in self.mechanisms.values()
                if isinstance(mech, ServerMechanism)]

    @property
    def client_mechanisms(self) -> Sequence[ClientMechanism]:
        """List of available :class:`ClientMechanism` objects."""
        return [mech for mech in self.mechanisms.values()
                if isinstance(mech, ClientMechanism)]

    def get(self, name: bytes) -> Optional[BaseMechanism]:
        """Get a SASL mechanism by name.

        Args:
            name: The SASL mechanism name.

        Returns:
            The mechanism object or ``None``

        """
        return self.mechanisms.get(name.upper())

    def get_server(self, name: bytes) -> Optional[ServerMechanism]:
        """Like :meth:`.get`, but only mechanisms inheriting
        :class:`ServerMechanism` will be returned.

        Args:
            name: The SASL mechanism name.

        Returns:
            The mechanism object or ``None``

        """
        mech = self.get(name)
        return mech if isinstance(mech, ServerMechanism) else None

    def get_client(self, name: bytes) -> Optional[ClientMechanism]:
        """Like :meth:`.get`, but only mechanisms inheriting
        :class:`ClientMechanism` will be returned.

        Args:
            name: The SASL mechanism name.

        Returns:
            The mechanism object or ``None``

        """
        mech = self.get(name)
        return mech if isinstance(mech, ClientMechanism) else None
