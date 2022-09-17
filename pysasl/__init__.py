
from abc import abstractmethod, ABCMeta
from collections import OrderedDict
from typing import Union, Optional, Iterable, Tuple, Sequence

import pkg_resources

from . import mechanisms
from .creds.client import ClientCredentials
from .creds.server import ServerCredentials

__all__ = ['__version__', 'ServerChallenge', 'ChallengeResponse',
           'ServerMechanism', 'ClientMechanism', 'SASLAuth']


#: The pysasl package version.
__version__: str = pkg_resources.require(__package__)[0].version

_Mechanism = Union['ServerMechanism', 'ClientMechanism']


class ServerChallenge(Exception):
    """Raised by :meth:`~ServerMechanism.server_attempt` to provide server
    challenges.

    Args:
        data: The challenge string that should be sent to the client.

    """

    __slots__ = ['_data']

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self._data = data

    @property
    def data(self) -> bytes:
        """The server challenge that should be sent to the client."""
        return self._data

    def __repr__(self) -> str:
        return f'ServerChallenge({self.data!r})'


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

    def __repr__(self) -> str:
        return f'ChallengeResponse({self.challenge!r}, {self.response!r})'


class _BaseMechanism:

    __slots__: Sequence[str] = ['_name']

    def __init__(self, name: Union[str, bytes]) -> None:
        super().__init__()
        if isinstance(name, str):
            name = name.encode('ascii')
        self._name = name

    @property
    def name(self) -> bytes:
        """The SASL name for this mechanism."""
        return self._name

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _BaseMechanism):
            return self.name == other.name
        return NotImplemented


class ServerMechanism(_BaseMechanism, metaclass=ABCMeta):
    """Base class for implementing SASL mechanisms that support server-side
    credential verification.

    """

    __slots__: Sequence[str] = []

    @abstractmethod
    def server_attempt(self, responses: Sequence[ChallengeResponse]) \
            -> Tuple[ServerCredentials, Optional[bytes]]:
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
            InvalidResponse: The server received an invalid client response.

        """
        ...


class ClientMechanism(_BaseMechanism, metaclass=ABCMeta):
    """Base class for implementing SASL mechanisms that support client-side
    credential verification.

    """

    __slots__: Sequence[str] = []

    @abstractmethod
    def client_attempt(self, creds: ClientCredentials,
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

    __slots__ = ['_server_mechanisms', '_client_mechanisms']

    def __init__(self, mechanisms: Sequence[_Mechanism]) -> None:
        super().__init__()
        self._server_mechanisms = OrderedDict(
            (mech.name, mech)
            for mech in mechanisms if isinstance(mech, ServerMechanism))
        self._client_mechanisms = OrderedDict(
            (mech.name, mech)
            for mech in mechanisms if isinstance(mech, ClientMechanism))

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
        builtin = {m.name: m for m in cls._get_builtin_mechanisms()}
        return SASLAuth([builtin[name] for name in names])

    @classmethod
    def _get_builtin_mechanisms(cls) -> Iterable[_Mechanism]:
        group = mechanisms.__package__
        for entry_point in pkg_resources.iter_entry_points(group):
            mech_cls = entry_point.load()
            yield mech_cls(entry_point.name)

    @property
    def server_mechanisms(self) -> Sequence[ServerMechanism]:
        """List of available :class:`ServerMechanism` objects."""
        return list(self._server_mechanisms.values())

    @property
    def client_mechanisms(self) -> Sequence[ClientMechanism]:
        """List of available :class:`ClientMechanism` objects."""
        return list(self._client_mechanisms.values())

    def get_server(self, name: bytes) -> Optional[ServerMechanism]:
        """Like :meth:`.get`, but only mechanisms inheriting
        :class:`ServerMechanism` will be returned.

        Args:
            name: The SASL mechanism name.

        Returns:
            The mechanism object or ``None``

        """
        return self._server_mechanisms.get(name.upper())

    def get_client(self, name: bytes) -> Optional[ClientMechanism]:
        """Like :meth:`.get`, but only mechanisms inheriting
        :class:`ClientMechanism` will be returned.

        Args:
            name: The SASL mechanism name.

        Returns:
            The mechanism object or ``None``

        """
        return self._client_mechanisms.get(name.upper())
