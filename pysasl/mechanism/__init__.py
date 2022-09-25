

from abc import abstractmethod, ABCMeta
from typing import Union, Optional, Tuple, Sequence
from typing_extensions import TypeAlias

from ..config import SASLConfig
from ..creds.client import ClientCredentials
from ..creds.server import ServerCredentials

__all__ = ['Mechanism', 'ServerChallenge', 'ChallengeResponse',
           'ServerMechanism', 'ClientMechanism']

#: A type alias for either server or client mechanisms.
Mechanism: TypeAlias = Union['ServerMechanism', 'ClientMechanism']


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

    __slots__: Sequence[str] = ['_name', '_config']

    def __init__(self, name: Union[str, bytes], config: SASLConfig) -> None:
        super().__init__()
        if isinstance(name, str):
            name = name.encode('ascii')
        self._name = name
        self._config = config

    @property
    def name(self) -> bytes:
        """The SASL name for this mechanism."""
        return self._name

    @property
    def config(self) -> SASLConfig:
        """The configuration object."""
        return self._config

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _BaseMechanism):
            return self.name == other.name and self.config == other.config
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
