
from typing import Sequence

__all__ = ['AuthenticationError', 'UnexpectedChallenge', 'InvalidResponse',
           'MechanismUnusable']


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


class InvalidResponse(AuthenticationError):
    """During server-side authentication, the SASL mechanism received an
    authentication response from the client that was invalid.

    """

    __slots__: Sequence[str] = []

    def __init__(self) -> None:
        super().__init__('Invalid auth response')


class MechanismUnusable(AuthenticationError):
    """The mechanism cannot be used to authenticate the given identity. Usually
    this is due to an unsupported hashing algorithm used in the server-side
    authentication database.

    Args:
        name: The mechanism name that is unusable.

    """

    __slots__: Sequence[str] = []

    def __init__(self, name: str) -> None:
        super().__init__(f'{name} cannot authenticate this identity')
