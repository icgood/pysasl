
from typing import Optional, Sequence
from typing_extensions import Final

__all__ = ['AuthenticationError', 'UnexpectedChallenge', 'InvalidResponse',
           'ExternalVerificationRequired', 'MechanismUnusable']


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


class ExternalVerificationRequired(AuthenticationError):
    """The credentials are structurally valid but require external
    verification.

    If *token* is ``None``, the credentials provided no additional information
    for verification. Otherwise, *token* should be verified and authorized for
    the :attr:`~pysasl.creds.AuthenticationCredentials.identity` from the
    credentials.

    Args:
        token: A bearer token, if required for verification.

    """

    __slots__: Sequence[str] = ['token']

    def __init__(self, token: Optional[str] = None) -> None:
        super().__init__()
        self.token: Final = token


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
