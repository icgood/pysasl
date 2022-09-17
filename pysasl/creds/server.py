
from abc import abstractmethod
from typing import Optional, Sequence
from typing_extensions import Protocol

from . import Credentials
from ..identity import Identity

__all__ = ['ServerCredentials']


class ServerCredentials(Credentials, Protocol):
    """Credentials that are received from a client and should be authenticated
    against a known secret value.

    """

    __slots__: Sequence[str] = []

    @abstractmethod
    def verify(self, identity: Optional[Identity]) -> bool:
        """Authenticates the credentials against the given *identity*.

        Args:
            identity: The identity being authenticated.

        Raises:
            MechanismUnusable: The mechanism is not capable of verifying
                *identity*.

        """
        ...
