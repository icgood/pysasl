
from abc import abstractmethod
from typing import Sequence
from typing_extensions import Protocol

__all__ = ['Credentials']


class Credentials(Protocol):
    """SASL authentication credentials consist of an authentication identity
    and an authorization identity, the identity to be assumed.

    Consider a UNIX system where ``root`` is the superuser and only it may
    assume the identity of other users. With an authentication identity of
    ``root`` and an authorization identity of ``terry``, the authorization
    would succeed because the authentication identity has sufficient
    privileges to assume the authorization identity. If the authentication
    identity were ``greg``, authorization would fail because ``greg`` does not
    have superuser privileges to assume the identity of ``terry``.

    See:
        :class:`~pysasl.creds.identity.Identity`,
        `RFC 4422 2. <https://www.rfc-editor.org/rfc/rfc4422#section-2>`_

    """

    __slots__: Sequence[str] = []

    @property
    @abstractmethod
    def authcid(self) -> str:
        """The authentication identity, e.g. a login username."""
        ...

    @property
    @abstractmethod
    def authzid(self) -> str:
        """The authorization identity. The :attr:`.authcid` identity must have
        sufficient privileges to assume this identity for the authentication
        attempt to succeed.

        """
        ...
