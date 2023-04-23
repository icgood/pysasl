
import sys
from collections import OrderedDict
from typing import Iterable, Optional, Sequence
from typing_extensions import Final, Self

if sys.version_info >= (3, 10):  # pragma: no cover
    from importlib.metadata import entry_points
else:  # pragma: no cover
    from importlib_metadata import entry_points

from . import mechanism
from .__about__ import __version__
from .config import default_config, SASLConfig
from .mechanism import Mechanism, ServerMechanism, ClientMechanism

__all__ = ['__version__', 'SASLAuth']


class SASLAuth(SASLConfig):
    """Manages the mechanisms available for authentication attempts.

    Args:
        mechanisms: List of available SASL mechanism objects.
        config: The configuration object.

    """

    __slots__ = ['config', '_server_mechanisms', '_client_mechanisms']

    def __init__(self, mechanisms: Sequence[Mechanism], *,
                 config: SASLConfig = default_config) -> None:
        super().__init__()
        self.config: Final = config
        self._server_mechanisms = OrderedDict(
            (mech.name, mech)
            for mech in mechanisms if isinstance(mech, ServerMechanism))
        self._client_mechanisms = OrderedDict(
            (mech.name, mech)
            for mech in mechanisms if isinstance(mech, ClientMechanism))

    @classmethod
    def defaults(cls, *, config: SASLConfig = default_config) -> Self:
        """Uses the default built-in authentication mechanisms, ``PLAIN`` and
        ``LOGIN``.

        Args:
            config: The configuration object.

        Returns:
            A new :class:`SASLAuth` object.

        """
        return cls.named([b'PLAIN', b'LOGIN'])

    @classmethod
    def named(cls, names: Iterable[bytes], *,
              config: SASLConfig = default_config) -> Self:
        """Uses the built-in authentication mechanisms that match a provided
        name.

        Args:
            names: The authentication mechanism names.
            config: The configuration object.

        Returns:
            A new :class:`SASLAuth` object.

        Raises:
            KeyError: A mechanism name was not recognized.

        """
        builtin = {m.name: m for m in cls._get_builtin_mechanisms(config)}
        return cls([builtin[name] for name in names])

    @classmethod
    def _get_builtin_mechanisms(cls, config: SASLConfig) \
            -> Iterable[Mechanism]:
        group = mechanism.__package__
        for entry_point in entry_points(group=group):
            mech_cls = entry_point.load()
            yield mech_cls(entry_point.name, config)

    @property
    def server_mechanisms(self) -> Sequence[ServerMechanism]:
        """List of available :class:`~pysasl.mechanism.ServerMechanism`
        objects.

        """
        return list(self._server_mechanisms.values())

    @property
    def client_mechanisms(self) -> Sequence[ClientMechanism]:
        """List of available :class:`~pysasl.mechanism.ClientMechanism`
        objects.

        """
        return list(self._client_mechanisms.values())

    def get_server(self, name: bytes) -> Optional[ServerMechanism]:
        """Get a :class:`~pysasl.mechanism.ClientMechanism` by name.

        Args:
            name: The SASL mechanism name.

        Returns:
            The mechanism object or ``None``

        """
        return self._server_mechanisms.get(name.upper())

    def get_client(self, name: bytes) -> Optional[ClientMechanism]:
        """Get a :class:`~pysasl.mechanism.ClientMechanism` by name.

        Args:
            name: The SASL mechanism name.

        Returns:
            The mechanism object or ``None``

        """
        return self._client_mechanisms.get(name.upper())
