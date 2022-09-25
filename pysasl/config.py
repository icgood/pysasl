
from dataclasses import dataclass
from typing_extensions import Final

from .prep import default_prep, Preparation

__all__ = ['SASLConfig', 'default_config']


@dataclass(frozen=True)
class SASLConfig:
    """Provides any configuration necessary for
    :class:`~pysasl.mechanism.ServerMechanism` or
    :class:`~pysasl.mechanism.ClientMechanism` instances.

    """

    prepare: Preparation = default_prep
    """The preparation algorithm function."""


@dataclass(frozen=True, init=False, repr=False)
class _DefaultConfig(SASLConfig):

    def __init__(self) -> None:
        super().__init__()

    def __repr__(self) -> str:
        return 'SASLConfig()'


#: A configuration instance with all defaults.
default_config: Final = _DefaultConfig()
