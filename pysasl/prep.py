
from abc import abstractmethod
from typing_extensions import Protocol

try:
    from passlib.utils import saslprep as _saslprep
except ImportError as exc:  # pragma: no cover
    _saslprep = None
    _saslprep_exc = exc

__all__ = ['Preparation', 'prepare', 'set_default_prep', 'noprep', 'saslprep']

_default_prep: 'Preparation'


class Preparation(Protocol):
    """Any callable that prepares a string value to improve the likelihood that
    comparisons behave in an expected manner.

    See Also:
        `RFC 4422 5.
        <https://datatracker.ietf.org/doc/html/rfc4422#section-5>`_

    """

    @abstractmethod
    def __call__(self, source: str) -> str:
        ...


def prepare(source: str) -> str:
    """Prepares the *source* string using the default preparation algorithm.
    Unless changed by :func:`set_default_prep`, this default is
    :func:`saslprep` if available otherwise :func:`noprep`.

    Args:
        source: The string to prepare.

    """
    return _default_prep(source)


def set_default_prep(prep: Preparation) -> None:  # pragma: no cover
    """Modifies the global default preparation algorithm used by
    :func:`prepare`.

    Args:
        prep: The new preparation algorithm function.

    """
    global _default_prep
    _default_prep = prep


def noprep(source: str) -> str:  # pragma: no cover
    """A :class:`Preparation` implementation that returns the *source* value
    unchanged.

    Args:
        source: The string to prepare.

    """
    return source


def saslprep(source: str) -> str:
    """The SASLprep algorithm defined by `RFC 4013
    <https://datatracker.ietf.org/doc/html/rfc4013>`_, implemented by
    :func:`passlib.utils.saslprep`.

    Args:
        source: The string to prepare.

    Raises:
        ImportError: The implementation is not available.

    """
    if _saslprep is not None:
        ret: str = _saslprep(source)
        return ret
    else:  # pragma: no cover
        raise _saslprep_exc


if _saslprep is not None:
    _default_prep = saslprep
else:  # pragma: no cover
    _default_prep = noprep
