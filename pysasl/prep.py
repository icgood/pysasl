
from abc import abstractmethod
from typing_extensions import Protocol

try:
    from passlib.utils import saslprep as _saslprep
except ImportError as exc:  # pragma: no cover
    _saslprep = None
    _saslprep_exc = exc

__all__ = ['Preparation', 'prepare', 'default_prep', 'noprep', 'saslprep']


class Preparation(Protocol):
    """A callable object that prepares a string value to improve the likelihood
    that comparisons behave in an expected manner.

    See Also:
        `RFC 4422 5.
        <https://datatracker.ietf.org/doc/html/rfc4422#section-5>`_

    """

    @abstractmethod
    def __call__(self, source: str) -> str:
        ...


def prepare(source: str) -> str:
    """Prepares the *source* string using the preparation algorithm referenced
    by :data:`default_prep`.

    Args:
        source: The string to prepare.

    """
    return default_prep(source)


#: The default preparation algorithm, used by :func:`prepare`. The
#: :func:`saslprep` function is used if it is available, otherwise
#: :func:`noprep` is used.
default_prep: Preparation


def noprep(source: str) -> str:  # pragma: no cover
    """A :class:`Preparation` implementation that returns the source value
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
    default_prep = saslprep
else:  # pragma: no cover
    default_prep = noprep
