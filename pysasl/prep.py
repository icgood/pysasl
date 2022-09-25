
import warnings
from abc import abstractmethod
from typing_extensions import Final, Protocol

try:
    from passlib.utils import saslprep as _saslprep
except ImportError as exc:  # pragma: no cover
    _saslprep = None
    _saslprep_exc = exc
    warnings.warn('passlib.utils.saslprep is not available', ImportWarning)

__all__ = ['Preparation', 'default_prep', 'noprep', 'saslprep']


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

#: Prepares the *source* string using the default preparation algorithm. This
#: default is :func:`saslprep` if available otherwise :func:`noprep`.
default_prep: Final = _default_prep
