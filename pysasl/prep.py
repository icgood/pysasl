
from stringprep import (
    in_table_a1,
    in_table_b1,
    in_table_c12,
    in_table_c21_c22,
    in_table_c3,
    in_table_c4,
    in_table_c5,
    in_table_c6,
    in_table_c7,
    in_table_c8,
    in_table_c9,
    in_table_d1,
    in_table_d2,
)
from typing import Callable
from typing_extensions import TypeAlias
from unicodedata import normalize

__all__ = ['Preparation', 'noprep', 'saslprep']

#: Any callable that prepares a string value to improve the likelihood that
#: comparisons behave in an expected manner.
#:
#: See Also:
#:    `RFC 4422 5. <https://datatracker.ietf.org/doc/html/rfc4422#section-5>`_
Preparation: TypeAlias = Callable[[str], str]


def _always_false(code: str) -> bool:
    return False


def noprep(source: str) -> str:
    """Returns *source* unmodified."""
    return source


def saslprep(source: str, *, allow_unassigned: bool = False) -> str:
    """The SASLprep algorithm defined by `RFC 4013
    <https://datatracker.ietf.org/doc/html/rfc4013>`_.

    Args:
        source: The string to prepare.
        allow_unassigned: Allow unassigned code points in the result string,
            Per `RFC 3454 7.
            <https://datatracker.ietf.org/doc/html/rfc3454#section-7>`_, this
            should only be used "queries" and never stored strings.

    """
    mapped = ''.join(
        ' ' if in_table_c12(code) else code
        for code in source
        if not in_table_b1(code)
    )
    normalized = normalize('NFKC', mapped)
    check_unassigned = _always_false if allow_unassigned else in_table_a1
    any_d1 = False
    any_d2 = False
    for code in normalized:
        if check_unassigned(code) \
                or in_table_c21_c22(code) \
                or in_table_c3(code) \
                or in_table_c4(code) \
                or in_table_c5(code) \
                or in_table_c6(code) \
                or in_table_c7(code) \
                or in_table_c8(code) \
                or in_table_c9(code):
            raise ValueError(source)
        elif in_table_d1(code):
            any_d1 = True
        elif in_table_d2(code):
            any_d2 = True
    if any_d1:
        if any_d2:
            raise ValueError(source)
        elif not in_table_d1(source[0]) \
                or not in_table_d1(source[-1]):
            raise ValueError(source)
    return normalized
