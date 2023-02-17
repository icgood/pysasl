
from typing import Any, Iterable, NamedTuple


class Distribution(NamedTuple):
    version: str


def distribution(name: str) -> Distribution:
    ...


class EntryPoint:
    name: str

    def load(self) -> Any:
        ...


def entry_points(*, group: str) -> Iterable[EntryPoint]:
    ...
