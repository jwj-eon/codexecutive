"""Deeply immutable reference values for the shared lifecycle foundation.

This module adds one frozen value type on top of the unchanged values.py
encoder. A FrozenValue stores exactly one canonical JSON text produced by
values.canonical_json; no mutable input or decoded structure is retained,
and every to_plain projection is freshly re-decoded. freeze is the only
public constructor; equality, hashing, and the digest all derive from the
stored canonical text through the unchanged foundation API. Ordinary
attribute assignment and deletion are refused, and public construction,
including a direct FrozenValue.__new__ call, raises.
"""

from __future__ import annotations

import json

from lifecycle_conformance.values import (
    LifecycleContractError,
    canonical_digest,
    canonical_json,
)

_REFUSED = "values:canonical_rejected"


class FrozenValue:
    """One deeply immutable value, addressed by its canonical JSON text."""

    __slots__ = ("_canonical_text",)

    def __new__(cls, *args, **kwargs) -> "FrozenValue":
        raise LifecycleContractError(_REFUSED)

    def __init__(self) -> None:
        raise LifecycleContractError(_REFUSED)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("FrozenValue is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("FrozenValue is immutable")

    def to_plain(self) -> object:
        """Return a newly decoded, independent JSON value."""
        try:
            return json.loads(self._canonical_text)
        except ValueError:
            raise LifecycleContractError(_REFUSED) from None

    def digest(self) -> str:
        """SHA-256 over the plain value via the unchanged foundation API."""
        return canonical_digest(self.to_plain())

    def __eq__(self, other: object) -> bool:
        return (
            type(other) is FrozenValue
            and self._canonical_text == other._canonical_text
        )

    def __hash__(self) -> int:
        return hash((FrozenValue.__name__, self._canonical_text))


def freeze(value: object) -> FrozenValue:
    """Freeze provider-free data into a FrozenValue via canonical_json."""
    frozen = object.__new__(FrozenValue)
    object.__setattr__(frozen, "_canonical_text", canonical_json(value))
    return frozen
