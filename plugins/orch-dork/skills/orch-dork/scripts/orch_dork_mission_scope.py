"""Canonical write-scope helpers (Issue 226 v2 batch-claim admission).

These helpers are intentionally tiny and free of heavy authority or
dev-only imports so the new v2 MissionAuthority admission and Root's
separate CandidateStager work share one definition of:

  * what counts as canonical write-scope fragments,
  * when two scopes cover any common path, and
  * when a specific path lies inside a given scope.

They raise :class:`ScopeRefusal` (a ``ValueError`` subclass) for
malformed input and never invent empty scopes; ``normalize_scope``
either returns a non-empty tuple or raises.

The legacy whole-repository convention is retained as the sole-element
tuple ``(".",)``; the pre-Issue226 CandidateStager scope must remain
accepted here without widening the canonical-fragment rules.

The public functions strictly validate both scope sets and paths through
the same canonical-fragment rules. Empty, unknown or malformed scope
sets refuse; invalid paths (alias components, absolute spelling,
backslash or control characters) refuse even under the legacy ``.``
whole-repository scope. The internal helper ``_validate_fragment`` is
the single shared validator; ``normalize_scope`` is the single source
of truth for canonical-scope sets.
"""

from __future__ import annotations


_MAX_SCOPE_ENTRIES = 64


class ScopeRefusal(ValueError):
    """Caller misuse of the scope helpers."""


def _validate_fragment(value, label):
    """Validate a single canonical relative POSIX fragment.

    Used for both individual scope fragments and individual paths.
    The legacy sole ``"."`` fragment is NOT accepted here; callers
    that need the whole-repository sentinel must use ``normalize_scope``.
    """
    if not isinstance(value, str) or not value:
        raise ScopeRefusal(label + " must be a non-empty string")
    if value.startswith("/"):
        raise ScopeRefusal(label + " must not be absolute")
    if "\\" in value:
        raise ScopeRefusal(label + " must not use backslash")
    if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in value):
        raise ScopeRefusal(label + " must not use control characters")
    parts = value.split("/")
    for part in parts:
        if part == "":
            raise ScopeRefusal(label + " must not have empty component")
        if part in (".", ".."):
            raise ScopeRefusal(label + " must not have alias component")
        if part == ".git":
            raise ScopeRefusal(label + " must not traverse .git subtree")


def _validate_scope_set(value, label):
    """Validate a scope iterable through ``normalize_scope`` and return the tuple."""
    if not isinstance(value, (list, tuple)):
        raise ScopeRefusal(label + " must be a list or tuple of strings")
    return normalize_scope(value)


def normalize_scope(value):
    """Return the canonical sorted unique scope tuple for ``value``.

    The input must be a list or tuple of strings. Each fragment must be
    canonical relative POSIX spelling: not absolute, no aliases, no
    backslash or control characters, no ``.git`` subtree, and no
    parent-child redundancy. Duplicates raise :class:`ScopeRefusal`.

    The legacy sole-element tuple ``(".",)`` is accepted as the whole-
    repository sentinel and returned unchanged; the canonical-fragment
    rules above do not apply to that tuple. The result is always sorted
    ascending by fragment and unique.
    """
    if not isinstance(value, (list, tuple)):
        raise ScopeRefusal("scope must be a list or tuple of strings")
    items = tuple(value)
    if not items:
        raise ScopeRefusal("scope must not be empty")
    if len(items) > _MAX_SCOPE_ENTRIES:
        raise ScopeRefusal("scope exceeds 64 fragments")
    if items == (".",):
        return (".",)
    collected = []
    for item in items:
        _validate_fragment(item, "scope fragment")
        collected.append(item)
    if len(set(collected)) != len(collected):
        raise ScopeRefusal("scope has duplicate fragments")
    sorted_frags = sorted(collected)
    for index, parent in enumerate(sorted_frags):
        for inner, child in enumerate(sorted_frags):
            if index != inner and child.startswith(parent + "/"):
                raise ScopeRefusal("scope has redundant parent-child fragment")
    return tuple(sorted_frags)


def scopes_overlap(left, right):
    """Return whether the two scopes cover any common path.

    The legacy whole-repository fragment ``.`` overlaps with any scope.
    Two distinct canonical fragments overlap when they are equal or one
    is a strict path prefix of the other (``a`` covers ``a/b``).
    Both scope arguments are validated through ``normalize_scope``; an
    empty, unknown or otherwise malformed scope set refuses.
    """
    left_set = _validate_scope_set(left, "left scope")
    right_set = _validate_scope_set(right, "right scope")
    if "." in left_set or "." in right_set:
        return True
    for left_fragment in left_set:
        for right_fragment in right_set:
            if left_fragment == right_fragment:
                return True
            if (left_fragment.startswith(right_fragment + "/") or
                    right_fragment.startswith(left_fragment + "/")):
                return True
    return False


def path_in_scope(path, scope):
    """Return whether ``path`` lies inside ``scope``.

    The path is validated as a single canonical relative POSIX
    fragment; alias components, absolute spelling, backslash or
    control characters and the ``.git`` subtree all refuse. The scope
    is validated through ``normalize_scope``; empty, unknown or
    malformed scope sets refuse. Invalid or empty paths refuse even
    under the legacy ``.`` whole-repository scope; legitimate
    canonical paths under ``.`` stay admitted.
    """
    _validate_fragment(path, "path")
    scope_set = _validate_scope_set(scope, "scope")
    if "." in scope_set:
        return True
    for fragment in scope_set:
        if path == fragment:
            return True
        if path.startswith(fragment + "/"):
            return True
    return False


__all__ = ["ScopeRefusal", "normalize_scope", "scopes_overlap", "path_in_scope"]
