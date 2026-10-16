"""Closed machine-readable coverage-fragment schema and validator (Issue 165).

A coverage fragment is the unit of bookkeeping between slices 166-169 and the
later promotion gate (170): it claims, per registry item identifier, whether an
item is covered, uncovered with a closed rationale, or fenced behind an explicit
external boundary. One fragment seed corresponds to one case bundle: a closed
vocabulary digest, a registry digest, and the case ids that bundle owns.

The validator is closed and fails closed. Every rejection is one stable
non-reflecting reason code; no raw caller input is ever echoed into a message.
Duplicate, missing, malformed, stale-reference, unexplained-uncovered, and
unknown-field violations each map to exactly one closed reason. A boundary
entry carries exactly one lc-boundary identifier and zero model cases, so an
external boundary can never masquerade as modeled coverage.
"""

from __future__ import annotations

from lifecycle_conformance import values
from lifecycle_conformance import registries

FRAGMENT_SCHEMA = "orch-dork/lifecycle-coverage-fragment/v1"

FRAGMENT_TOP_LEVEL = ("schema", "fragment_id", "digests", "entries")
DIGESTS_FIELDS = ("vocab", "registry")
ENTRY_FIELDS = ("id", "status", "cases", "rationale")
CASE_FIELDS = ("id", "strength")

STATUS_COVERED = "covered"
STATUS_UNCOVERED = "uncovered"
STATUS_EXTERNAL_BOUNDARY = "external_boundary"
ENTRY_STATUSES = (STATUS_COVERED, STATUS_UNCOVERED, STATUS_EXTERNAL_BOUNDARY)

CASE_STRENGTH_DIRECT = "direct"
CASE_STRENGTH_EVIDENCE = "evidence"
CASE_STRENGTHS = (CASE_STRENGTH_DIRECT, CASE_STRENGTH_EVIDENCE)

_HEX64 = "0123456789abcdef"

# Closed rejection reasons: one per required refuse class (SPEC section 12:
# duplicate, missing, malformed, stale-reference, unexplained uncovered,
# unknown field) plus the schema-mismatch case. Messages carry only the owner
# case key, never raw input.
REASON_SCHEMA_MISMATCH = "LIFECYCLE_FRAGMENT_SCHEMA_MISMATCH"
REASON_MALFORMED = "LIFECYCLE_FRAGMENT_MALFORMED"
REASON_DUPLICATE_ID = "LIFECYCLE_FRAGMENT_DUPLICATE_ID"
REASON_MISSING_FIELD = "LIFECYCLE_FRAGMENT_MISSING_FIELD"
REASON_STALE_REFERENCE = "LIFECYCLE_FRAGMENT_STALE_REFERENCE"
REASON_UNEXPLAINED_GAP = "LIFECYCLE_FRAGMENT_UNEXPLAINED_GAP"
REASON_UNKNOWN_FIELD = "LIFECYCLE_FRAGMENT_UNKNOWN_FIELD"

REASONS = (
    REASON_SCHEMA_MISMATCH,
    REASON_MALFORMED,
    REASON_DUPLICATE_ID,
    REASON_MISSING_FIELD,
    REASON_STALE_REFERENCE,
    REASON_UNEXPLAINED_GAP,
    REASON_UNKNOWN_FIELD,
)


class FragmentError(ValueError):
    """One closed, fail-closed coverage-fragment rejection.

    reason is a closed LIFECYCLE_FRAGMENT_* token. The rendered message is the
    reason token plus, at most, the owner case key; detail is retained on the
    instance for diagnosis and is never reflected into the message.
    """

    def __init__(
        self,
        reason: str,
        *,
        owner: str | None = None,
        detail: object = None,
    ) -> None:
        if reason not in REASONS:
            raise ValueError("fragment rejection reasons are closed")
        self.reason = reason
        self.owner = owner
        self.detail = detail
        super().__init__(self._message())

    def _message(self) -> str:
        if self.owner:
            return self.reason + "[lc=" + self.owner + "]"
        return self.reason


def _reject(reason: str, *, owner: str | None = None, detail: object = None) -> None:
    raise FragmentError(reason, owner=owner, detail=detail)


def _is_hex64(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(c in _HEX64 for c in value)


def fragment_seed(case_id: str, vocab_digest: str, registry_digest: str) -> str:
    """Content-derived identity for one fragment seed.

    The seed binds the case key to the exact closed vocabulary digest and the
    exact registry content digest, so a fragment cannot drift from the
    vocabularies or registries it claims to cover.
    """
    if not isinstance(case_id, str) or not case_id or not values._CASE_ID.match(case_id):
        _reject(REASON_MALFORMED, detail="fragment seed case id")
    if not _is_hex64(vocab_digest) or not _is_hex64(registry_digest):
        _reject(REASON_MALFORMED, detail="fragment seed digest")
    return values.canonical_digest(
        {
            "schema": FRAGMENT_SCHEMA,
            "case_id": case_id,
            "vocab": vocab_digest,
            "registry": registry_digest,
        }
    )


def build_fragment(
    case_id: str,
    vocab_digest: str,
    registry_digest: str,
    entries: list[dict],
) -> dict:
    """Assemble one unvalidated candidate fragment for validate_fragment.

    The builder is a mechanical convenience; it performs no semantics beyond
    seed composition, and its output still must pass the closed validator.
    """
    return {
        "schema": FRAGMENT_SCHEMA,
        "fragment_id": fragment_seed(case_id, vocab_digest, registry_digest),
        "digests": {
            "vocab": vocab_digest,
            "registry": registry_digest,
        },
        "entries": entries,
    }


def _check_required(mapping: dict, required: tuple, *, owner: str | None) -> None:
    for field in required:
        if field not in mapping:
            _reject(REASON_MISSING_FIELD, owner=owner, detail=field)


def _check_unknown(mapping: dict, allowed: tuple, *, owner: str | None) -> None:
    for key in mapping:
        if key not in allowed:
            _reject(REASON_UNKNOWN_FIELD, owner=owner, detail=key)


def _check_entry_shape(entry: object, *, owner: str) -> None:
    if not isinstance(entry, dict) or isinstance(entry, bool):
        _reject(REASON_MALFORMED, owner=owner, detail="entry")
    _check_required(entry, ENTRY_FIELDS, owner=owner)
    _check_unknown(entry, ENTRY_FIELDS, owner=owner)
    if not isinstance(entry["id"], list):
        _reject(REASON_MALFORMED, owner=owner, detail="entry.id")
    if not isinstance(entry["status"], str):
        _reject(REASON_MALFORMED, owner=owner, detail="entry.status")
    if entry["status"] not in ENTRY_STATUSES:
        _reject(REASON_MALFORMED, owner=owner, detail="entry.status")
    if not isinstance(entry["cases"], list):
        _reject(REASON_MALFORMED, owner=owner, detail="entry.cases")
    if not isinstance(entry["rationale"], str):
        _reject(REASON_MALFORMED, owner=owner, detail="entry.rationale")


def _check_case(case: object, *, owner: str) -> tuple[str, str]:
    if not isinstance(case, dict) or isinstance(case, bool):
        _reject(REASON_MALFORMED, owner=owner, detail="case")
    _check_required(case, CASE_FIELDS, owner=owner)
    _check_unknown(case, CASE_FIELDS, owner=owner)
    case_id = case["id"]
    strength = case["strength"]
    if not isinstance(case_id, str) or not case_id or not values._CASE_ID.match(case_id):
        _reject(REASON_MALFORMED, owner=owner, detail="case.id")
    if not isinstance(strength, str) or strength not in CASE_STRENGTHS:
        _reject(REASON_MALFORMED, owner=owner, detail="case.strength")
    return case_id, strength


def _entry_ids(entry: dict, *, owner: str) -> list[str]:
    ids = entry["id"]
    for item_id in ids:
        if not isinstance(item_id, str) or not values.is_item_id(item_id):
            _reject(REASON_MALFORMED, owner=owner, detail="entry.id")
    return list(ids)


def _check_entries(fragment: dict, *, owner: str, store: registries.RegistryStore | None) -> None:
    entries = fragment["entries"]
    if not isinstance(entries, list):
        _reject(REASON_MALFORMED, owner=owner, detail="entries")
    seen_ids: set[str] = set()
    for entry in entries:
        _check_entry_shape(entry, owner=owner)
        ids = _entry_ids(entry, owner=owner)
        if not ids and entry["status"] != STATUS_EXTERNAL_BOUNDARY:
            _reject(REASON_MALFORMED, owner=owner, detail="entry.id")
        if entry["status"] == STATUS_EXTERNAL_BOUNDARY:
            if len(ids) != 1:
                _reject(REASON_MALFORMED, owner=owner, detail="boundary id")
            if ids[0].split(":", 1)[0] != "lc-boundary":
                _reject(REASON_SCHEMA_MISMATCH, owner=owner, detail="boundary kind")
            if entry["cases"]:
                _reject(REASON_MALFORMED, owner=owner, detail="boundary cases")
            if entry["rationale"]:
                _reject(REASON_MALFORMED, owner=owner, detail="boundary rationale")
        elif entry["status"] == STATUS_COVERED:
            if entry["rationale"]:
                _reject(REASON_MALFORMED, owner=owner, detail="covered rationale")
        else:
            if not entry["rationale"].strip():
                _reject(REASON_UNEXPLAINED_GAP, owner=owner, detail="uncovered rationale")
        own_seen: set[str] = set()
        for item_id in ids:
            if item_id in own_seen or item_id in seen_ids:
                _reject(REASON_DUPLICATE_ID, owner=owner, detail="id")
            own_seen.add(item_id)
            if store is not None:
                kind = item_id.split(":", 1)[0]
                try:
                    store.get(kind, item_id)
                except values.LifecycleContractError:
                    _reject(
                        REASON_STALE_REFERENCE, owner=owner, detail="bound store"
                    )
        seen_ids.update(own_seen)
        case_ids: set[str] = set()
        seen_pairs: set[tuple[str, str]] = set()
        for case in entry["cases"]:
            case_id, strength = _check_case(case, owner=owner)
            if case_id in case_ids or (case_id, strength) in seen_pairs:
                _reject(REASON_DUPLICATE_ID, owner=owner, detail="case")
            case_ids.add(case_id)
            seen_pairs.add((case_id, strength))


def _check_digests(fragment: dict, *, owner: str) -> dict:
    digests = fragment["digests"]
    if not isinstance(digests, dict) or isinstance(digests, bool):
        _reject(REASON_MALFORMED, owner=owner, detail="digests")
    _check_required(digests, DIGESTS_FIELDS, owner=owner)
    _check_unknown(digests, DIGESTS_FIELDS, owner=owner)
    for field in DIGESTS_FIELDS:
        if not _is_hex64(digests[field]):
            _reject(REASON_MALFORMED, owner=owner, detail="digests." + field)
    return digests


def validate_fragment(fragment: object, *, owner: str, store: registries.RegistryStore | None = None) -> dict:
    """Validate one closed coverage fragment; return a sealed stats report.

    owner is the case key the seed names; the fragment seed is recomputed
    from (schema, case, vocab, registry) and must match fragment_id. When a
    bound store is supplied, every referenced item identifier must exist and
    the registry digest must equal the store digest. Raises FragmentError
    with one closed reason on the first violation; messages never reflect
    caller input.
    """
    if not isinstance(owner, str) or not owner or not values._CASE_ID.match(owner):
        _reject(REASON_MALFORMED, detail="owner")
    if not isinstance(fragment, dict) or isinstance(fragment, bool):
        _reject(REASON_MALFORMED, owner=owner, detail="fragment")
    _check_required(fragment, FRAGMENT_TOP_LEVEL, owner=owner)
    _check_unknown(fragment, FRAGMENT_TOP_LEVEL, owner=owner)
    if fragment["schema"] != FRAGMENT_SCHEMA:
        _reject(REASON_SCHEMA_MISMATCH, owner=owner, detail="schema")
    digests = _check_digests(fragment, owner=owner)
    if not isinstance(fragment["fragment_id"], str) or not _is_hex64(fragment["fragment_id"]):
        _reject(REASON_MALFORMED, owner=owner, detail="fragment_id")
    if fragment["fragment_id"] != fragment_seed(owner, digests["vocab"], digests["registry"]):
        _reject(REASON_STALE_REFERENCE, owner=owner, detail="fragment_id")
    if store is not None:
        if not isinstance(store, registries.RegistryStore):
            _reject(REASON_MALFORMED, owner=owner, detail="bound store")
        if digests["registry"] != store.digest():
            _reject(REASON_STALE_REFERENCE, owner=owner, detail="registry digest")
    _check_entries(fragment, owner=owner, store=store)
    return {
        "schema": FRAGMENT_SCHEMA,
        "owner": owner,
        "fragment_id": fragment["fragment_id"],
        "entry_count": len(fragment["entries"]),
        "digest": values.canonical_digest(
            {
                "digests": digests,
                "entries": fragment["entries"],
            }
        ),
    }
