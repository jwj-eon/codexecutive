"""Stable nine-kind registries for the shared lifecycle contract (Issue 165).

Every modeled item -- state, transition, invariant, persistent mutation
site, external-action site, constructor/validator pair, host fixture,
historical replay, and explicit external boundary -- is registered under
a closed-grammar identity. The registry is the object the coverage
fragment validator and the campaign derive counts, reachability, and
evidence from; a new item without a registration fails coverage.
"""

from __future__ import annotations

from dataclasses import dataclass

from lifecycle_conformance import values

REGISTRY_KINDS = values.REGISTRY_ITEMS

# The closed kind under which transition records are registered. The pure
# transition interface looks them up here; traces are generated from this
# registry view, not a private helper.
TRANSITIONS_KIND = "lc-trans"


class RegistryStore:
    """In-memory stable registry over the nine closed item kinds.

    The store is plain provider-free data. Adds are validated fail-closed,
    the store is never read by a production component, and the store's own
    content digest is what a coverage fragment references.
    """

    def __init__(self) -> None:
        self._items: dict[str, dict[str, dict]] = {kind: {} for kind in REGISTRY_KINDS}
        self._owners: dict[str, dict[str, str]] = {kind: {} for kind in REGISTRY_KINDS}

    def add(self, kind: str, item_id: str, owner: str, record: dict) -> None:
        """Register one item under its closed kind and grammar-stable id."""
        if kind not in self._items:
            raise values.LifecycleContractError("registry:unknown_kind")
        if not values.is_item_id(item_id):
            raise values.LifecycleContractError("registry:invalid_item", lc=item_id)
        head = item_id.split(":", 1)[0]
        if head != kind:
            raise values.LifecycleContractError("registry:kind_mismatch")
        self._validate_owner(kind, owner)
        self._validate_record(kind, record)
        if item_id in self._items[kind]:
            raise values.LifecycleContractError(
                "registry:duplicate", lc=item_id, product=kind
            )
        self._items[kind][item_id] = dict(record)
        self._owners[kind][item_id] = owner

    def get(self, kind: str, item_id: str) -> dict:
        """Fetch one registered record; stale or unknown ids fail closed."""
        if kind not in self._items:
            raise values.LifecycleContractError("registry:unknown_kind")
        if item_id not in self._items[kind]:
            raise values.LifecycleContractError("registry:stale_reference")
        return dict(self._items[kind][item_id])

    def owner_of(self, kind: str, item_id: str) -> str:
        if kind not in self._owners or item_id not in self._owners[kind]:
            raise values.LifecycleContractError("registry:stale_reference")
        return self._owners[kind][item_id]

    def items_of(self, kind: str) -> dict[str, dict]:
        """All records of one kind, in deterministic (insertion-free) order."""
        if kind not in self._items:
            raise values.LifecycleContractError("registry:unknown_kind")
        return {
            item_id: dict(self._items[kind][item_id])
            for item_id in sorted(self._items[kind])
        }

    def kinds(self) -> tuple[str, ...]:
        return tuple(REGISTRY_KINDS)

    def digest(self) -> str:
        """Content digest of every registered record, by kind."""
        payload = {
            kind: self.items_of(kind) for kind in self.kinds() if self.items_of(kind)
        }
        return values.canonical_digest(payload)

    @staticmethod
    def _validate_owner(kind: str, owner: str) -> None:
        if not isinstance(owner, str) or not values._TOKEN.match(owner):
            raise values.LifecycleContractError("registry:invalid_owner")

    @staticmethod
    def _validate_record(kind: str, record: dict) -> None:
        if not isinstance(record, dict):
            raise values.LifecycleContractError("registry:invalid_record")
        try:
            values.canonical_json(record)
        except values.LifecycleContractError:
            raise values.LifecycleContractError("registry:invalid_record") from None
        if kind == "lc-trans":
            required = ("from", "to", "trigger")
            for field in required:
                if not isinstance(record.get(field), str) or not record.get(field):
                    raise values.LifecycleContractError("registry:invalid_record")
            if record["from"] not in values.LIFECYCLE_PHASES:
                raise values.LifecycleContractError("registry:invalid_record")
            if record["to"] not in values.LIFECYCLE_PHASES:
                raise values.LifecycleContractError("registry:invalid_record")
        elif kind == "lc-state":
            if not isinstance(record.get("phase"), str):
                raise values.LifecycleContractError("registry:invalid_record")
            if record["phase"] not in values.LIFECYCLE_PHASES:
                raise values.LifecycleContractError("registry:invalid_record")
        elif kind == "lc-inv":
            required = ("kind", "class")
            for field in required:
                if not isinstance(record.get(field), str) or not record.get(field):
                    raise values.LifecycleContractError("registry:invalid_record")
            if record["kind"] not in values.INVARIANT_KINDS:
                raise values.LifecycleContractError("registry:invalid_record")
            if record["class"] not in values.INVARIANT_CLASSES:
                raise values.LifecycleContractError("registry:invalid_record")
        elif kind == "lc-mut":
            _require_closed_class(record, values.MUTATION_SITE_CLASSES)
        elif kind == "lc-act":
            _require_closed_class(record, values.EXTERNAL_ACTION_SITE_CLASSES)
        elif kind == "lc-boundary":
            _require_boundary_record(record)


@dataclass(frozen=True)
class RegistryReport:
    """Sealed read of one store: kind counts plus the store content digest."""

    counts: dict
    digest: str


def seal_report(store: RegistryStore) -> RegistryReport:
    """Seal a store into its count-and-digest report for downstream binding."""
    counts = {kind: len(store.items_of(kind)) for kind in store.kinds()}
    return RegistryReport(counts=counts, digest=store.digest())


def validate_item(kind: str, item_id: str) -> None:
    """Validate one registry item identity against the closed grammar."""
    if kind not in REGISTRY_KINDS:
        raise values.LifecycleContractError("registry:unknown_kind")
    if not values.is_item_id(item_id):
        raise values.LifecycleContractError("registry:invalid_item", lc=item_id)
    if item_id.split(":", 1)[0] != kind:
        raise values.LifecycleContractError("registry:kind_mismatch")
def _require_closed_class(record: dict, vocabulary: tuple) -> None:
    """A site must name exactly one closed class."""
    if isinstance(record.get("class"), str) and record["class"] in vocabulary:
        return
    raise values.LifecycleContractError("registry:invalid_record")


_BOUNDARY_FIELDS = (
    "topic",
    "observation_class",
    "rationale",
    "owner",
    "evidence_expectation",
)


def _require_boundary_record(record: dict) -> None:
    """An explicit external boundary is a closed five-field record.

    It carries a typed observation class, rationale, owner, and a later
    evidence expectation. A malformed boundary fails at registration, and
    a boundary record can never satisfy a modeled registry kind.
    """
    if set(record) != set(_BOUNDARY_FIELDS):
        raise values.LifecycleContractError("registry:invalid_record")
    for field in _BOUNDARY_FIELDS:
        value = record[field]
        if not isinstance(value, str) or not value:
            raise values.LifecycleContractError("registry:invalid_record")
    if record["topic"] not in values.EXTERNAL_BOUNDARY_TOPICS:
        raise values.LifecycleContractError("registry:invalid_record")
    if record["observation_class"] not in values.OBSERVATION_CLASSES:
        raise values.LifecycleContractError("registry:invalid_record")
