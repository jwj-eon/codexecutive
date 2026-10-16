"""Stable identities and the closed vocabulary of the shared lifecycle
provider-free contract (Issue 165).

This module is the single owner of the closed names that SPEC section 12
requires foundation slices to share: controller/action/grant channels, the
two lanes, acknowledgement, continuation, result, aggregation, Sol review,
terminal verification, cleanup/process, capacity, and owner state. It
computes canonical digests over provider-free data with a bounded
canonical-JSON encoder so every identity is reproducible from content alone.

The contract is provider-free in both directions. A rejection reason is a
closed reason code plus at most grammar-stable identifier fields; no raw
caller input is ever reflected into a message.
"""

from __future__ import annotations

import hashlib
import json
import math
import re

CONTRACT_SCHEMA = "orch-dork/lifecycle-conformance-contract/v1"

REGISTRY_ITEMS = (
    "lc-state",
    "lc-trans",
    "lc-inv",
    "lc-mut",
    "lc-act",
    "lc-pair",
    "lc-fix",
    "lc-replay",
    "lc-boundary",
)

# Stable vocabulary namespaces. Every public registry item name must
# belong to exactly one of these closed namespaces.
LANES = ("spec", "standards")

# Modeled products the vocabulary must be able to name (SPEC 12):
# controller/action/grant channel, lane workers, process/cleanup, and the
# shared capacity/owner surface.
PRODUCTS = ("spec", "standards", "controller", "process", "shared")

DIRECTIVE_KINDS = (
    "action",
    "wait_for_observation",
    "terminal_closure",
    "external_authority_required",
)

OBSERVATION_CLASSES = (
    "accepted",
    "refused",
    "failed",
    "unknown",
    "interrupted_before",
    "interrupted_after",
    "partial",
    "malformed",
    "missing",
    "not_dispatched",
    "stale",
    "mismatched",
    "duplicated",
    "cleanup_unavailable",
)

# The closed lifecycle phase vocabulary. Naming a phase here does not make
# the foundation implement the corresponding transition; the transition
# registry records what is registered and what is unreachable, with
# rationale.
LIFECYCLE_PHASES = (
    "pre_turn",
    "host_readiness",
    "activation",
    "spawn_grant",
    "spawn",
    "acknowledgement",
    "continuation",
    "typed_result",
    "worker_progress",
    "aggregation",
    "sol_review",
    "terminal_verification",
    "cleanup",
    "capacity_settlement",
    "final_qualification",
    "failure_closure",
    "owner_rotation",
    "terminal",
)

GRANT_STATES = (
    "none",
    "requested",
    "authorized",
    "dispatched",
    "settled",
    "released",
    "stale",
    "refused",
)

CONTINUATION_OUTCOMES = (
    "success",
    "failure",
    "unknown",
    "not_dispatched",
    "malformed_result",
    "refused",
)

MUTATION_SITE_CLASSES = (
    "controller_event_commit",
    "terminal_commit",
    "grant_transition",
    "hook_durability_record",
    "capacity_reserve_release",
    "artifact_receipt_creation",
    "cleanup_evidence",
    "owner_rotation",
)

EXTERNAL_ACTION_SITE_CLASSES = (
    "host_task_start",
    "spawn",
    "acknowledgement_observation",
    "continuation",
    "typed_result_observation",
    "sol_review",
    "terminal_observation",
    "worker_closure",
    "process_interruption",
    "cleanup",
)

FAILURE_CLASSES = (
    "hook_missing",
    "hook_refused",
    "process_interruption",
    "partial_spawn",
    "acknowledgement_missing",
    "continuation_success",
    "continuation_failed",
    "continuation_unknown",
    "continuation_not_dispatched",
    "typed_result_invalid",
    "grant_stale",
    "capacity_stale",
    "owner_mismatch",
    "sol_review_failed",
    "terminal_verification_failed",
    "cleanup_failed",
)

INVARIANT_CLASSES = (
    "single_legal_successor",
    "exact_next_directive",
    "no_stranded_resource",
    "replay_determinism",
    "protocol_custody",
    "exactly_once",
)

INVARIANT_KINDS = ("trace", "state", "closure")

# Explicit external boundaries: behavior outside the finite model. Every
# boundary record names exactly one of these closed topics, so a boundary
# cannot mask an omitted modeled transition or fixture.
EXTERNAL_BOUNDARY_TOPICS = (
    "model_semantic_quality",
    "provider_availability",
    "network_timing",
    "kernel_scheduling",
    "future_host_version",
)

# Guarded rejection reasons shared across the foundation. Messages carry
# only the closed reason code; no raw input is reflected.
GUARDED_REASONS = (
    "LIFECYCLE_CONTRACT_MISMATCH",
    "LIFECYCLE_SCHEMA_UNKNOWN",
    "LIFECYCLE_NO_REGISTRY",
    "LIFECYCLE_EXTERNAL_BOUNDARY",
    "LIFECYCLE_INVALID_ITEM",
    "LIFECYCLE_UNEXPLAINED_GAP",
    "LIFECYCLE_MUTATION_REQUIRED",
    "LIFECYCLE_STALE_REFERENCE",
    "LIFECYCLE_DUPLICATE_ITEM",
    "LIFECYCLE_MISSING_ITEM",
    "LIFECYCLE_PROVIDER_REFUSED",
    "LIFECYCLE_HOST_UNKNOWN",
)

_ITEM_ID = re.compile(r"^(lc-[a-z]+):[a-z0-9][a-z0-9._-]*:[A-Za-z0-9._-]+$")

_CASE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")

_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,95}$")

_CANONICAL_DEPTH_LIMIT = 200


def _is_finite(value: float) -> bool:
    """True when a float has a finite canonical JSON rendering."""
    return math.isfinite(value)


class LifecycleContractError(ValueError):
    """Fail-closed rejection with a stable, non-reflecting reason code.

    reason must be a closed token (module prefix plus reason). lc and
    product may each carry at most one grammar-stable identifier field;
    free-form caller input is never echoed into the message. The detail
    argument is retained on the instance and is never reflected into the
    rendered message.
    """

    def __init__(
        self,
        reason: str,
        *,
        lc: str | None = None,
        product: str | None = None,
        detail: object = None,
    ) -> None:
        super().__init__(self._message(reason, lc, product))
        self.reason = reason
        self.lc = lc
        self.product = product
        self.detail = detail

    @staticmethod
    def _message(reason: str, lc: str | None, product: str | None) -> str:
        fields = []
        if lc:
            fields.append("lc=" + lc)
        if product:
            fields.append("product=" + product)
        if not fields:
            return reason
        return reason + "[" + ", ".join(fields) + "]"

    @property
    def code(self) -> str:
        """The plain reason token, independent of any stable fields."""
        return self.reason


def canonical_json(obj: object) -> str:
    """Render provider-free data as one canonical JSON string.

    The encoder is bounded and deterministic: keys are sorted, separators
    are minimal, non-ASCII is escaped, and NaN/infinite values, nesting
    beyond a fixed depth, or any other JSON type are refused fail-closed
    with the closed reason values:canonical_rejected.
    """
    return _canonical_json(obj, 0)


def _canonical_json(obj: object, depth: int) -> str:
    if depth > _CANONICAL_DEPTH_LIMIT:
        raise LifecycleContractError("values:canonical_rejected")
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda pair: str(pair[0]))
        parts = []
        for key, value in items:
            if not isinstance(key, str):
                raise LifecycleContractError("values:canonical_rejected")
            parts.append(
                json.dumps(key, ensure_ascii=True) + ":" + _canonical_json(value, depth + 1)
            )
        return "{" + ",".join(parts) + "}"
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_canonical_json(item, depth + 1) for item in obj) + "]"
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=True)
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if obj is None:
        return "null"
    if isinstance(obj, (int, float)):
        if isinstance(obj, float) and not _is_finite(obj):
            raise LifecycleContractError("values:canonical_rejected")
        return json.dumps(obj, ensure_ascii=True)
    raise LifecycleContractError("values:canonical_rejected")


def canonical_digest(obj: object) -> str:
    """SHA-256 over the canonical JSON rendering of obj."""
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def item_kind(prefix: str) -> str | None:
    """Map a stable identifier prefix to a closed registry-item namespace."""
    if prefix in REGISTRY_ITEMS:
        return prefix
    return None


def is_item_id(candidate: object) -> bool:
    """True when candidate is a closed-grammar registry item identifier."""
    if not isinstance(candidate, str):
        return False
    if item_kind(candidate.split(":", 1)[0]) is None:
        return False
    return _ITEM_ID.match(candidate) is not None


def lane_of(product_phrase: object) -> str:
    """Resolve the owning lane or the shared product for a stable phrase.

    The closed vocabulary must be able to name controller/action/grant
    channels, both lanes, and the shared process/capacity/owner surface,
    without implementing any of the corresponding transitions. The dot is
    the lane separator in registry item phrases.
    """
    if not isinstance(product_phrase, str) or ":" not in product_phrase:
        raise LifecycleContractError("values:grammar_rejected")
    head = product_phrase.split(":", 1)[0]
    if head in LANES:
        return head
    if head in set(PRODUCTS) - set(LANES):
        return "shared"
    raise LifecycleContractError("values:grammar_rejected")


def vocabulary_digest() -> str:
    """Content digest of every closed vocabulary in this module."""
    return canonical_digest(
        {
            "schema": CONTRACT_SCHEMA,
            "lanes": list(LANES),
            "products": list(PRODUCTS),
            "directives": list(DIRECTIVE_KINDS),
            "observations": list(OBSERVATION_CLASSES),
            "phases": list(LIFECYCLE_PHASES),
            "grants": list(GRANT_STATES),
            "continuations": list(CONTINUATION_OUTCOMES),
            "mutation_sites": list(MUTATION_SITE_CLASSES),
            "action_sites": list(EXTERNAL_ACTION_SITE_CLASSES),
            "failures": list(FAILURE_CLASSES),
            "invariants": list(INVARIANT_CLASSES),
            "invariant_kinds": list(INVARIANT_KINDS),
            "boundaries": list(EXTERNAL_BOUNDARY_TOPICS),
            "registry_items": list(REGISTRY_ITEMS),
        }
    )
