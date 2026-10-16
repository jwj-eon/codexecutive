"""Issue 200 U1: hosted online-diagram format, sanitizer, encoder and decoder.

Bounded, one-way projection from ``orch_dork_local_ui_projection.project_run`` /
``plan_view`` output into the small, closed ``orch-dork/online-diagram/v1``
shape admitted to the hosted privacy class. The shape carries only the facts a
remote viewer needs (state, lanes, roles, states, cost, verdict) and never
private task bodies, host paths, credentials, raw transcripts or dollar
estimates.

The runtime is stdlib-only: validator, encoder and decoder use ``json``,
``base64``, ``hashlib`` and ``re``; no third-party imports occur at module load.
"""

from __future__ import annotations

import base64
import hashlib
from json import JSONDecoder
import json
import math
from pathlib import Path
import re
from typing import Any, Mapping

import orch_dork_live_view as live_view
import orch_dork_governed_run_cost as cost_module

SCHEMA = "orch-dork/online-diagram/v1"
SITE_SCHEMA = "orch-dork/online-history-site/v1"
OFFER_SCHEMA = "orch-dork/online-diagram-offer/v1"
PRIVACY_CLASS = "hosted_standard"
NODE_STATES = live_view.NODE_STATES
EDGE_STATES = live_view.EDGE_STATES
EVIDENCE_CLASSES = live_view.EVIDENCE_CLASSES
ROLES = cost_module.ROLES
TOKEN_FIELDS = cost_module.TOKEN_FIELDS

MAX_DIAGRAM_BYTES = 65536
FITS_LINK_MAX_BYTES = 6000
MAX_LANES = 32
MAX_PER_ROLE = 16
MAX_MODEL_LEN = 96
MAX_INT = 10 ** 12
MIN_REVISION = 1
MAX_REVISION = 1000

_TOP_KEYS = frozenset({
    "schema", "privacy_class", "kind", "source_digest", "state", "verdict",
    "revision", "started_at", "ended_at", "root", "lanes", "cost", "counts"
})
_ROOT_KEYS = frozenset({"state", "evidence_class", "planned_model", "observed_model"})
_LANE_KEYS = frozenset({
    "label", "state", "evidence_class", "planned_model",
    "observed_model", "spawn", "join"
})
_COST_KEYS = frozenset({
    "billing", "actual_cost", "usage_status", "threads_without_usage",
    "per_role", "estimate"
})
_PER_ROLE_KEYS = frozenset({
    "role", "model", "threads", "observed_threads", "lanes", "tokens"
})
_TOKEN_KEYS = frozenset(TOKEN_FIELDS)
_ESTIMATE_KEYS = frozenset({
    "status", "frontier_model", "tokens_on_frontier_model",
    "tokens_moved_off_frontier_model"
})
_COUNTS_KEYS = frozenset({"issues", "unknowns", "contradictions"})
_RUN_STATES = frozenset({
    "STARTING", "RUNNING", "CHECKING", "AWAITING_REVISION",
    "AWAITING_APPROVAL", "TERMINAL", "UNREADABLE", "UNKNOWN"
})
_VERDICTS = frozenset({
    "Verified", "Failed checks", "Interrupted \u2014 not verified",
    "Stopped by you", "Refused"
})
_USAGE_STATUSES = frozenset({"observed", "partial", "unavailable"})
_ESTIMATE_STATUSES = frozenset({"unknown", "observed", "lower_bound"})

_KIND_VALUES = frozenset({"run", "plan"})
_MODEL_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._@+-]*(/[A-Za-z0-9][A-Za-z0-9._@+-]*)?$"
)
_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|\+00:00)$"
)
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]*")
_SITE_ORIGIN_RE = re.compile(r"^https://[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$")


def default_site_origin_path() -> Path:
    return Path(__file__).resolve().parents[1] / "runtime" / "online-history-site.json"


def _missing_code(prefix, key):
    """Return the ``:missing`` refusal code for a schema-declared field.

    Codes follow the structural path; the prefix is the segment and the field
    name is the schema key. Top-level uses ``diagram:<field>:missing``,
    sections use ``<prefix>.<field>:missing`` to keep the path unambiguous.
    """

    if prefix == "diagram":
        return "diagram:" + key + ":missing"
    return prefix + "." + key + ":missing"


def _is_int(value: Any) -> bool:
    return type(value) is int


def _is_nonneg_int(value: Any) -> bool:
    return _is_int(value) and 0 <= value <= MAX_INT


def _is_valid_model(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if len(value) > MAX_MODEL_LEN:
        return False
    return bool(_MODEL_RE.fullmatch(value))


def _member(value: Any, allowed: frozenset | set | tuple) -> bool:
    """Closed-vocabulary membership that never raises on arbitrary JSON values."""

    return isinstance(value, str) and value in allowed


def _is_iso(value: Any) -> bool:
    return isinstance(value, str) and bool(_ISO_RE.fullmatch(value))


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX_RE.fullmatch(value))


def validate(value: Any) -> list[str]:
    """Validate a diagram against the closed and complete schema.

    Returns a sorted list of refusal codes; an empty list accepts the value.
    Codes name only the structural path and the rule; they never echo a
    submitted value or the name of a key the schema does not name.
    """

    issues: list[str] = []
    if not isinstance(value, Mapping):
        return ["diagram:object_required"]
    # Privacy-class admission gate; the explicit hosted declaration.
    if "privacy_class" not in value:
        issues.append("diagram:privacy_class_missing")
    else:
        pc = value["privacy_class"]
        if pc == "local_only":
            issues.append("diagram:privacy_class_local_only")
        elif pc != PRIVACY_CLASS:
            issues.append("diagram:privacy_class_invalid")
    # Each top-level key must be present; extra keys are refused. Both
    # omissions and extras share the :missing or :unknown_field code.
    extras_top = sorted(set(value) - _TOP_KEYS)
    for _ in extras_top:
        issues.append("diagram:unknown_field")
    # privacy_class already gets the more specific :privacy_class_missing code.
    structural_top_keys = _TOP_KEYS - {"privacy_class"}
    for key in sorted(structural_top_keys):
        if key not in value:
            issues.append(_missing_code("diagram", key))
    # Schema constant and kind.
    if "schema" in value:
        if value["schema"] != SCHEMA:
            issues.append("diagram:schema_invalid")
    if "kind" in value:
        if value["kind"] is None:
            issues.append("kind:null_forbidden")
        elif not _member(value["kind"], _KIND_VALUES):
            issues.append("kind:invalid")
    for field, allowed in (("state", _RUN_STATES), ("verdict", _VERDICTS)):
        if field in value and value[field] is not None and not _member(value[field], allowed):
            issues.append(field + ":invalid")
    if "source_digest" in value and value["source_digest"] is not None and not _is_digest(value["source_digest"]):
        issues.append("source_digest:invalid")
    issues += _check_int_member("revision", value.get("revision"),
                                 lo=MIN_REVISION, hi=MAX_REVISION,
                                 non_null=True)
    for field in ("started_at", "ended_at"):
        v = value.get(field)
        if v is not None and not _is_iso(v):
            issues.append(field + ":invalid_iso")
    issues += _validate_root(value.get("root"))
    issues += _validate_lanes(value.get("lanes"))
    issues += _validate_cost(value.get("cost"))
    issues += _validate_counts(value.get("counts"))
    issues += _validate_size_limit(value)
    return sorted(set(issues))


def _validate_root(root):
    issues: list[str] = []
    if root is None:
        return issues + ["root:missing"]
    if not isinstance(root, Mapping):
        return issues + ["root:object_required"]
    extras = sorted(set(root) - _ROOT_KEYS)
    for _ in extras:
        issues.append("root:unknown_field")
    for key in sorted(_ROOT_KEYS):
        if key not in root:
            issues.append(_missing_code("root", key))
    if "state" in root and root["state"] is not None and not _member(root["state"], NODE_STATES):
        issues.append("root.state:invalid")
    elif "state" in root and root["state"] is None:
        issues.append("root.state:null_forbidden")
    if "evidence_class" in root and root["evidence_class"] is not None \
            and not _member(root["evidence_class"], EVIDENCE_CLASSES):
        issues.append("root.evidence_class:invalid")
    elif "evidence_class" in root and root["evidence_class"] is None:
        issues.append("root.evidence_class:null_forbidden")
    for field in ("planned_model", "observed_model"):
        v = root.get(field)
        if v is not None and not _is_valid_model(v):
            issues.append("root." + field + ":invalid")
    return issues


def _validate_lanes(lanes):
    issues: list[str] = []
    if lanes is None:
        return issues + ["lanes:missing"]
    if not isinstance(lanes, list):
        return issues + ["lanes:array_required"]
    if len(lanes) > MAX_LANES:
        issues.append("lanes:too_many")
    last_label_index = 0
    for index, lane in enumerate(lanes):
        prefix = "lanes[" + str(index) + "]"
        if not isinstance(lane, Mapping):
            issues.append(prefix + ":object_required")
            continue
        extras = sorted(set(lane) - _LANE_KEYS)
        for _ in extras:
            issues.append(prefix + ":unknown_field")
        for key in sorted(_LANE_KEYS):
            if key not in lane:
                issues.append(_missing_code(prefix, key))
        # Lane labels must be exactly "L1".."Ln" in array order.
        label = lane.get("label") if isinstance(lane, Mapping) else None
        expected_label = "L" + str(index + 1)
        if label != expected_label:
            issues.append(prefix + ".label:invalid")
        last_label_index = index
        for field in ("state",):
            v = lane.get(field)
            if v is None:
                issues.append(prefix + "." + field + ":null_forbidden")
            elif not _member(v, NODE_STATES):
                issues.append(prefix + "." + field + ":invalid")
        for field in ("spawn", "join"):
            v = lane.get(field)
            if v is None:
                issues.append(prefix + "." + field + ":null_forbidden")
            elif not _member(v, EDGE_STATES):
                issues.append(prefix + "." + field + ":invalid")
        v = lane.get("evidence_class")
        if v is None:
            issues.append(prefix + ".evidence_class:null_forbidden")
        elif not _member(v, EVIDENCE_CLASSES):
            issues.append(prefix + ".evidence_class:invalid")
        for field in ("planned_model", "observed_model"):
            v = lane.get(field)
            if v is not None and not _is_valid_model(v):
                issues.append(prefix + "." + field + ":invalid")
    return issues


def _validate_cost(cost):
    issues: list[str] = []
    if cost is None:
        return issues + ["cost:missing"]
    if not isinstance(cost, Mapping):
        return issues + ["cost:object_required"]
    extras = sorted(set(cost) - _COST_KEYS)
    for _ in extras:
        issues.append("cost:unknown_field")
    for key in sorted(_COST_KEYS):
        if key not in cost:
            issues.append(_missing_code("cost", key))
    if "billing" in cost:
        v = cost["billing"]
        if v is None:
            issues.append("cost.billing:null_forbidden")
        elif v != "unknown":
            issues.append("cost.billing:invalid")
    if "actual_cost" in cost:
        v = cost["actual_cost"]
        if v is None:
            issues.append("cost.actual_cost:null_forbidden")
        elif v != "unknown":
            issues.append("cost.actual_cost:invalid")
    if "usage_status" in cost:
        v = cost["usage_status"]
        if v is not None and not _member(v, _USAGE_STATUSES):
            issues.append("cost.usage_status:invalid")
    if "threads_without_usage" in cost:
        issues += _check_int_member("cost.threads_without_usage",
                                     cost["threads_without_usage"],
                                     lo=0, hi=MAX_INT, nullable=True)
    issues += _validate_per_role(cost.get("per_role"))
    issues += _validate_estimate(cost.get("estimate"))
    return issues


def _validate_per_role(rows):
    issues: list[str] = []
    if rows is None:
        return issues + ["cost.per_role:missing"]
    if not isinstance(rows, list):
        return issues + ["cost.per_role:array_required"]
    if len(rows) > MAX_PER_ROLE:
        issues.append("cost.per_role:too_many")
    for index, row in enumerate(rows):
        prefix = "cost.per_role[" + str(index) + "]"
        if not isinstance(row, Mapping):
            issues.append(prefix + ":object_required")
            continue
        extras = sorted(set(row) - _PER_ROLE_KEYS)
        for _ in extras:
            issues.append(prefix + ":unknown_field")
        for key in sorted(_PER_ROLE_KEYS):
            if key not in row:
                issues.append(_missing_code(prefix, key))
        role = row.get("role") if isinstance(row, Mapping) else None
        if role is None:
            issues.append(prefix + ".role:null_forbidden")
        elif not _member(role, ROLES):
            issues.append(prefix + ".role:invalid")
        model = row.get("model") if isinstance(row, Mapping) else None
        if model is None:
            issues.append(prefix + ".model:null_forbidden")
        elif not _is_valid_model(model):
            issues.append(prefix + ".model:invalid")
        for field in ("threads", "observed_threads", "lanes"):
            issues += _check_int_member(prefix + "." + field,
                                         row.get(field), lo=0, hi=MAX_INT,
                                         non_null=True)
        issues += _validate_tokens(row.get("tokens"), prefix + ".tokens")
    return issues


def _validate_tokens(tokens, prefix):
    issues: list[str] = []
    if tokens is None:
        return issues + [prefix + ":missing"]
    if not isinstance(tokens, Mapping):
        return issues + [prefix + ":object_required"]
    extras = sorted(set(tokens) - _TOKEN_KEYS)
    for _ in extras:
        issues.append(prefix + ":unknown_field")
    for field in sorted(_TOKEN_KEYS):
        if field not in tokens:
            issues.append(_missing_code(prefix, field))
            continue
        issues += _check_int_member(prefix + "." + field, tokens[field],
                                     lo=0, hi=MAX_INT, non_null=True)
    return issues


def _validate_estimate(estimate):
    issues: list[str] = []
    if estimate is None:
        return issues + ["cost.estimate:missing"]
    if not isinstance(estimate, Mapping):
        return issues + ["cost.estimate:object_required"]
    extras = sorted(set(estimate) - _ESTIMATE_KEYS)
    for _ in extras:
        issues.append("cost.estimate:unknown_field")
    for key in sorted(_ESTIMATE_KEYS):
        if key not in estimate:
            issues.append(_missing_code("cost.estimate", key))
    status = estimate.get("status") if isinstance(estimate, Mapping) else None
    if status is None:
        issues.append("cost.estimate.status:null_forbidden")
    elif not _member(status, _ESTIMATE_STATUSES):
        issues.append("cost.estimate.status:invalid")
    fm = estimate.get("frontier_model") if isinstance(estimate, Mapping) else None
    if fm is not None and not _is_valid_model(fm):
        issues.append("cost.estimate.frontier_model:invalid")
    for field in ("tokens_on_frontier_model", "tokens_moved_off_frontier_model"):
        v = estimate.get(field)
        issues += _check_int_member("cost.estimate." + field, v, lo=0, hi=MAX_INT,
                                     nullable=True)
    return issues


def _validate_counts(counts):
    issues: list[str] = []
    if counts is None:
        return issues + ["counts:missing"]
    if not isinstance(counts, Mapping):
        return issues + ["counts:object_required"]
    extras = sorted(set(counts) - _COUNTS_KEYS)
    for _ in extras:
        issues.append("counts:unknown_field")
    for key in sorted(_COUNTS_KEYS):
        if key not in counts:
            issues.append(_missing_code("counts", key))
    for field in ("issues", "unknowns", "contradictions"):
        issues += _check_int_member("counts." + field,
                                     counts.get(field), lo=0, hi=MAX_INT,
                                     non_null=True)
    return issues


def _check_int_member(path, value, *, lo, hi, nullable=False, non_null=False):
    if value is None:
        if nullable:
            return []
        if non_null:
            return [path + ":null_forbidden"]
        return []
    if not _is_int(value):
        return [path + ":non_integer"]
    if not (lo <= value <= hi):
        return [path + ":out_of_range"]
    return []


def _validate_size_limit(value):
    try:
        _payload, canonical = encode_with_canonical(value)
    except (TypeError, ValueError):
        return []
    if len(canonical) > MAX_DIAGRAM_BYTES:
        return ["diagram:too_large"]
    return []


def encode(diagram_obj: Mapping[str, Any]) -> str:
    """Encode a diagram as the URL-fragment base64url string.

    The fragment is never sent to the Site's server. The encoder uses the
    canonical JSON (``sort_keys=True``, ``separators=(",", ":")``,
    ``ensure_ascii=True``) so a decoder that uses the same options produces an
    equal object.
    """

    return encode_with_canonical(diagram_obj)[0]


def encode_with_canonical(diagram_obj: Mapping[str, Any]) -> tuple:
    """Encode the diagram as ``(payload_str, canonical_bytes)``.

    The canonical bytes are used by ``offer`` for the file fallback digest and
    by the size-bound check in ``validate``.
    """

    canonical = json.dumps(diagram_obj, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True).encode("utf-8")
    payload = base64.urlsafe_b64encode(canonical).rstrip(b"=").decode("ascii")
    return payload, canonical


def decode(payload: str) -> dict:
    """Decode and admit a fragment payload.

    Refuses characters outside the unpadded base64url alphabet, invalid UTF-8 or
    JSON, trailing data, non-object JSON, duplicate keys, non-finite numbers and
    any diagram the validator refuses; refusals carry codes only.
    """

    if not isinstance(payload, str):
        raise ValueError("payload:not_string")
    if not _BASE64URL_RE.fullmatch(payload) or len(payload) % 4 == 1:
        raise ValueError("payload:invalid_base64")
    try:
        padded = payload + "=" * (-len(payload) % 4)
        raw = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error, UnicodeEncodeError) as error:
        raise ValueError("payload:invalid_base64") from error
    value = _parse_canonical_object(raw)
    issues = validate(value)
    if issues:
        raise ValueError("diagram_refused:" + ",".join(issues))
    return value


class _PayloadRefusal(Exception):
    """A named refusal raised inside the JSON decoder, kept apart from its ValueError."""


def _parse_float_reject_non_finite(string):
    value = float(string)
    if not math.isfinite(value):
        raise _PayloadRefusal("payload:non_finite")
    return value


def _parse_constant_reject_non_finite(constant):
    raise _PayloadRefusal("payload:non_finite")


def _parse_canonical_object(raw: bytes) -> dict:
    decoder = JSONDecoder(object_pairs_hook=_dup_key_pairs_hook,
                          parse_float=_parse_float_reject_non_finite,
                          parse_constant=_parse_constant_reject_non_finite)
    try:
        text = raw.decode("utf-8")
        value, end = decoder.raw_decode(text)
    except _PayloadRefusal as refusal:
        raise ValueError(str(refusal)) from None
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("payload:invalid_json") from error
    if text[end:].strip():
        raise ValueError("payload:invalid_json")
    if not isinstance(value, dict):
        raise ValueError("payload:not_object")
    return value


def _dup_key_pairs_hook(pairs):
    seen = set()
    result = {}
    for key, value in pairs:
        if key in seen:
            raise _PayloadRefusal("payload:duplicate_key")
        seen.add(key)
        result[key] = value
    return result


def load_site_origin(path=None) -> str | None:
    """Return the published Site's origin, or None when it is not yet set."""

    path = Path(path) if path is not None else default_site_origin_path()
    raw = json.loads(path.read_bytes())
    if not isinstance(raw, Mapping) or raw.get("schema") != SITE_SCHEMA:
        raise ValueError("site_origin:schema_invalid")
    origin = raw.get("origin")
    if origin is None:
        return None
    if not isinstance(origin, str) or not _SITE_ORIGIN_RE.fullmatch(origin):
        raise ValueError("site_origin:invalid")
    if "/" in origin[8:] or "?" in origin or "#" in origin or "@" in origin \
            or ":" in origin[8:]:
        raise ValueError("site_origin:invalid")
    return origin


def build(view: Mapping[str, Any]) -> dict:
    """Construct a closed diagram from a projected run or plan view."""

    graph = view.get("graph")
    if not isinstance(graph, Mapping):
        raise ValueError("diagram_refused:graph:object_required")
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    root_node = next((node for node in nodes if node.get("id") == "root"), {}) \
        if isinstance(nodes, list) else {}
    lanes_view = [
        node for node in (nodes or []) if isinstance(node, Mapping)
        and isinstance(node.get("id"), str) and node["id"] != "root"
    ]
    edges_by_lane: dict[str, dict[str, Mapping[str, Any]]] = {}
    for edge in edges or []:
        if not isinstance(edge, Mapping):
            continue
        eid = edge.get("id")
        if not isinstance(eid, str) or ":" not in eid:
            continue
        kind, _, lane_id = eid.partition(":")
        if kind in ("spawn", "join"):
            edges_by_lane.setdefault(lane_id, {})[kind] = edge
    lanes = []
    if len(lanes_view) > MAX_LANES:
        raise ValueError("diagram_refused:lanes:too_many")
    for index, node in enumerate(lanes_view):
        lane_id = node.get("id")
        edge_pair = edges_by_lane.get(lane_id, {})
        spawn_edge = edge_pair.get("spawn", {})
        join_edge = edge_pair.get("join", {})
        lanes.append({
            "label": "L" + str(index + 1),
            "state": node.get("state"),
            "evidence_class": node.get("evidence_class"),
            "planned_model": node.get("planned_model"),
            "observed_model": node.get("observed_model"),
            "spawn": spawn_edge.get("state"),
            "join": join_edge.get("state"),
        })
    cost_summary = view.get("cost") or {}
    per_role = _build_per_role(cost_summary)
    estimate = _build_estimate(cost_summary)
    run_id = str(view.get("run_id") or "")
    kind = "plan" if run_id.startswith("plan-") else "run"
    digest = view.get("canonical_digest")
    if digest is not None and not _is_digest(digest):
        digest = None
    diagram_obj = {
        "schema": SCHEMA,
        "privacy_class": PRIVACY_CLASS,
        "kind": kind,
        "source_digest": digest,
        "state": view.get("state"),
        "verdict": view.get("verdict"),
        "revision": _revision_or_default(view.get("revision")),
        "started_at": view.get("started_at"),
        "ended_at": view.get("ended_at"),
        "root": {
            "state": root_node.get("state"),
            "evidence_class": root_node.get("evidence_class"),
            "planned_model": root_node.get("planned_model"),
            "observed_model": root_node.get("observed_model"),
        },
        "lanes": lanes,
        "cost": {
            "billing": "unknown",
            "actual_cost": "unknown",
            "usage_status": _usage_status(cost_summary.get("usage_status")),
            "threads_without_usage": _nonneg_or_none(cost_summary.get("threads_without_usage")),
            "per_role": per_role,
            "estimate": estimate,
        },
        "counts": {
            "issues": len(view.get("issues") or []),
            "unknowns": len(view.get("unknowns") or []),
            "contradictions": len((view.get("graph", {}) or {}).get("contradictions") or []),
        },
    }
    # Sanitize every model field defensively (the close-shaped validator still
    # catches anything that slipped through here).
    diagram_obj["root"]["planned_model"] = _clean_model(diagram_obj["root"]["planned_model"])
    diagram_obj["root"]["observed_model"] = _clean_model(diagram_obj["root"]["observed_model"])
    for lane in diagram_obj["lanes"]:
        lane["planned_model"] = _clean_model(lane["planned_model"])
        lane["observed_model"] = _clean_model(lane["observed_model"])
    # The sanitized copy must itself be admissible; a refusal names codes only.
    issues = validate(diagram_obj)
    if issues:
        raise ValueError("diagram_refused:" + ",".join(issues))
    return diagram_obj


def _revision_or_default(value):
    if not _is_int(value):
        return 1
    if value < MIN_REVISION:
        return MIN_REVISION
    if value > MAX_REVISION:
        return MAX_REVISION
    return value


def _nonneg_or_none(value):
    if not _is_nonneg_int(value):
        return None
    return value


def _usage_status(value):
    if value in _USAGE_STATUSES:
        return value
    return None


def _clean_model(value):
    if _is_valid_model(value):
        return value
    return None


def _lane_count(value):
    """The cost summary lists a role's lane ids; the hosted copy keeps only how many."""

    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return len(set(value))
    return _nonneg_or_none(value)


def _build_per_role(cost_summary):
    rows = cost_summary.get("per_role") if isinstance(cost_summary, Mapping) else None
    if not isinstance(rows, list):
        return []
    if len(rows) > MAX_PER_ROLE:
        raise ValueError("diagram_refused:cost.per_role:too_many")
    out = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("diagram_refused:cost.per_role:object_required")
        role = row.get("role")
        if role not in ROLES:
            raise ValueError("diagram_refused:cost.per_role.role:invalid")
        tokens_in = row.get("tokens") if isinstance(row, Mapping) else {}
        tokens = {}
        if isinstance(tokens_in, Mapping):
            for field in TOKEN_FIELDS:
                value = tokens_in.get(field)
                if _is_nonneg_int(value):
                    tokens[field] = value
                else:
                    tokens[field] = 0
        else:
            tokens = {field: 0 for field in TOKEN_FIELDS}
        out.append({
            "role": role,
            "model": _clean_model(row.get("model")),
            "threads": _nonneg_or_none(row.get("threads")),
            "observed_threads": _nonneg_or_none(row.get("observed_threads")),
            "lanes": _lane_count(row.get("lanes")),
            "tokens": tokens,
        })
    return out


def _build_estimate(cost_summary):
    estimate_in = cost_summary.get("estimate") if isinstance(cost_summary, Mapping) else None
    if not isinstance(estimate_in, Mapping):
        estimate = {}
    else:
        estimate = dict(estimate_in)
    status_in = estimate.get("status")
    if status_in in _ESTIMATE_STATUSES:
        status = status_in
    else:
        status = "unknown"
    return {
        "status": status,
        "frontier_model": _clean_model(estimate.get("frontier_model")),
        "tokens_on_frontier_model": _nonneg_or_none(estimate.get("tokens_on_frontier_model")),
        "tokens_moved_off_frontier_model": _nonneg_or_none(
            estimate.get("tokens_moved_off_frontier_model")),
    }


def offer(view: Mapping[str, Any], origin: str | None) -> dict:
    diagram_obj = build(view)
    payload, canonical = encode_with_canonical(diagram_obj)
    fits_link = len(payload) <= FITS_LINK_MAX_BYTES
    # A link exists only when a Site is published and the payload fits one;
    # otherwise the file fallback carries the same canonical bytes.
    link = origin.rstrip("/") + "/view#d=" + payload if origin is not None and fits_link else None
    digest = diagram_obj.get("source_digest")
    if isinstance(digest, str) and len(digest) >= 12:
        file_stub = digest[:12]
    else:
        file_stub = hashlib.sha256(canonical).hexdigest()[:12]
    return {
        "schema": OFFER_SCHEMA,
        "diagram": diagram_obj,
        "payload": payload,
        "bytes": len(canonical),
        "payload_chars": len(payload),
        "fits_link": fits_link,
        "link": link,
        "site": origin,
        "file_name": "orch-dork-diagram-" + file_stub + ".json",
    }
