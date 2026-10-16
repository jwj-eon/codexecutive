#!/usr/bin/env python3
"""Exact token attribution for classic-V1 runtime usage records.

Usage records are generation receipts, not cumulative session snapshots.  A
forked child may report the parent's copied history in its provider input
count; the explicit ``forked_prefix_tokens`` boundary is removed once and is
retained as evidence.  Compaction snapshots are retained but are never added
to generation totals.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional


USAGE_SCHEMA = "orch-dork/usage-attribution/v1"
USAGE_ADAPTER_VERSION = "classic-v1-usage/1.0"


class UsageAttributionError(ValueError):
    def __init__(self, report: Mapping[str, Any]):
        self.report = dict(report)
        super().__init__("usage attribution failed: " + ", ".join(report["issues"]))


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _source(record: Mapping[str, Any], position: int) -> Optional[dict[str, Any]]:
    value = record.get("source_ref", record.get("source"))
    if isinstance(value, str) and value.strip():
        return {"record_id": value.strip(), "position": position}
    if isinstance(value, Mapping):
        record_id = value.get("record_id", value.get("id", value.get("ref")))
        if _text(record_id):
            return {"record_id": record_id.strip(), "position": position}
    return None


def _records(raw: Mapping[str, Any] | Iterable[Mapping[str, Any]]) -> tuple[list[Any], list[str]]:
    issues: list[str] = []
    if isinstance(raw, Mapping):
        # This adapter consumes raw V1 receipts only.  A normalized usage
        # report is derived evidence and must not be accepted as an
        # independent runtime source.
        if raw.get("schema") not in (None, "orch-dork/raw-classic-v1"):
            issues.append("raw:schema_invalid")
        values = raw.get("usage", raw.get("records", raw.get("events")))
        if not isinstance(values, list):
            issues.append("raw:usage_not_array")
            values = []
    elif isinstance(raw, Iterable) and not isinstance(raw, (str, bytes)):
        values = list(raw)
    else:
        values = []
        issues.append("raw:not_object_or_array")
    return values, issues


def _task_ids_from_graph(graph: Optional[Mapping[str, Any]]) -> tuple[set[str], Optional[str]]:
    if not isinstance(graph, Mapping):
        return set(), None
    root = graph.get("root")
    children = graph.get("children")
    ids: set[str] = set()
    root_id = None
    if isinstance(root, Mapping) and _text(root.get("task_id")):
        root_id = root["task_id"].strip()
        ids.add(root_id)
    if isinstance(children, list):
        for child in children:
            if isinstance(child, Mapping) and _text(child.get("task_id")):
                ids.add(child["task_id"].strip())
    return ids, root_id


def _graph_issues(graph: Optional[Mapping[str, Any]]) -> tuple[list[str], set[str], Optional[str]]:
    """Validate the identity boundary before attributing any usage record."""

    if graph is None:
        return [], set(), None
    issues: list[str] = []
    if not isinstance(graph, Mapping):
        return ["graph:not_object"], set(), None
    root = graph.get("root")
    children = graph.get("children")
    ids: set[str] = set()
    root_id: Optional[str] = None
    if not isinstance(root, Mapping):
        issues.append("graph:root_not_object")
    elif not _text(root.get("task_id")):
        issues.append("graph:root_id_missing")
    else:
        root_id = root["task_id"].strip()
        ids.add(root_id)
    if not isinstance(children, list):
        issues.append("graph:children_not_array")
    else:
        for position, child in enumerate(children):
            if not isinstance(child, Mapping):
                issues.append("graph:child_not_object:%d" % position)
                continue
            task_id = child.get("task_id")
            if not _text(task_id):
                issues.append("graph:child_id_missing:%d" % position)
                continue
            task_id = task_id.strip()
            if task_id in ids:
                issues.append("graph:duplicate_task:%s" % task_id)
            ids.add(task_id)
    return issues, ids, root_id


def _field_values(record: Mapping[str, Any], field: str) -> list[tuple[str, Any]]:
    values: list[tuple[str, Any]] = []
    if field in record:
        values.append((field, record[field]))
    nested = record.get("usage")
    if isinstance(nested, Mapping) and field in nested:
        values.append(("usage." + field, nested[field]))
    return values


def _usage_value(record: Mapping[str, Any], field: str) -> Any:
    values = _field_values(record, field)
    if values:
        return values[0][1]
    return None


def _kind(record: Mapping[str, Any]) -> Optional[str]:
    value = record.get("kind", record.get("type"))
    if not _text(value):
        return None
    aliases = {
        "generation": "generation",
        "turn": "generation",
        "response": "generation",
        "usage": "generation",
        "compaction": "compaction",
        "compaction.snapshot": "compaction",
    }
    return aliases.get(value.strip())


def _prefix(record: Mapping[str, Any]) -> Any:
    for field in (
        "forked_prefix_tokens",
        "copied_history_tokens",
        "copied_input_tokens",
        "history_prefix_tokens",
    ):
        value = _usage_value(record, field)
        if value is not None:
            return value
    return None


def _prefix_values(record: Mapping[str, Any]) -> list[tuple[str, Any]]:
    values: list[tuple[str, Any]] = []
    for field in (
        "forked_prefix_tokens",
        "copied_history_tokens",
        "copied_input_tokens",
        "history_prefix_tokens",
    ):
        values.extend((name, value) for name, value in _field_values(record, field) if value is not None)
    return values


def _component() -> dict[str, Any]:
    return {
        "input_tokens": 0,
        "copied_history_tokens": 0,
        "attributable_input_tokens": 0,
        "cached_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_tokens": 0,
        "raw_total_tokens": 0,
        "attributed_total_tokens": 0,
        "generation_records": 0,
        "compaction_snapshots": 0,
        "usage_ids": [],
        "known": True,
    }


def attribute_usage(
    raw: Mapping[str, Any] | Iterable[Mapping[str, Any]],
    graph: Optional[Mapping[str, Any]] = None,
    *,
    expected_task_ids: Optional[Iterable[str]] = None,
) -> dict[str, Any]:
    """Attribute V1 token receipts without treating missing values as zero.

    ``raw_total_tokens`` is the provider-reported total for generation records;
    ``attributed_total_tokens`` subtracts copied fork history.  Compaction
    snapshots are reported separately and excluded from both totals.
    """

    records, issues = _records(raw)
    graph_supplied = graph is not None
    graph_issues, graph_ids, root_id = _graph_issues(graph)
    issues.extend(graph_issues)
    explicit_expected = expected_task_ids is not None
    expected: set[str] = set()
    if explicit_expected:
        if isinstance(expected_task_ids, str):
            expected_values: Iterable[Any] = (expected_task_ids,)
        elif expected_task_ids is None:
            expected_values = ()
        else:
            try:
                expected_values = iter(expected_task_ids)
            except TypeError:
                issues.append("expected_task_ids_not_iterable")
                expected_values = ()
        for value in expected_values:
            if not _text(value):
                issues.append("expected_task_id_invalid")
            else:
                expected.add(value.strip())
    else:
        expected = set(graph_ids)
    known_task_ids = set(graph_ids) | set(expected)
    if graph_supplied and explicit_expected and expected != graph_ids:
        issues.append("graph:expected_task_ids_mismatch")
    if graph_supplied and root_id is None and (expected or records):
        # A supplied graph is an authority boundary.  Never select an
        # arbitrary child as the root when that boundary is malformed.
        if "graph:root_id_missing" not in issues:
            issues.append("graph:root_id_missing")
    elif not graph_supplied and root_id is None and len(expected) == 1:
        root_id = next(iter(expected))
    elif not graph_supplied and expected and root_id is None:
        issues.append("graph:root_id_missing")
    if not graph_supplied and not expected:
        observed_ids = {
            str(record.get("task_id", record.get("session_id", record.get("thread_id")))).strip()
            for record in records
            if isinstance(record, Mapping)
            and _text(record.get("task_id", record.get("session_id", record.get("thread_id"))))
        }
        if len(observed_ids) == 1:
            root_id = next(iter(observed_ids))
        elif len(observed_ids) > 1:
            issues.append("graph:root_id_missing")

    if not records:
        issues.append("raw:no_usage_records")

    source_refs: list[dict[str, Any]] = []
    seen_sources: set[str] = set()
    seen_usage: set[str] = set()
    seen_slots: set[tuple[str, str, str]] = set()
    components: dict[str, dict[str, Any]] = {}
    compaction_records: list[dict[str, Any]] = []
    parsed_generation: list[dict[str, Any]] = []

    for position, record in enumerate(records):
        record_issue_start = len(issues)
        if not isinstance(record, Mapping):
            issues.append("usage[%d]:not_object" % position)
            continue
        source = _source(record, position)
        if source is None:
            issues.append("usage[%d]:source_ref_missing" % position)
        else:
            source_refs.append(source)
            if source["record_id"] in seen_sources:
                issues.append("source:duplicate:%s" % source["record_id"])
            seen_sources.add(source["record_id"])
        usage_id = record.get("usage_id", record.get("id"))
        if not _text(usage_id):
            issues.append("usage[%d]:usage_id_missing" % position)
            usage_id = "<missing-%d>" % position
        else:
            usage_id = usage_id.strip()
            if usage_id in seen_usage:
                issues.append("usage:duplicate:%s" % usage_id)
            seen_usage.add(usage_id)
        task_id = record.get("task_id", record.get("session_id", record.get("thread_id")))
        if not _text(task_id):
            issues.append("usage[%d]:task_id_missing" % position)
            task_id = "<missing-task-%d>" % position
        else:
            task_id = task_id.strip()
        if known_task_ids and task_id not in known_task_ids:
            issues.append("usage:unknown_task:%s" % task_id)
        if expected and task_id not in expected:
            issues.append("usage:unexpected_task:%s" % task_id)

        kind = _kind(record)
        if kind is None:
            issues.append("usage[%d]:kind_invalid" % position)
            continue

        turn_id = record.get("turn_id", record.get("response_id", ""))
        turn_id = turn_id.strip() if _text(turn_id) else ""
        slot = (task_id, turn_id, kind)
        if slot in seen_slots:
            issues.append("usage:duplicate_slot:%s:%s:%s" % slot)
        seen_slots.add(slot)

        if kind == "compaction":
            # A compaction receipt is a snapshot of context work.  It may not
            # silently enter generation totals; the raw receipt remains bound.
            snapshot = record.get("snapshot", record.get("cumulative", True))
            if snapshot is not True:
                issues.append("compaction:not_snapshot:%s" % usage_id)
            values = _validated_values(record, position, issues, allow_missing_total=False)
            compaction_records.append({
                "usage_id": usage_id,
                "task_id": task_id,
                "turn_id": turn_id,
                "snapshot": snapshot,
                "tokens": values,
                "source_ref": source,
                "included_in_generation_total": False,
            })
            component = components.setdefault(task_id, _component())
            component["compaction_snapshots"] += 1
            if len(issues) != record_issue_start:
                component["known"] = False
            continue

        values = _validated_values(record, position, issues, allow_missing_total=False)
        prefix_values = _prefix_values(record)
        if len({repr(value) for _, value in prefix_values}) > 1:
            issues.append("usage:copied_history_boundary_conflict:%s" % usage_id)
        prefix = prefix_values[0][1] if prefix_values else None
        if task_id != root_id and prefix is None:
            issues.append("usage:copied_history_boundary_missing:%s:%s" % (task_id, usage_id))
            prefix = 0
            prefix_known = False
        else:
            # A root has no parent history to exclude.  The zero boundary is
            # therefore known even when the provider omits an explicit field.
            prefix_known = True
            if prefix is None:
                prefix = 0
        if not _int(prefix):
            issues.append("usage:copied_history_invalid:%s" % usage_id)
            prefix = 0
            prefix_known = False
        if task_id == root_id and prefix != 0:
            issues.append("usage:root_copied_history_nonzero:%s" % usage_id)
        if values["input_tokens"] is not None and prefix > values["input_tokens"]:
            issues.append("usage:copied_history_exceeds_input:%s" % usage_id)
        attributable_input = None if values["input_tokens"] is None else values["input_tokens"] - prefix
        raw_total = values["total_tokens"]
        attributed_total = None if raw_total is None else raw_total - prefix
        if attributable_input is not None and attributable_input < 0:
            attributable_input = None
        if attributed_total is not None and attributed_total < 0:
            attributed_total = None
        parsed_generation.append({
            "usage_id": usage_id,
            "task_id": task_id,
            "turn_id": turn_id,
            "source_ref": source,
            "values": values,
            "copied_history_tokens": prefix,
            "copied_history_known": prefix_known,
            "attributable_input_tokens": attributable_input,
            "attributed_total_tokens": attributed_total,
        })

        component = components.setdefault(task_id, _component())
        component["generation_records"] += 1
        component["usage_ids"].append(usage_id)
        component["known"] = (
            component["known"]
            and len(issues) == record_issue_start
            and prefix_known
            and all(value is not None for value in values.values())
        )
        for name in ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens", "raw_total_tokens"):
            key = "total_tokens" if name == "raw_total_tokens" else name
            value = values[key]
            if value is not None:
                component[name] += value
        component["copied_history_tokens"] += prefix
        if attributable_input is not None:
            component["attributable_input_tokens"] += attributable_input
        if attributed_total is not None:
            component["attributed_total_tokens"] += attributed_total

    if expected:
        for task_id in sorted(expected):
            if task_id not in components or components[task_id]["generation_records"] == 0:
                issues.append("usage:missing:%s" % task_id)
                components.setdefault(task_id, _component())["known"] = False

    # A zero-record component is unknown, not an observed zero.  Likewise, a
    # partially specified record never receives a numeric substitute.
    for component in components.values():
        if not component["known"]:
            for key in ("input_tokens", "copied_history_tokens", "attributable_input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens", "raw_total_tokens", "attributed_total_tokens"):
                component[key] = None

    known = not issues and bool(parsed_generation) if expected or records else not issues
    status = "PASS" if known else ("UNKNOWN" if not issues and not parsed_generation else "FAIL")
    combined_raw = None
    combined_attributed = None
    if all(component["known"] for component in components.values()) and parsed_generation and not issues:
        combined_raw = sum(component["raw_total_tokens"] for component in components.values())
        combined_attributed = sum(component["attributed_total_tokens"] for component in components.values())

    return {
        "schema": USAGE_SCHEMA,
        "adapter_version": USAGE_ADAPTER_VERSION,
        "evidence_tier": "runtime-observed",
        "status": status,
        "issues": sorted(set(issues)),
        "source_refs": source_refs,
        "components": components,
        "compaction_records": compaction_records,
        "combined": {
            "raw_total_tokens": combined_raw,
            "copied_history_tokens": sum((component["copied_history_tokens"] or 0) for component in components.values()) if known else None,
            "attributed_total_tokens": combined_attributed,
            "known": combined_attributed is not None,
        },
        "records": parsed_generation,
    }


def _validated_values(record: Mapping[str, Any], position: int, issues: list[str], *, allow_missing_total: bool) -> dict[str, Optional[int]]:
    # ``allow_missing_total`` remains a compatibility parameter; exact V1
    # attribution never synthesizes a provider total from component fields.
    values: dict[str, Optional[int]] = {}
    for name in ("input_tokens", "output_tokens", "reasoning_tokens", "cached_input_tokens"):
        raw_values = [value for _, value in _field_values(record, name)]
        if len({repr(value) for value in raw_values}) > 1:
            issues.append("usage[%d]:%s_conflicting" % (position, name))
        value = _usage_value(record, name)
        if not _int(value):
            issues.append("usage[%d]:%s_missing_or_invalid" % (position, name))
            values[name] = None
        else:
            values[name] = value
    raw_totals = [value for _, value in _field_values(record, "total_tokens")]
    if len({repr(value) for value in raw_totals}) > 1:
        issues.append("usage[%d]:total_tokens_conflicting" % position)
    total = _usage_value(record, "total_tokens")
    if not _int(total):
        issues.append("usage[%d]:total_tokens_missing_or_invalid" % position)
        values["total_tokens"] = None
    else:
        values["total_tokens"] = total
    if values["cached_input_tokens"] is not None and values["input_tokens"] is not None and values["cached_input_tokens"] > values["input_tokens"]:
        issues.append("usage[%d]:cached_input_exceeds_input" % position)
    if values["reasoning_tokens"] is not None and values["output_tokens"] is not None and values["reasoning_tokens"] > values["output_tokens"]:
        issues.append("usage[%d]:reasoning_exceeds_output" % position)
    if values["total_tokens"] is not None and values["input_tokens"] is not None and values["output_tokens"] is not None:
        if values["total_tokens"] != values["input_tokens"] + values["output_tokens"]:
            issues.append("usage[%d]:total_mismatch" % position)
    return values


def require_usage(raw: Mapping[str, Any] | Iterable[Mapping[str, Any]], graph: Optional[Mapping[str, Any]] = None, *, expected_task_ids: Optional[Iterable[str]] = None) -> dict[str, Any]:
    report = attribute_usage(raw, graph, expected_task_ids=expected_task_ids)
    if report["status"] != "PASS":
        raise UsageAttributionError(report)
    return report


class UsageAttributor:
    adapter_version = USAGE_ADAPTER_VERSION

    def attribute(self, raw: Mapping[str, Any] | Iterable[Mapping[str, Any]], graph: Optional[Mapping[str, Any]] = None, *, expected_task_ids: Optional[Iterable[str]] = None) -> dict[str, Any]:
        return attribute_usage(raw, graph, expected_task_ids=expected_task_ids)

    normalize = attribute


attribute_v1_usage = attribute_usage
normalize_usage = attribute_usage
attribute_v1 = attribute_usage
attribute_token_usage = attribute_usage
UsageAttribution = UsageAttributor


__all__ = [
    "USAGE_SCHEMA",
    "USAGE_ADAPTER_VERSION",
    "UsageAttributionError",
    "UsageAttributor",
    "UsageAttribution",
    "attribute_token_usage",
    "attribute_v1",
    "attribute_usage",
    "attribute_v1_usage",
    "normalize_usage",
    "require_usage",
]
