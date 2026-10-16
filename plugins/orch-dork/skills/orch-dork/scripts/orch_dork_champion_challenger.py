#!/usr/bin/env python3
"""Provider-free inactive Champion/Challenger evidence for Issue 149.

The evaluator seals configurations, corpus manifests, per-fixture observations,
and one offline comparison.  It never runs a fixture, contacts a model, starts
shadow or canary traffic, activates a configuration, suspends a Champion,
trains weights, dispatches work, or mutates production policy.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Mapping


PROGRAM_SCHEMA = "orch-dork/champion-challenger-program/v1"
REPORT_SCHEMA = "orch-dork/champion-challenger-report/v1"
CONFIGURATION_DRAFT_SCHEMA = "orch-dork/configuration-draft/v1"
CONFIGURATION_SCHEMA = "orch-dork/champion-challenger-configuration/v1"
CORPUS_DRAFT_SCHEMA = "orch-dork/offline-corpus-draft/v1"
CORPUS_SCHEMA = "orch-dork/offline-corpus/v1"
RESULT_DRAFT_SCHEMA = "orch-dork/offline-fixture-result-draft/v1"
RESULT_SCHEMA = "orch-dork/offline-fixture-result/v1"
EVALUATION_SCHEMA = "orch-dork/champion-challenger-evaluation/v1"
# Issue 186 (FR68): a v2 configuration also binds the registry generation and
# the routing policy digest its runs freeze under, and may name the one role
# default it routes under.  decide_role_default decides a role-default
# Challenger; its sealed decision replays from the same sealed inputs.
CONFIGURATION_DRAFT_SCHEMA_V2 = "orch-dork/configuration-draft/v2"
CONFIGURATION_SCHEMA_V2 = "orch-dork/champion-challenger-configuration/v2"
# A watcher has no configured total-token or root-ingress ceiling. V3 records
# that absence explicitly as null for those two limits; historical schemas
# retain their numeric-only contract.
CONFIGURATION_DRAFT_SCHEMA_V3 = "orch-dork/configuration-draft/v3"
CONFIGURATION_SCHEMA_V3 = "orch-dork/champion-challenger-configuration/v3"
ROLE_DEFAULT_PROMOTION_SCHEMA = "orch-dork/role-default-promotion/v1"


ACTIONS = (
    "seal_configuration",
    "seal_corpus",
    "seal_result",
    "evaluate_offline",
    "decide_role_default",
)
PARTITIONS = ("frozen", "recent_failures", "adversarial", "holdout")
GATE_ORDER = ("safety", "correctness", "usefulness", "efficiency")

MAX_CANONICAL_BYTES = 262_144
MAX_LIST_ITEMS = 512
MAX_NESTING = 32
MAX_COMPOSITE_NODES = 4096
MAX_COUNT = 10**12
MAX_AGGREGATE_COUNT = MAX_COUNT * MAX_LIST_ITEMS

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")

_PROGRAM_FIELDS = frozenset({"schema", "action", "request"})
_CONFIG_REQUEST_FIELDS = frozenset({"configuration"})
_CORPUS_REQUEST_FIELDS = frozenset({"corpus"})
_RESULT_REQUEST_FIELDS = frozenset({"result"})
_EVALUATION_REQUEST_FIELDS = frozenset(
    {
        "champion",
        "challenger",
        "corpus",
        "champion_results",
        "challenger_results",
        "evaluated_at",
    }
)
_ROLE_DEFAULT_REQUEST_FIELDS = _EVALUATION_REQUEST_FIELDS | frozenset(
    {"role", "champion_routing_policy", "challenger_routing_policy"}
)
# A role-default Challenger may differ from its Champion only in the role's
# default and what follows from it: the routing rules and routing policy its
# runs freeze under and the model and runtime identities that run.
_ROLE_DEFAULT_SHARED_FIELDS = (
    "registry_generation",
    "profile_registry_sha256",
    "compiler_sha256",
    "prompt_bundle_sha256",
    "context_policy",
    "budgets",
    "verification_policy",
)

_CONFIG_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "configuration_id",
        "role",
        "profile_registry_sha256",
        "compiler_sha256",
        "prompt_bundle_sha256",
        "routing_rules_sha256",
        "model_runtime_identities",
        "context_policy",
        "budgets",
        "verification_policy",
    }
)
_CONFIG_FIELDS = _CONFIG_DRAFT_FIELDS | frozenset({"configuration_sha256"})
_CONFIG_DRAFT_FIELDS_V2 = _CONFIG_DRAFT_FIELDS | frozenset(
    {"registry_generation", "routing_policy_sha256", "role_default"}
)
_CONFIG_FIELDS_V2 = _CONFIG_DRAFT_FIELDS_V2 | frozenset({"configuration_sha256"})
_ROLE_DEFAULT_FIELDS = frozenset({"role", "profile_id"})

_MODEL_FIELDS = frozenset(
    {"role", "model_id", "runtime_id", "checkpoint_sha256"}
)
_POLICY_FIELDS = frozenset({"policy_id", "policy_sha256"})
_BUDGET_FIELDS = frozenset(
    {
        "token_limit",
        "cost_limit_micros",
        "latency_limit_ms",
        "sol_ingress_limit_tokens",
        "repair_limit",
    }
)
_CORPUS_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "corpus_id",
        "partitions",
        "training_lineage_sha256s",
        "holdout_lineage_sha256s",
        "created_at",
        "valid_until",
    }
)
_CORPUS_FIELDS = _CORPUS_DRAFT_FIELDS | frozenset({"corpus_sha256"})
_RESULT_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "configuration_sha256",
        "fixture_sha256",
        "partition",
        "lineage_sha256",
        "safety",
        "privacy",
        "authority",
        "correctness",
        "human_usefulness_bps",
        "cost_micros",
        "latency_ms",
        "human_review_sha256",
        "evidence_sha256",
    }
)
_RESULT_FIELDS = _RESULT_DRAFT_FIELDS | frozenset({"result_sha256"})
_GATE_FIELDS = frozenset(
    {"gate", "status", "champion_value", "challenger_value"}
)
_METRIC_FIELDS = frozenset(
    {
        "safety",
        "privacy",
        "authority",
        "correctness",
        "human_usefulness_bps",
        "cost_micros",
        "latency_ms",
    }
)
_EVALUATION_FIELDS = frozenset(
    {
        "schema",
        "champion_sha256",
        "challenger_sha256",
        "corpus_sha256",
        "champion_result_sha256s",
        "challenger_result_sha256s",
        "evaluated_at",
        "gate_order",
        "gates",
        "metrics",
        "decision",
        "last_known_good_champion_sha256",
        "challenger_retained_offline",
        "forward_activation_required",
        "shadow_permitted",
        "canary_permitted",
        "activation_permitted",
        "automatic_suspension_permitted",
        "bandit_permitted",
        "model_training_permitted",
        "policy_mutated",
        "dispatch_permitted",
        "tools_permitted",
        "workers_permitted",
        "authority_granted",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "retries",
        "fallbacks",
        "replacements",
        "release_permitted",
        "installation_permitted",
        "evaluation_sha256",
    }
)


def _canonical(value: Any) -> bytes:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(raw) > MAX_CANONICAL_BYTES:
        raise ValueError("canonical_bytes_exceeded")
    return raw


def _shape_within_bounds(value: Any) -> bool:
    stack = [(value, 0)]
    composite_nodes = 0
    while stack:
        current, depth = stack.pop()
        if isinstance(current, Mapping):
            composite_nodes += 1
            if (
                depth > MAX_NESTING
                or composite_nodes > MAX_COMPOSITE_NODES
                or len(current) > MAX_LIST_ITEMS
            ):
                return False
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            composite_nodes += 1
            if (
                depth > MAX_NESTING
                or composite_nodes > MAX_COMPOSITE_NODES
                or len(current) > MAX_LIST_ITEMS
            ):
                return False
            stack.extend((item, depth + 1) for item in current)
    return True


def json_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    result = deepcopy(dict(value))
    result.pop(field, None)
    result[field] = json_sha256(result)
    return result


def _sealed(value: Any, field: str) -> bool:
    if not isinstance(value, Mapping) or not _sha(value.get(field)):
        return False
    core = dict(value)
    digest = core.pop(field)
    try:
        return digest == json_sha256(core)
    except (TypeError, ValueError, OverflowError):
        return False


def _sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _count(value: Any, *, maximum: int = MAX_COUNT) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _instant(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo == timezone.utc else None


def _closed(
    value: Any, fields: frozenset[str], label: str, issues: list[str]
) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or set(value) != fields:
        issues.append(label + ":contract_invalid")
        return None
    return deepcopy(dict(value))


def _sha_list(
    value: Any, label: str, issues: list[str], *, nonempty: bool = True
) -> list[str] | None:
    if (
        not isinstance(value, list)
        or (nonempty and not value)
        or len(value) > MAX_LIST_ITEMS
        or any(not _sha(item) for item in value)
        or len(value) != len(set(value))
    ):
        issues.append(label + ":invalid")
        return None
    return sorted(value)


def _validate_configuration_draft(
    value: Any, issues: list[str]
) -> dict[str, Any] | None:
    version_two = (
        isinstance(value, Mapping)
        and value.get("schema") in (CONFIGURATION_DRAFT_SCHEMA_V2, CONFIGURATION_DRAFT_SCHEMA_V3)
    )
    config = _closed(
        value,
        _CONFIG_DRAFT_FIELDS_V2 if version_two else _CONFIG_DRAFT_FIELDS,
        "configuration",
        issues,
    )
    if config is None:
        return None
    if not version_two and config.get("schema") != CONFIGURATION_DRAFT_SCHEMA:
        issues.append("configuration:schema_invalid")

    if not _identifier(config.get("configuration_id")):
        issues.append("configuration:id_invalid")
    if config.get("role") not in {"champion", "challenger"}:
        issues.append("configuration:role_invalid")
    for field in (
        "profile_registry_sha256",
        "compiler_sha256",
        "prompt_bundle_sha256",
        "routing_rules_sha256",
    ):
        if not _sha(config.get(field)):
            issues.append("configuration:" + field + "_invalid")

    identities = config.get("model_runtime_identities")
    normalized_identities: list[dict[str, Any]] = []
    if (
        not isinstance(identities, list)
        or not identities
        or len(identities) > 32
    ):
        issues.append("configuration:model_identities_invalid")
    else:
        for raw in identities:
            item = _closed(raw, _MODEL_FIELDS, "configuration:model", issues)
            if item is None:
                continue
            if not all(
                _identifier(item.get(field))
                for field in ("role", "model_id", "runtime_id")
            ) or not _sha(item.get("checkpoint_sha256")):
                issues.append("configuration:model_identity_invalid")
                continue
            normalized_identities.append(item)
        keys = [item["role"] for item in normalized_identities]
        if len(keys) != len(set(keys)):
            issues.append("configuration:model_role_duplicate")
        config["model_runtime_identities"] = sorted(
            normalized_identities,
            key=lambda item: (
                item["role"], item["model_id"], item["runtime_id"]
            ),
        )

    for field in ("context_policy", "verification_policy"):
        policy = _closed(
            config.get(field), _POLICY_FIELDS, "configuration:" + field, issues
        )
        if policy is not None and (
            not _identifier(policy.get("policy_id"))
            or not _sha(policy.get("policy_sha256"))
        ):
            issues.append("configuration:" + field + "_invalid")
    budgets = _closed(
        config.get("budgets"), _BUDGET_FIELDS, "configuration:budgets", issues
    )
    if budgets is not None:
        for field in _BUDGET_FIELDS:
            if (config["schema"] == CONFIGURATION_DRAFT_SCHEMA_V3
                    and field in ("token_limit", "sol_ingress_limit_tokens")
                    and budgets[field] is None):
                continue
            maximum = 2 if field == "repair_limit" else MAX_COUNT
            if not _count(budgets.get(field), maximum=maximum):
                issues.append("configuration:budget_invalid")
                break
    if version_two:
        if not _identifier(config.get("registry_generation")):
            issues.append("configuration:registry_generation_invalid")
        if not _sha(config.get("routing_policy_sha256")):
            issues.append("configuration:routing_policy_sha256_invalid")
        role_default = config.get("role_default")
        if role_default is not None:
            default = _closed(
                role_default,
                _ROLE_DEFAULT_FIELDS,
                "configuration:role_default",
                issues,
            )
            if default is not None and not all(
                _identifier(default.get(field)) for field in _ROLE_DEFAULT_FIELDS
            ):
                issues.append("configuration:role_default_invalid")

    return config


def validate_configuration(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    version_two = (
        isinstance(value, Mapping) and value.get("schema") in (CONFIGURATION_SCHEMA_V2, CONFIGURATION_SCHEMA_V3)
    )
    config = _closed(
        value,
        _CONFIG_FIELDS_V2 if version_two else _CONFIG_FIELDS,
        "configuration",
        issues,
    )
    if config is not None:
        if not version_two and config.get("schema") != CONFIGURATION_SCHEMA:
            issues.append("configuration:schema_invalid")
        if not _sealed(config, "configuration_sha256"):
            issues.append("configuration:seal_invalid")
        draft = dict(config)
        draft.pop("configuration_sha256", None)
        draft["schema"] = (
            CONFIGURATION_DRAFT_SCHEMA_V3 if config.get("schema") == CONFIGURATION_SCHEMA_V3
            else CONFIGURATION_DRAFT_SCHEMA_V2 if version_two else CONFIGURATION_DRAFT_SCHEMA
        )
        _validate_configuration_draft(draft, issues)
    unique = sorted(set(issues))
    return {"status": "PASS" if not unique else "FAIL", "issues": unique}


def _configuration(value: Any) -> tuple[dict[str, Any] | None, list[str]]:
    issues: list[str] = []
    draft = _validate_configuration_draft(value, issues)
    if issues or draft is None:
        return None, sorted(set(issues))
    draft["schema"] = (
        CONFIGURATION_SCHEMA_V3 if draft["schema"] == CONFIGURATION_DRAFT_SCHEMA_V3
        else CONFIGURATION_SCHEMA_V2
        if draft["schema"] == CONFIGURATION_DRAFT_SCHEMA_V2
        else CONFIGURATION_SCHEMA
    )
    return _seal(draft, "configuration_sha256"), []


def _validate_corpus_draft(
    value: Any, issues: list[str]
) -> dict[str, Any] | None:
    corpus = _closed(value, _CORPUS_DRAFT_FIELDS, "corpus", issues)
    if corpus is None:
        return None
    if corpus.get("schema") != CORPUS_DRAFT_SCHEMA:
        issues.append("corpus:schema_invalid")
    if not _identifier(corpus.get("corpus_id")):
        issues.append("corpus:id_invalid")
    partitions = _closed(
        corpus.get("partitions"), frozenset(PARTITIONS), "corpus:partitions", issues
    )
    all_fixtures: list[str] = []
    if partitions is not None:
        for partition in PARTITIONS:
            normalized = _sha_list(
                partitions.get(partition),
                "corpus:partition:" + partition,
                issues,
            )
            if normalized is not None:
                partitions[partition] = normalized
                all_fixtures.extend(normalized)
        if len(all_fixtures) != len(set(all_fixtures)):
            issues.append("corpus:fixture_overlap")
        corpus["partitions"] = partitions
    training = _sha_list(
        corpus.get("training_lineage_sha256s"), "corpus:training_lineages", issues
    )
    holdout = _sha_list(
        corpus.get("holdout_lineage_sha256s"), "corpus:holdout_lineages", issues
    )
    if training is not None:
        corpus["training_lineage_sha256s"] = training
    if holdout is not None:
        corpus["holdout_lineage_sha256s"] = holdout
    if training is not None and holdout is not None and set(training) & set(holdout):
        issues.append("corpus:lineage_overlap")
    created = _instant(corpus.get("created_at"))
    valid_until = _instant(corpus.get("valid_until"))
    if created is None:
        issues.append("corpus:created_at_invalid")
    if valid_until is None:
        issues.append("corpus:valid_until_invalid")
    if created is not None and valid_until is not None and valid_until <= created:
        issues.append("corpus:validity_invalid")
    return corpus


def validate_corpus(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    corpus = _closed(value, _CORPUS_FIELDS, "corpus", issues)
    if corpus is not None:
        if corpus.get("schema") != CORPUS_SCHEMA:
            issues.append("corpus:schema_invalid")
        if not _sealed(corpus, "corpus_sha256"):
            issues.append("corpus:seal_invalid")
        draft = dict(corpus)
        draft.pop("corpus_sha256", None)
        draft["schema"] = CORPUS_DRAFT_SCHEMA
        _validate_corpus_draft(draft, issues)
    unique = sorted(set(issues))
    return {"status": "PASS" if not unique else "FAIL", "issues": unique}


def _corpus(value: Any) -> tuple[dict[str, Any] | None, list[str]]:
    issues: list[str] = []
    draft = _validate_corpus_draft(value, issues)
    if issues or draft is None:
        return None, sorted(set(issues))
    draft["schema"] = CORPUS_SCHEMA
    return _seal(draft, "corpus_sha256"), []


def _validate_result_draft(
    value: Any, issues: list[str]
) -> dict[str, Any] | None:
    result = _closed(value, _RESULT_DRAFT_FIELDS, "result", issues)
    if result is None:
        return None
    if result.get("schema") != RESULT_DRAFT_SCHEMA:
        issues.append("result:schema_invalid")
    for field in (
        "configuration_sha256",
        "fixture_sha256",
        "lineage_sha256",
        "human_review_sha256",
        "evidence_sha256",
    ):
        if not _sha(result.get(field)):
            issues.append("result:" + field + "_invalid")
    if result.get("partition") not in PARTITIONS:
        issues.append("result:partition_invalid")
    for field in ("safety", "privacy", "authority", "correctness"):
        if result.get(field) not in {"PASS", "FAIL"}:
            issues.append("result:" + field + "_invalid")
    if not _count(result.get("human_usefulness_bps"), maximum=10_000):
        issues.append("result:usefulness_invalid")
    for field in ("cost_micros", "latency_ms"):
        if not _count(result.get(field)):
            issues.append("result:" + field + "_invalid")
    return result


def validate_result(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    result = _closed(value, _RESULT_FIELDS, "result", issues)
    if result is not None:
        if result.get("schema") != RESULT_SCHEMA:
            issues.append("result:schema_invalid")
        if not _sealed(result, "result_sha256"):
            issues.append("result:seal_invalid")
        draft = dict(result)
        draft.pop("result_sha256", None)
        draft["schema"] = RESULT_DRAFT_SCHEMA
        _validate_result_draft(draft, issues)
    unique = sorted(set(issues))
    return {"status": "PASS" if not unique else "FAIL", "issues": unique}


def _result(value: Any) -> tuple[dict[str, Any] | None, list[str]]:
    issues: list[str] = []
    draft = _validate_result_draft(value, issues)
    if issues or draft is None:
        return None, sorted(set(issues))
    draft["schema"] = RESULT_SCHEMA
    return _seal(draft, "result_sha256"), []


def _result_set(
    value: Any,
    *,
    label: str,
    config_sha256: str,
    corpus: Mapping[str, Any],
    issues: list[str],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > MAX_LIST_ITEMS:
        issues.append("evaluation:" + label + "_results_invalid")
        return []
    normalized: list[dict[str, Any]] = []
    for raw in value:
        verdict = validate_result(raw)
        if verdict["status"] != "PASS" or raw.get(
            "configuration_sha256"
        ) != config_sha256:
            issues.append("evaluation:" + label + "_result_invalid")
            continue
        normalized.append(deepcopy(dict(raw)))
    expected = {
        fixture
        for partition in PARTITIONS
        for fixture in corpus["partitions"][partition]
    }
    actual = [item["fixture_sha256"] for item in normalized]
    if set(actual) != expected or len(actual) != len(set(actual)):
        issues.append("evaluation:" + label + "_coverage_mismatch")
    for item in normalized:
        if item["fixture_sha256"] not in corpus["partitions"][item["partition"]]:
            issues.append("evaluation:" + label + "_partition_mismatch")
        allowed_lineages = (
            corpus["holdout_lineage_sha256s"]
            if item["partition"] == "holdout"
            else corpus["training_lineage_sha256s"]
        )
        if item["lineage_sha256"] not in allowed_lineages:
            issues.append("evaluation:" + label + "_lineage_mismatch")
    return sorted(normalized, key=lambda item: item["fixture_sha256"])


def _gate(
    gate: str,
    status: str,
    champion_value: Any,
    challenger_value: Any,
) -> dict[str, Any]:
    return {
        "gate": gate,
        "status": status,
        "champion_value": champion_value,
        "challenger_value": challenger_value,
    }


def _result_metrics(results: list[dict[str, Any]]) -> dict[str, int]:
    return {
        **{
            field: sum(item[field] == "PASS" for item in results)
            for field in ("safety", "privacy", "authority", "correctness")
        },
        "human_usefulness_bps": sum(
            item["human_usefulness_bps"] for item in results
        )
        // len(results),
        "cost_micros": sum(item["cost_micros"] for item in results),
        "latency_ms": sum(item["latency_ms"] for item in results),
    }


def _derive_gate_outcome(
    champion: Mapping[str, int],
    challenger: Mapping[str, int],
    result_count: int,
) -> tuple[list[dict[str, Any]], str]:
    conformance_fields = ("safety", "privacy", "authority")
    if any(
        champion[field] != result_count
        for field in (*conformance_fields, "correctness")
    ):
        raise ValueError("champion_baseline_not_passing")

    champion_conformance = {
        field: champion[field] for field in conformance_fields
    }
    challenger_conformance = {
        field: challenger[field] for field in conformance_fields
    }
    gate_values = (
        (champion_conformance, challenger_conformance),
        (champion["correctness"], challenger["correctness"]),
        (
            champion["human_usefulness_bps"],
            challenger["human_usefulness_bps"],
        ),
        (
            {
                "cost_micros": champion["cost_micros"],
                "latency_ms": champion["latency_ms"],
            },
            {
                "cost_micros": challenger["cost_micros"],
                "latency_ms": challenger["latency_ms"],
            },
        ),
    )
    passed = (
        all(challenger[field] == result_count for field in conformance_fields),
        challenger["correctness"] == result_count,
        challenger["human_usefulness_bps"]
        >= champion["human_usefulness_bps"],
        challenger["cost_micros"] <= champion["cost_micros"]
        and challenger["latency_ms"] <= champion["latency_ms"],
    )
    gates = [
        _gate(
            gate,
            "PASS" if gate_passed else "FAIL",
            values[0],
            values[1],
        )
        for gate, values, gate_passed in zip(GATE_ORDER, gate_values, passed)
    ]
    failed_index = next(
        (index for index, gate_passed in enumerate(passed) if not gate_passed),
        None,
    )
    if failed_index is not None:
        for gate in gates[failed_index + 1 :]:
            gate["status"] = "NOT_EVALUATED"
        decision = (
            "REFUSED_SAFETY",
            "REFUSED_CORRECTNESS",
            "REFUSED_USEFULNESS",
            "RETAINED_CHAMPION",
        )[failed_index]
    else:
        decision = "OFFLINE_CHALLENGER_RETAINED"
    return gates, decision


def validate_evaluation(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    record = _closed(value, _EVALUATION_FIELDS, "evaluation_record", issues)
    if record is not None:
        if record.get("schema") != EVALUATION_SCHEMA:
            issues.append("evaluation_record:schema_invalid")
        if not _sealed(record, "evaluation_sha256"):
            issues.append("evaluation_record:seal_invalid")
        for field in (
            "champion_sha256",
            "challenger_sha256",
            "corpus_sha256",
            "last_known_good_champion_sha256",
        ):
            if not _sha(record.get(field)):
                issues.append("evaluation_record:" + field + "_invalid")
        if record.get("last_known_good_champion_sha256") != record.get(
            "champion_sha256"
        ):
            issues.append("evaluation_record:champion_history_rewritten")
        result_counts: dict[str, int] = {}
        for role in ("champion", "challenger"):
            field = role + "_result_sha256s"
            result_sha256s = _sha_list(
                record.get(field), "evaluation_record:" + field, issues
            )
            if result_sha256s is not None:
                result_counts[role] = len(result_sha256s)
        if (
            len(result_counts) == 2
            and result_counts["champion"] != result_counts["challenger"]
        ):
            issues.append("evaluation_record:result_count_mismatch")
        if _instant(record.get("evaluated_at")) is None:
            issues.append("evaluation_record:evaluated_at_invalid")
        if record.get("gate_order") != list(GATE_ORDER):
            issues.append("evaluation_record:gate_order_invalid")
        gates = record.get("gates")
        normalized_gates: list[dict[str, Any]] = []
        if not isinstance(gates, list) or len(gates) != len(GATE_ORDER):
            issues.append("evaluation_record:gates_invalid")
        else:
            failed_seen = False
            for expected, raw in zip(GATE_ORDER, gates):
                gate = _closed(
                    raw, _GATE_FIELDS, "evaluation_record:gate", issues
                )
                if gate is None or gate.get("gate") != expected:
                    issues.append("evaluation_record:gate_identity_invalid")
                    continue
                normalized_gates.append(gate)
                status = gate.get("status")
                if status not in {"PASS", "FAIL", "NOT_EVALUATED"}:
                    issues.append("evaluation_record:gate_status_invalid")
                if failed_seen and status != "NOT_EVALUATED":
                    issues.append("evaluation_record:gate_precedence_invalid")
                if not failed_seen and status == "NOT_EVALUATED":
                    issues.append("evaluation_record:gate_precedence_invalid")
                if status == "FAIL":
                    failed_seen = True
        metrics = _closed(
            record.get("metrics"),
            frozenset({"champion", "challenger"}),
            "evaluation_record:metrics",
            issues,
        )
        metric_rows: dict[str, dict[str, Any]] = {}
        if metrics is not None:
            for role in ("champion", "challenger"):
                row = _closed(
                    metrics.get(role),
                    _METRIC_FIELDS,
                    "evaluation_record:metrics:" + role,
                    issues,
                )
                if row is None:
                    continue
                maximum_results = result_counts.get(role, MAX_LIST_ITEMS)
                count_fields = ("safety", "privacy", "authority", "correctness")
                if any(
                    not _count(row.get(field), maximum=maximum_results)
                    for field in count_fields
                ) or not _count(
                    row.get("human_usefulness_bps"), maximum=10_000
                ):
                    issues.append("evaluation_record:metric_invalid")
                if any(
                    not _count(
                        row.get(field), maximum=MAX_AGGREGATE_COUNT
                    )
                    for field in ("cost_micros", "latency_ms")
                ):
                    issues.append("evaluation_record:metric_invalid")
                metric_rows[role] = row
        decisions = {
            "REFUSED_SAFETY",
            "REFUSED_CORRECTNESS",
            "REFUSED_USEFULNESS",
            "RETAINED_CHAMPION",
            "OFFLINE_CHALLENGER_RETAINED",
        }
        if record.get("decision") not in decisions:
            issues.append("evaluation_record:decision_invalid")
        if (
            len(metric_rows) == 2
            and len(result_counts) == 2
            and result_counts["champion"] == result_counts["challenger"]
            and len(normalized_gates) == len(GATE_ORDER)
            and "evaluation_record:metric_invalid" not in issues
        ):
            try:
                expected_gates, expected_decision = _derive_gate_outcome(
                    metric_rows["champion"],
                    metric_rows["challenger"],
                    result_counts["challenger"],
                )
            except ValueError:
                issues.append(
                    "evaluation_record:champion_baseline_not_passing"
                )
            else:
                for gate, expected in zip(normalized_gates, expected_gates):
                    if (
                        gate.get("champion_value")
                        != expected["champion_value"]
                        or gate.get("challenger_value")
                        != expected["challenger_value"]
                    ):
                        issues.append("evaluation_record:gate_value_mismatch")
                    if gate.get("status") != expected["status"]:
                        issues.append(
                            "evaluation_record:gate_precedence_invalid"
                        )
                if (
                    record.get("decision") != expected_decision
                ):
                    issues.append("evaluation_record:decision_gate_mismatch")
        if record.get("challenger_retained_offline") is not (
            record.get("decision") == "OFFLINE_CHALLENGER_RETAINED"
        ):
            issues.append("evaluation_record:retention_mismatch")
        if record.get("forward_activation_required") is not True:
            issues.append("evaluation_record:forward_activation_missing")
        for field in (
            "shadow_permitted",
            "canary_permitted",
            "activation_permitted",
            "automatic_suspension_permitted",
            "bandit_permitted",
            "model_training_permitted",
            "policy_mutated",
            "dispatch_permitted",
            "tools_permitted",
            "workers_permitted",
            "authority_granted",
        ):
            if record.get(field) is not False:
                issues.append("evaluation_record:inactive_flag_invalid")
        if (
            record.get("provider_free") is not True
            or record.get("model_calls") != 0
            or record.get("hosted_calls") != 0
            or record.get("retries") != 0
            or record.get("fallbacks") != 0
            or record.get("replacements") != 0
        ):
            issues.append("evaluation_record:provider_boundary_invalid")
        for field in ("release_permitted", "installation_permitted"):
            if record.get(field) is not False:
                issues.append("evaluation_record:inactive_flag_invalid")
    unique = sorted(set(issues))
    return {"status": "PASS" if not unique else "FAIL", "issues": unique}


def _evaluate_offline(
    request: Mapping[str, Any], issues: list[str]
) -> tuple[str, dict[str, Any] | None]:
    value = _closed(request, _EVALUATION_REQUEST_FIELDS, "evaluation", issues)
    if value is None:
        return "ENVELOPE_INVALID", None
    champion = value["champion"]
    challenger = value["challenger"]
    corpus = value["corpus"]
    if validate_configuration(champion)["status"] != "PASS" or champion.get(
        "role"
    ) != "champion":
        issues.append("evaluation:champion_invalid")
    if validate_configuration(challenger)["status"] != "PASS" or challenger.get(
        "role"
    ) != "challenger":
        issues.append("evaluation:challenger_invalid")
    if (
        isinstance(champion, Mapping)
        and isinstance(challenger, Mapping)
        and champion.get("configuration_sha256")
        == challenger.get("configuration_sha256")
    ):
        issues.append("evaluation:configurations_not_distinct")
    if validate_corpus(corpus)["status"] != "PASS":
        issues.append("evaluation:corpus_invalid")
    evaluated = _instant(value.get("evaluated_at"))
    if evaluated is None:
        issues.append("evaluation:evaluated_at_invalid")
    if issues:
        return "EVIDENCE_INVALID", None
    assert isinstance(champion, Mapping)
    assert isinstance(challenger, Mapping)
    assert isinstance(corpus, Mapping)
    created = _instant(corpus["created_at"])
    valid_until = _instant(corpus["valid_until"])
    if (
        evaluated is None
        or created is None
        or valid_until is None
        or not created <= evaluated <= valid_until
    ):
        issues.append("evaluation:corpus_stale")
        return "EVIDENCE_INVALID", None

    champion_results = _result_set(
        value["champion_results"],
        label="champion",
        config_sha256=champion["configuration_sha256"],
        corpus=corpus,
        issues=issues,
    )
    challenger_results = _result_set(
        value["challenger_results"],
        label="challenger",
        config_sha256=challenger["configuration_sha256"],
        corpus=corpus,
        issues=issues,
    )
    if issues:
        return "EVIDENCE_INVALID", None

    champion_metrics = _result_metrics(champion_results)
    challenger_metrics = _result_metrics(challenger_results)
    try:
        gates, decision = _derive_gate_outcome(
            champion_metrics,
            challenger_metrics,
            len(challenger_results),
        )
    except ValueError:
        issues.append("evaluation:champion_baseline_not_passing")
        return "EVIDENCE_INVALID", None

    record = _seal(
        {
            "schema": EVALUATION_SCHEMA,
            "champion_sha256": champion["configuration_sha256"],
            "challenger_sha256": challenger["configuration_sha256"],
            "corpus_sha256": corpus["corpus_sha256"],
            "champion_result_sha256s": sorted(
                item["result_sha256"] for item in champion_results
            ),
            "challenger_result_sha256s": sorted(
                item["result_sha256"] for item in challenger_results
            ),
            "evaluated_at": value["evaluated_at"],
            "gate_order": list(GATE_ORDER),
            "gates": gates,
            "metrics": {
                "champion": champion_metrics,
                "challenger": challenger_metrics,
            },
            "decision": decision,
            "last_known_good_champion_sha256": champion[
                "configuration_sha256"
            ],
            "challenger_retained_offline": decision
            == "OFFLINE_CHALLENGER_RETAINED",
            "forward_activation_required": True,
            "shadow_permitted": False,
            "canary_permitted": False,
            "activation_permitted": False,
            "automatic_suspension_permitted": False,
            "bandit_permitted": False,
            "model_training_permitted": False,
            "policy_mutated": False,
            "dispatch_permitted": False,
            "tools_permitted": False,
            "workers_permitted": False,
            "authority_granted": False,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
            "retries": 0,
            "fallbacks": 0,
            "replacements": 0,
            "release_permitted": False,
            "installation_permitted": False,
        },
        "evaluation_sha256",
    )
    return decision, record


def _role_policy_issues(
    label: str, config: Mapping[str, Any], policy: Any, role: str
) -> list[str]:
    """Whether one configuration's routing policy routes the role through its default.

    The policy must be the sealed policy the configuration binds, in its
    registry generation, routing the role through exactly the
    configuration's default profile, and when that route names a model the
    configuration's identities must run it for the role.
    """

    if not isinstance(policy, Mapping) or not _sealed(policy, "policy_sha256"):
        return ["role_default:" + label + "_policy_invalid"]
    issues: list[str] = []
    if policy["policy_sha256"] != config["routing_policy_sha256"]:
        issues.append("role_default:" + label + "_policy_unbound")
    if policy.get("registry_generation") != config["registry_generation"]:
        issues.append("role_default:" + label + "_policy_generation_mismatch")
    profile_id = config["role_default"]["profile_id"]
    roles = policy.get("roles")
    routes = policy.get("routes")
    route = routes.get(profile_id) if isinstance(routes, Mapping) else None
    if (
        not isinstance(roles, Mapping)
        or roles.get(role) != [profile_id]
        or not isinstance(route, Mapping)
    ):
        issues.append("role_default:" + label + "_policy_role_mismatch")
    elif route.get("model") is not None and not any(
        identity["role"] == role and identity["model_id"] == route["model"]
        for identity in config["model_runtime_identities"]
    ):
        issues.append("role_default:" + label + "_identity_mismatch")
    return issues


def _routing_outside_role(policy: Mapping[str, Any], role: str) -> tuple[Any, ...]:
    """Everything a routing policy decides that the role's default does not."""

    nodes = policy.get("nodes") if isinstance(policy.get("nodes"), Mapping) else {}
    routes = policy.get("routes") if isinstance(policy.get("routes"), Mapping) else {}

    def in_role(entry: Any) -> bool:
        return isinstance(entry, Mapping) and entry.get("role") == role

    return (
        policy.get("registry_sha256"),
        {node: entry for node, entry in nodes.items() if not in_role(entry)},
        sorted(node for node, entry in nodes.items() if in_role(entry)),
        {profile: route for profile, route in routes.items() if not in_role(route)},
    )


def _decide_role_default(
    request: Any, issues: list[str]
) -> tuple[str, dict[str, Any] | None, dict[str, Any] | None]:
    """Decide the offline stage of one role-default Challenger (Issue 186).

    The request is an offline evaluation request plus the role and the
    sealed routing policy each configuration binds.  Both configurations
    must be v2 and name a default for that role; each policy must route the
    role through exactly that default and the identities must run its
    model; and the Challenger may differ from the Champion only in that
    default, the routing it implies, and the identities that run.  The
    offline evaluation is derived here from the same sealed inputs, so the
    decision replays.  The decision records the offline stage only: FR60's
    shadow observation, separately authorized canary, and forward
    activation still follow, so it permits no activation.
    """

    value = _closed(request, _ROLE_DEFAULT_REQUEST_FIELDS, "role_default", issues)
    if value is None:
        return "ENVELOPE_INVALID", None, None
    role = value["role"]
    if not _identifier(role):
        issues.append("role_default:role_invalid")
    configurations: dict[str, Mapping[str, Any]] = {}
    for label in ("champion", "challenger"):
        config = value[label]
        if not isinstance(config, Mapping) or config.get("schema") != CONFIGURATION_SCHEMA_V2:
            issues.append("role_default:" + label + "_record_required")
            continue
        if validate_configuration(config)["status"] != "PASS" or config.get("role") != label:
            issues.append("role_default:" + label + "_record_invalid")
            continue
        default = config.get("role_default")
        if not isinstance(default, Mapping) or default.get("role") != role:
            issues.append("role_default:" + label + "_default_missing")
            continue
        configurations[label] = config
    if issues:
        return "EVIDENCE_INVALID", None, None
    champion = configurations["champion"]
    challenger = configurations["challenger"]
    champion_policy = value["champion_routing_policy"]
    challenger_policy = value["challenger_routing_policy"]
    issues.extend(_role_policy_issues("champion", champion, champion_policy, role))
    issues.extend(_role_policy_issues("challenger", challenger, challenger_policy, role))
    if champion["role_default"]["profile_id"] == challenger["role_default"]["profile_id"]:
        issues.append("role_default:profile_unchanged")
    if any(
        champion.get(field) != challenger.get(field)
        for field in _ROLE_DEFAULT_SHARED_FIELDS
    ) or (
        isinstance(champion_policy, Mapping)
        and isinstance(challenger_policy, Mapping)
        and _routing_outside_role(champion_policy, role)
        != _routing_outside_role(challenger_policy, role)
    ):
        issues.append("role_default:challenger_not_isolated")
    if issues:
        return "EVIDENCE_INVALID", None, None
    decision, evaluation = _evaluate_offline(
        {field: value[field] for field in _EVALUATION_REQUEST_FIELDS}, issues
    )
    if issues or evaluation is None:
        return "EVIDENCE_INVALID", None, None
    retained = decision == "OFFLINE_CHALLENGER_RETAINED"
    record = _seal(
        {
            "schema": ROLE_DEFAULT_PROMOTION_SCHEMA,
            "stage": "offline",
            "role": role,
            "champion_profile_id": champion["role_default"]["profile_id"],
            "challenger_profile_id": challenger["role_default"]["profile_id"],
            "registry_generation": challenger["registry_generation"],
            "champion_sha256": champion["configuration_sha256"],
            "challenger_sha256": challenger["configuration_sha256"],
            "champion_routing_policy_sha256": champion["routing_policy_sha256"],
            "challenger_routing_policy_sha256": challenger["routing_policy_sha256"],
            "challenger_model_runtime_identities": deepcopy(
                challenger["model_runtime_identities"]
            ),
            "corpus_sha256": evaluation["corpus_sha256"],
            "evaluation_sha256": evaluation["evaluation_sha256"],
            "evaluation_decision": decision,
            "decision": "OFFLINE_RETAINED" if retained else "NOT_RETAINED",
            "forward_activation_required": True,
            "shadow_permitted": False,
            "canary_permitted": False,
            "activation_permitted": False,
            "policy_mutated": False,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        },
        "decision_sha256",
    )
    return (
        "ROLE_DEFAULT_OFFLINE_RETAINED" if retained else "ROLE_DEFAULT_NOT_RETAINED",
        evaluation,
        record,
    )


def replay_role_default_promotion(request: Any, decision: Any) -> dict[str, Any]:
    """Re-derive one role-default decision from its sealed inputs and compare.

    PASS only when the request decides again and its decision equals the
    sealed decision byte for byte.
    """

    report = evaluate(
        {"schema": PROGRAM_SCHEMA, "action": "decide_role_default", "request": request}
    )
    replayed = report.get("role_default_promotion")
    if report.get("status") != "PASS" or not isinstance(replayed, Mapping):
        return {"status": "FAIL", "issues": ["role_default:replay_refused"], "decision": None}
    if not _sealed(decision, "decision_sha256") or decision != replayed:
        return {"status": "FAIL", "issues": ["role_default:replay_mismatch"], "decision": None}
    return {"status": "PASS", "issues": [], "decision": deepcopy(dict(replayed))}


def _blank(action: str | None) -> dict[str, Any]:
    return {
        "configuration": None,
        "corpus": None,
        "result": None,
        "evaluation": None,
        "action": action if action in ACTIONS else "unknown",
    }


def evaluate(program: Any) -> dict[str, Any]:
    issues: list[str] = []
    action: str | None = None
    try:
        canonical_input = _canonical(program) if _shape_within_bounds(program) else None
    except (TypeError, ValueError, OverflowError, RecursionError):
        canonical_input = None
    if canonical_input is None:
        issues.append("input:hostile_or_noncanonical")
        envelope = None
    else:
        envelope = _closed(program, _PROGRAM_FIELDS, "program", issues)
    payload = _blank(None)
    decision = "ENVELOPE_INVALID"
    if envelope is not None:
        raw_action = envelope.get("action")
        if envelope.get("schema") != PROGRAM_SCHEMA:
            issues.append("program:schema_invalid")
        if raw_action in ACTIONS:
            action = raw_action
            payload["action"] = action
            if action == "decide_role_default":
                payload["role_default_promotion"] = None
        else:
            issues.append("program:action_invalid")
        if not issues and action == "seal_configuration":
            request = _closed(
                envelope["request"],
                _CONFIG_REQUEST_FIELDS,
                "request",
                issues,
            )
            if request is not None:
                payload["configuration"], found = _configuration(
                    request["configuration"]
                )
                issues.extend(found)
                decision = "CONFIGURATION_SEALED" if not found else "REJECTED"
        elif not issues and action == "seal_corpus":
            request = _closed(
                envelope["request"], _CORPUS_REQUEST_FIELDS, "request", issues
            )
            if request is not None:
                payload["corpus"], found = _corpus(request["corpus"])
                issues.extend(found)
                decision = "CORPUS_SEALED" if not found else "REJECTED"
        elif not issues and action == "seal_result":
            request = _closed(
                envelope["request"], _RESULT_REQUEST_FIELDS, "request", issues
            )
            if request is not None:
                payload["result"], found = _result(request["result"])
                issues.extend(found)
                decision = "RESULT_SEALED" if not found else "REJECTED"
        elif not issues and action == "evaluate_offline":
            decision, payload["evaluation"] = _evaluate_offline(
                envelope["request"], issues
            )
        elif not issues and action == "decide_role_default":
            (
                decision,
                payload["evaluation"],
                payload["role_default_promotion"],
            ) = _decide_role_default(envelope["request"], issues)
    unique = sorted(set(issues))
    report = {
        "schema": REPORT_SCHEMA,
        **payload,
        "status": "PASS" if not unique else "FAIL",
        "decision": decision,
        "issues": unique,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "retries": 0,
        "fallbacks": 0,
        "replacements": 0,
        "mutation_permitted": False,
        "dispatch_permitted": False,
        "tools_permitted": False,
        "workers_permitted": False,
        "authority_granted": False,
        "release_permitted": False,
        "installation_permitted": False,
    }
    return _seal(report, "report_sha256")


__all__ = [
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "CONFIGURATION_DRAFT_SCHEMA",
    "CONFIGURATION_SCHEMA",
    "CORPUS_DRAFT_SCHEMA",
    "CORPUS_SCHEMA",
    "RESULT_DRAFT_SCHEMA",
    "RESULT_SCHEMA",
    "EVALUATION_SCHEMA",
    "CONFIGURATION_DRAFT_SCHEMA_V2",
    "CONFIGURATION_SCHEMA_V2",
    "CONFIGURATION_DRAFT_SCHEMA_V3",
    "CONFIGURATION_SCHEMA_V3",
    "ROLE_DEFAULT_PROMOTION_SCHEMA",
    "ACTIONS",
    "PARTITIONS",
    "GATE_ORDER",
    "json_sha256",
    "validate_configuration",
    "validate_corpus",
    "validate_result",
    "validate_evaluation",
    "replay_role_default_promotion",
    "evaluate",
]


if __name__ == "__main__":
    raise SystemExit("Import and call evaluate(program); no CLI is provided.")
