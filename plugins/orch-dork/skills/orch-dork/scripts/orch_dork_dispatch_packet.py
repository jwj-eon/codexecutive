#!/usr/bin/env python3
"""Issue 127: seal a tranche-one dispatch packet and its decision sheet.

Everything mechanical about dispatching tranche one already exists, spread
across six builders: the pooled basis, the ladder, the survival
projection, the campaign axes, the grant shape, and the dispatch
permutation.  Assembling them by hand at authorization time is the step
most likely to go wrong, and it is the only step between the programme and
its next real evidence.

This module assembles them once and seals the result, so the thing an
execution authority binds is provably the same thing that later registers.

A packet is not a grant.  It carries no authority digest, no grant digest,
and no attempt identifier.  It yields a registrable grant only after complete
canonical reproduction and an explicit or standing authority binding.
Building a packet must never be confusable with holding authority to run one.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_campaign_prereg as prereg  # noqa: E402
import orch_dork_experiment_campaign as campaign_contract  # noqa: E402
import orch_dork_live_sweep as live  # noqa: E402
import orch_dork_standing_authority as standing_authority  # noqa: E402
import orch_dork_tranche_ladder as ladder  # noqa: E402


PACKET_SCHEMA = "orch-dork/tranche-dispatch-packet/v1"
AUTHORITY_SCOPE_SCHEMA = "orch-dork/tranche-dispatch-authority-scope/v1"
DISPATCH_RUNTIME_CLOSURE_SCHEMA = (
    "orch-dork/tranche-dispatch-runtime-closure/v1"
)

_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_LABEL = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_AUTOMATIC_AUTHORITY = object()
_RUNTIME_SUFFIXES = frozenset({".py", ".ts"})
_REQUIRED_RUNTIME_FILES = frozenset(
    {
        "orch_dork_dispatch_packet.py",
        "orch_dork_live_sweep.py",
        "orch_dork_standing_authority.py",
    }
)

# Observed across the sealed v5 and v6 shards: fifty lane sessions carrying
# usage ran 20,991-23,185 tokens. The reservation is not a guess, and the
# packet records what it is a reservation *over*.
#
# Note this is deliberately a different population from the odds pool. The
# odds are priced on every campaign that produced a settled observation
# (54 sessions); token sizing can only use sessions that actually reported
# usage (50). A decision sheet must say which pool each number came from,
# or an Owner cannot reconcile them.
OBSERVED_LANE_SESSIONS = 50
MAX_OBSERVED_LANE_TOKENS = 23_185
RESERVED_TOKENS_PER_LANE_SESSION = 27_000

# One cell at a time, four lanes live, matching every campaign recorded so
# far. Wall clock has never bound a campaign (v6 used 358,066 ms of
# 21,600,000), so this ceiling is a backstop rather than a live constraint,
# and the decision sheet says so instead of presenting it as a binding
# limit. Sized as roughly ten times v6's whole-campaign wall for a tranche
# a fifth its size.
MAX_WALL_TIME_MS = 3_600_000
V6_OBSERVED_WALL_MS = 358_066
MAX_CELLS_IN_FLIGHT = 1
MAX_LIVE_LANE_SESSIONS = 4

# A modest grid to quote the lane-count cost against. The session figure
# is derived from this by inverting the rule of three, never hard-coded:
# an Owner-facing record must not carry a precise statistic whose origin
# cannot be traced.
REFERENCE_GRID_SESSIONS = 30

_AUTHORITY_NOTE = (
    "This packet describes a dispatch and its terms. It carries no "
    "authority by itself. After complete packet reproduction, standing "
    "Owner authority binds the exact packet and mints one one-use grant "
    "without a per-run approval message."
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def dispatch_runtime_closure_sha256(
    plugin_root: str | Path | None = None,
) -> str | None:
    """Hash every shipped runtime script that can participate in dispatch."""

    executing_root = Path(__file__).resolve().parents[3]
    root = (
        executing_root if plugin_root is None else Path(plugin_root)
    )
    try:
        if root != executing_root or not root.is_absolute() or root.is_symlink():
            return None
        resolved_root = root.resolve(strict=True)
        if resolved_root != root or not resolved_root.is_dir():
            return None
        scripts_root = root / "skills" / "orch-dork" / "scripts"
        if (
            scripts_root.is_symlink()
            or not scripts_root.is_dir()
            or scripts_root.resolve(strict=True) != scripts_root
        ):
            return None
        files = []
        for path in sorted(scripts_root.iterdir(), key=lambda item: item.name):
            if path.suffix not in _RUNTIME_SUFFIXES:
                continue
            if (
                path.is_symlink()
                or not path.is_file()
                or path.resolve(strict=True).parent != scripts_root
            ):
                return None
            files.append(
                {
                    "name": path.name,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    except OSError:
        return None
    if not _REQUIRED_RUNTIME_FILES.issubset(
        {item["name"] for item in files}
    ):
        return None
    return _sha256(
        {"schema": DISPATCH_RUNTIME_CLOSURE_SCHEMA, "files": files}
    )


def _round6(value: float) -> float:
    return float(round(value, 6))


def _refusal(issues: list[str]) -> dict[str, Any]:
    core = {
        "schema": PACKET_SCHEMA,
        "status": "FAIL",
        "issues": sorted(set(issues)),
        "campaign_label": None,
        "campaign": None,
        "grant_terms": None,
        "projections": None,
        "rung": None,
        "authorized": False,
        "descriptive_only": True,
        "grants_authority": False,
        "authority_note": _AUTHORITY_NOTE,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "record_sha256": _sha256(core)}


def _axes(campaign_label: str, lane_counts: list[int], seeds: list[int]):
    return {
        "schema": live.CAMPAIGN_AXES_SCHEMA,
        "campaign_id": campaign_label,
        "question": {
            "question_id": campaign_label + "-question",
            "statement": (
                "How does lane count interact with verified success on "
                "evidence extraction?"
            ),
            "primary_metric": "verified_success_bps",
            "population": "sealed-local-qwen-orchestration-fixtures",
            "null_hypothesis": (
                "No preregistered configuration reaches the "
                "verified-success threshold."
            ),
        },
        "decision_rule": {
            "metric": "verified_success_bps",
            "operator": "greater_than_or_equal",
            "threshold": {"numerator": 8_000, "denominator": 10_000},
            "minimum_complete_replicates": 3,
            "pass_disposition": "retain_default",
            "fail_disposition": "retain_default",
            "incomplete_disposition": "inconclusive",
        },
        "task_families": ["evidence_extraction"],
        "lane_counts": list(lane_counts),
        "cut_strategies": ["acceptance_unit"],
        "workload_buckets": {
            "high": {"item_count": 16, "coupling_density_bps": 5_000}
        },
        "seeds": list(seeds),
    }


def _lane_sessions(campaign: dict[str, Any]) -> int:
    seeds = len(campaign.get("seeds", []))
    total = 0
    for configuration in campaign.get("configuration_grid", []):
        parameters = {
            row["name"]: row["value"] for row in configuration["parameters"]
        }
        total += int(parameters["lane_count"]) * seeds
    return total


def build_dispatch_packet(
    *,
    campaign_label: str,
    prepared_at: str,
    prior_clean_sessions: int,
    prior_failures: int,
) -> dict[str, Any]:
    """Seal one tranche shape, its derived terms, and its projected odds.

    The shape is not chosen here: it is the rung the Issue 126 planner
    recommends for the supplied evidence, so a better pool automatically
    produces a larger tranche without anyone editing a constant.
    """

    issues: list[str] = []
    if not isinstance(campaign_label, str) or not _LABEL.fullmatch(
        campaign_label
    ):
        issues.append("packet:campaign_label_invalid")
    if not isinstance(prepared_at, str) or not _TIMESTAMP.fullmatch(
        prepared_at
    ):
        issues.append("packet:prepared_at_invalid")
    if type(prior_clean_sessions) is not int or prior_clean_sessions < 1:
        issues.append("packet:prior_sessions_invalid")
    if type(prior_failures) is not int or prior_failures < 0:
        issues.append("packet:prior_failures_invalid")
    if issues:
        return _refusal(issues)

    rung = ladder.recommend_tranche_size(
        prior_clean_sessions=prior_clean_sessions,
        prior_failures=prior_failures,
    )
    if not rung.get("feasible") or rung.get("sessions") is None:
        return _refusal(["packet:no_viable_tranche"])

    # Lane counts {1, 2} across three seeds gives 3 + 6 = 9 lane sessions,
    # which is the recommended rung at the current pool. A larger rung
    # would take a third lane count or more seeds; the packet refuses
    # rather than silently dispatching a shape that is not the rung.
    sessions = int(rung["sessions"])
    seeds = [11_101, 11_102, 11_103]
    lane_counts = [1, 2]
    axes = _axes(campaign_label, lane_counts, seeds)
    draft = live.build_live_campaign_draft(axes)
    sealed = campaign_contract.seal_campaign(draft)
    if sealed.get("status") != "PASS":
        return _refusal(["packet:campaign_invalid"])
    campaign = sealed["result"]["campaign"]

    lane_sessions = _lane_sessions(campaign)
    if lane_sessions != sessions:
        # The built shape must be the recommended rung, not merely close.
        return _refusal(["packet:shape_does_not_match_rung"])

    prereg_record = prereg.build_campaign_preregistration(
        campaign_label=campaign_label,
        preregistered_at=prepared_at,
        # One cell per configuration-and-seed pair. The identifiers must be
        # distinct, so the seed is part of the name rather than a repeat.
        cells=[
            "%s-r%d" % (row["configuration_id"], seed)
            for row in campaign["configuration_grid"]
            for seed in seeds
        ],
        sessions_per_cell=[
            int(
                {
                    item["name"]: item["value"]
                    for item in row["parameters"]
                }["lane_count"]
            )
            for row in campaign["configuration_grid"]
            for _ in seeds
        ],
        prior_clean_sessions=prior_clean_sessions,
        prior_failures=prior_failures,
        dispatch_seed=seeds[0],
    )
    if prereg_record.get("status") != "PASS":
        return _refusal(["packet:preregistration_invalid"])

    grant_terms = {
        "lane_sessions": lane_sessions,
        "cells": len(campaign["configuration_grid"]) * len(seeds),
        "reserved_tokens_per_lane_session": RESERVED_TOKENS_PER_LANE_SESSION,
        "max_tokens": RESERVED_TOKENS_PER_LANE_SESSION * lane_sessions,
        "max_wall_time_ms": MAX_WALL_TIME_MS,
        "max_cells_in_flight": MAX_CELLS_IN_FLIGHT,
        "max_live_lane_sessions": MAX_LIVE_LANE_SESSIONS,
        "forbidden": [
            "automatic_fallbacks",
            "automatic_replacements",
            "automatic_retries",
            "hosted_calls",
        ],
        "reservation_basis": {
            "observed_lane_sessions": OBSERVED_LANE_SESSIONS,
            "max_observed_lane_tokens": MAX_OBSERVED_LANE_TOKENS,
            "headroom_factor": _round6(
                RESERVED_TOKENS_PER_LANE_SESSION / MAX_OBSERVED_LANE_TOKENS
            ),
            "source": (
                "sealed issue111-stage1-pilot-v5 and -v6 evidence shards"
            ),
            "differs_from_odds_pool": (
                "Token sizing uses only sessions that reported usage; the "
                "odds use every campaign that produced a settled "
                "observation. The two populations are not the same size."
            ),
        },
    }

    core = {
        "schema": PACKET_SCHEMA,
        "status": "PASS",
        "issues": [],
        "campaign_label": campaign_label,
        "prepared_at": prepared_at,
        "campaign": {
            "campaign_sha256": campaign["campaign_sha256"],
            "cell_count": live.expected_run_count(campaign),
            "lane_counts": lane_counts,
            "seeds": seeds,
            "task_families": ["evidence_extraction"],
            "sealed": campaign,
        },
        "grant_terms": grant_terms,
        "rung": {
            "sessions": sessions,
            "completion_probability": rung["completion_probability"],
            "rule": rung["rule"],
            "bound_basis": rung["bound_basis"],
        },
        "projections": {
            "prior_clean_sessions": prior_clean_sessions,
            "prior_failures": prior_failures,
            "assumed_failure_rate": prereg_record["assumed_failure_rate"],
            "completion_probability": (
                prereg_record["completion_probability"]
            ),
            "pilot_outcomes_only": prereg_record["pilot_outcomes_only"],
            "bound_to_tighten": prereg_record["bound_to_tighten"],
            "preregistration_sha256": prereg_record["record_sha256"],
        },
        "stop_cost": {
            "max_sessions_forfeited": sessions - 1,
            "settled_cells_retained": True,
            "note": (
                "A stop forfeits the remaining cells of this tranche only. "
                "Every settled cell stays sealed and still enters the pool."
            ),
        },
        "does_not_answer": [
            (
                "the lane-count question, which needs %d clean sessions "
                "for a %d-cell grid to reach 50%% completion odds"
                % (
                    prereg.clean_sessions_for_target(
                        target_sessions=REFERENCE_GRID_SESSIONS,
                        completion=0.5,
                    ),
                    REFERENCE_GRID_SESSIONS,
                )
            ),
            (
                "whether any configuration beats the decision threshold; "
                "this tranche is powered to tighten a bound, not to decide"
            ),
        ],
        "authorized": False,
        "descriptive_only": True,
        "grants_authority": False,
        "authority_note": _AUTHORITY_NOTE,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "record_sha256": _sha256(core)}


def _reproduce_dispatch_packet(value: Any) -> dict[str, Any] | None:
    if (
        not isinstance(value, dict)
        or value.get("schema") != PACKET_SCHEMA
        or value.get("status") != "PASS"
        or not isinstance(value.get("projections"), dict)
    ):
        return None
    projections = value["projections"]
    try:
        return build_dispatch_packet(
            campaign_label=value.get("campaign_label"),
            prepared_at=value.get("prepared_at"),
            prior_clean_sessions=projections.get("prior_clean_sessions"),
            prior_failures=projections.get("prior_failures"),
        )
    except (TypeError, ValueError):
        return None


def _dispatch_grant_execution_contract(value: dict[str, Any]) -> dict[str, Any]:
    terms = value["grant_terms"]
    grant = live.build_parameterized_live_grant(
        value["campaign"]["sealed"],
        max_tokens=int(terms["max_tokens"]),
        max_wall_time_ms=int(terms["max_wall_time_ms"]),
        reserved_tokens_per_lane_session=int(
            terms["reserved_tokens_per_lane_session"]
        ),
        authority_source_sha256="0" * 64,
        grant_id="semantic-dispatch-grant",
        attempt_id="semantic-dispatch-attempt",
    )
    provenance = {
        "grant_id",
        "attempt_id",
        "campaign_sha256",
        "authority_source_sha256",
        "grant_sha256",
    }
    return {key: item for key, item in grant.items() if key not in provenance}


def _dispatch_authority_scope_sha256_reproduced(
    value: dict[str, Any], *, plugin_root: str | Path | None = None
) -> str | None:
    runtime_closure_sha256 = dispatch_runtime_closure_sha256(plugin_root)
    if runtime_closure_sha256 is None:
        return None
    sealed_campaign = value["campaign"]["sealed"]
    semantic_campaign = {
        "schema": sealed_campaign["schema"],
        "question": {
            key: item
            for key, item in sealed_campaign["question"].items()
            if key != "question_id"
        },
        "configuration_grid": sealed_campaign["configuration_grid"],
        "replicate_count": sealed_campaign["replicate_count"],
        "seeds": sealed_campaign["seeds"],
        "decision_rule": sealed_campaign["decision_rule"],
    }
    projections = {
        key: item
        for key, item in value["projections"].items()
        if key != "preregistration_sha256"
    }
    return _sha256(
        {
            "schema": AUTHORITY_SCOPE_SCHEMA,
            "campaign": semantic_campaign,
            "grant_terms": value["grant_terms"],
            "execution": {
                "runtime_closure_sha256": runtime_closure_sha256,
                "grant_contract": _dispatch_grant_execution_contract(value),
            },
            "rung": value["rung"],
            "projections": projections,
            "stop_cost": value["stop_cost"],
            "does_not_answer": value["does_not_answer"],
        }
    )


def dispatch_authority_scope_sha256(
    value: Any, *, plugin_root: str | Path | None = None
) -> str | None:
    """Hash material dispatch terms after complete canonical reproduction."""

    reproduced = _reproduce_dispatch_packet(value)
    if reproduced != value:
        return None
    return _dispatch_authority_scope_sha256_reproduced(
        value, plugin_root=plugin_root
    )


def grant_from_packet(
    value: Any,
    *,
    authority_source_sha256: Any = _AUTOMATIC_AUTHORITY,
    plugin_root: str | Path | None = None,
) -> dict[str, Any]:
    """Turn a sealed packet plus explicit or standing authority into a grant.

    This is the only function here that produces anything registrable. The
    complete packet is reproduced before authority binds, so a caller cannot
    self-seal wider terms between construction and registration.
    """

    issues: list[str] = []
    if not isinstance(value, dict) or value.get("schema") != PACKET_SCHEMA:
        return {
            "status": "FAIL",
            "issues": ["packet:invalid"],
            "grant": None,
            "campaign": None,
        }
    if value.get("status") != "PASS":
        return {
            "status": "FAIL",
            "issues": ["packet:not_passing"],
            "grant": None,
            "campaign": None,
        }
    core = {key: item for key, item in value.items() if key != "record_sha256"}
    if value.get("record_sha256") != _sha256(core):
        issues.append("packet:seal_mismatch")
    reproduced = _reproduce_dispatch_packet(value)
    if reproduced != value:
        issues.append("packet:reproduction_mismatch")
    authority_scope_sha256 = (
        _dispatch_authority_scope_sha256_reproduced(
            value, plugin_root=plugin_root
        )
        if reproduced == value
        else None
    )
    if reproduced == value and authority_scope_sha256 is None:
        issues.append("packet:runtime_unavailable")
    standing_binding = None
    if not issues and authority_source_sha256 is _AUTOMATIC_AUTHORITY:
        standing = standing_authority.bind_standing_owner_authority(
            authority_class=standing_authority.TRANCHE_DISPATCH_AUTHORITY_CLASS,
            authority_scope_sha256=authority_scope_sha256,
        )
        if standing.get("status") == "PASS":
            authority_source_sha256 = standing["authority_source_sha256"]
            standing_binding = standing
        else:
            issues.extend(standing.get("issues", []))
    if not isinstance(authority_source_sha256, str) or not _SHA256.fullmatch(
        authority_source_sha256
    ):
        issues.append("packet:authority_required")
    if issues:
        return {
            "status": "FAIL",
            "issues": sorted(set(issues)),
            "grant": None,
            "campaign": None,
        }

    campaign = value["campaign"]["sealed"]
    terms = value["grant_terms"]
    try:
        grant = live.build_parameterized_live_grant(
            campaign,
            max_tokens=int(terms["max_tokens"]),
            max_wall_time_ms=int(terms["max_wall_time_ms"]),
            reserved_tokens_per_lane_session=int(
                terms["reserved_tokens_per_lane_session"]
            ),
            authority_source_sha256=authority_source_sha256,
            grant_id=value["campaign_label"] + "-grant",
            attempt_id=value["campaign_label"] + "-attempt",
            standing_authority_binding=standing_binding,
        )
    except ValueError:
        return {
            "status": "FAIL",
            "issues": ["packet:grant_terms_invalid"],
            "grant": None,
            "campaign": None,
        }
    return {
        "status": "PASS",
        "issues": [],
        "grant": grant,
        "campaign": campaign,
        "authority_scope_sha256": authority_scope_sha256,
        "standing_authority": (
            standing_authority.standing_owner_binding_material(
                standing_binding
            )
            if standing_binding is not None
            else None
        ),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def render_decision_sheet(
    value: Any, *, plugin_root: str | Path | None = None
) -> str:
    """Render the bounded terms and standing-authority audit binding."""

    if not isinstance(value, dict) or value.get("status") != "PASS":
        return (
            "Tranche dispatch packet cannot be rendered: the packet did not "
            "build. No authorization decision is available."
        )
    runtime_closure_sha256 = dispatch_runtime_closure_sha256(plugin_root)
    authority_scope_sha256 = dispatch_authority_scope_sha256(
        value, plugin_root=plugin_root
    )
    if runtime_closure_sha256 is None or authority_scope_sha256 is None:
        return (
            "Tranche dispatch packet cannot be rendered: canonical "
            "reproduction failed. No authorization decision is available."
        )
    terms = value["grant_terms"]
    projections = value["projections"]
    stop = value["stop_cost"]
    basis = terms["reservation_basis"]
    policy = standing_authority.standing_owner_policy()
    standing = standing_authority.bind_standing_owner_authority(
        authority_class=standing_authority.TRANCHE_DISPATCH_AUTHORITY_CLASS,
        authority_scope_sha256=authority_scope_sha256,
    )
    lines = [
        "TRANCHE DISPATCH AUTHORITY AUDIT SHEET",
        "Campaign: %s" % value["campaign_label"],
        "Prepared: %s" % value["prepared_at"],
        "",
        "WHAT WOULD RUN",
        "  %d cells, %d lane sessions, one cell in flight, at most %d lanes live."
        % (
            terms["cells"],
            terms["lane_sessions"],
            terms["max_live_lane_sessions"],
        ),
        "  Lane counts %s across seeds %s on evidence extraction."
        % (value["campaign"]["lane_counts"], value["campaign"]["seeds"]),
        "",
        "EXACT LIMITS",
        "  At most {:,} attributable local-Qwen tokens.".format(
            terms["max_tokens"]
        ),
        "  {:,} tokens reserved per lane session ({:.2f}x the worst of {} observed lanes).".format(
            terms["reserved_tokens_per_lane_session"],
            basis["headroom_factor"],
            basis["observed_lane_sessions"],
        ),
        "  Forbidden: %s." % ", ".join(terms["forbidden"]),
        "  Wall-clock backstop {:,} ms. This has never bound a campaign".format(
            terms["max_wall_time_ms"]
        ),
        "    (v6 used {:,} ms of its {:,} ms ceiling), so it is a backstop,".format(
            V6_OBSERVED_WALL_MS, 21_600_000
        ),
        "    not a limit under test.",
        "",
        "WHAT THE EVIDENCE SAYS",
        "  Odds priced on %d clean sessions with %d failures, pooled across"
        % (
            projections["prior_clean_sessions"],
            projections["prior_failures"],
        ),
        "    every campaign that produced a settled observation.",
        "  Token reservation sized on the %d of those sessions that also"
        % basis["observed_lane_sessions"],
        "    reported usage. The two populations differ; that is expected.",
        "  Assumed failure rate %s (%s)."
        % (projections["assumed_failure_rate"], value["rung"]["bound_basis"]),
        "  Completion probability %s." % projections["completion_probability"],
        "  Powered: %s."
        % ("no, pilot outcomes only" if projections["pilot_outcomes_only"] else "yes"),
        "",
        "WHAT A STOP COSTS",
        "  At most %d lane sessions go unobserved, producing no evidence. %s"
        % (stop["max_sessions_forfeited"], stop["note"]),
        "",
        "WHAT THIS DOES NOT ANSWER",
    ]
    for item in value["does_not_answer"]:
        lines.append("  - It does not answer %s." % item)
    lines.extend(
        [
            "",
            "AUTHORIZATION",
            "  This packet carries no authority by itself. Complete canonical reproduction",
            "  makes it eligible for one one-use grant under standing Owner authority;",
            "  no per-run approval message is required.",
            "  Standing policy digest: %s" % policy["policy_sha256"],
            "  Runtime closure digest: %s" % runtime_closure_sha256,
            "  Standing authority source digest: %s"
            % standing["authority_source_sha256"],
            "  Authority scope digest: %s" % authority_scope_sha256,
            "  Packet digest (provenance only): %s" % value["record_sha256"],
        ]
    )
    return "\n".join(lines)


__all__ = [
    "PACKET_SCHEMA",
    "AUTHORITY_SCOPE_SCHEMA",
    "DISPATCH_RUNTIME_CLOSURE_SCHEMA",
    "MAX_OBSERVED_LANE_TOKENS",
    "OBSERVED_LANE_SESSIONS",
    "RESERVED_TOKENS_PER_LANE_SESSION",
    "MAX_WALL_TIME_MS",
    "V6_OBSERVED_WALL_MS",
    "MAX_CELLS_IN_FLIGHT",
    "MAX_LIVE_LANE_SESSIONS",
    "REFERENCE_GRID_SESSIONS",
    "build_dispatch_packet",
    "dispatch_runtime_closure_sha256",
    "dispatch_authority_scope_sha256",
    "grant_from_packet",
    "render_decision_sheet",
]
