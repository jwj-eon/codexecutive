#!/usr/bin/env python3
"""Standing authority and plan admission for governed runs (Issue 194, FR69).

Standing authority set at enrollment is the default (ADR 0011): it names the
worker limit, the per-run and daily cost limits, the allowed Workflow
Profiles, the role lineup, and whether every run asks first.  A frozen plan
within those limits starts at once with a notice; a plan beyond any of them
asks, naming each limit it exceeds; while fewer than two different models
have passed onboarding, or a named model has not, it is refused with the
reasons the profiles record (ADR 0012).

Under ADR 0002 the authority is one closed, versioned record.  An admission
binds its digest to the digest of the exact frozen plan, and the run it
starts consumes it once.  An approval answers one question: the ask names
the plan, every limit it exceeded and the day, and an approval of it starts
that plan once, that day, within the hour, while no other limit is exceeded.

Billing is usually not observable: Codex and OpenCodex record tokens, never
dollars.  A plan therefore carries a cost budget, the per-run limit unless it
asks for more, and the daily limit counts every budget admitted that day in
full until a run's actual cost is observed.  Nothing here turns a token
count into a dollar figure.

The module is pure: it reads no file, starts no process and calls no model.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import orch_dork_workflow_profiles as workflow_profiles  # noqa: E402


AUTHORITY_SCHEMA = "orch-dork/governed-standing-authority/v1"
PLAN_SCHEMA = "orch-dork/governed-run-plan/v1"
ADMISSION_SCHEMA = "orch-dork/governed-run-admission/v1"
ASK_SCHEMA = "orch-dork/governed-run-ask/v1"

WORKFLOW_PROFILES = tuple(workflow_profiles.PROFILE_IDS)
# A zero-worker governed run is one direct execution that Orch Dork verifies.
ZERO_WORKER_PROFILE = "direct/v1"
# A run with one lane worker executes, is verified, and gets at most one
# repair round; two or more lanes run in parallel and are joined (Issue 195).
ONE_LANE_PROFILE = "execute_verify_repair/v1"
LANES_PROFILE = "parallel_join/v1"
DEFAULT_ALLOWED_PROFILES = ("direct/v1", "execute_verify_repair/v1", "parallel_join/v1")
DEFAULT_WORKERS = 4
MAX_WORKERS = 8
DEFAULT_PER_RUN_CENTS = 200
DEFAULT_DAILY_CENTS = 1_000
MAX_CENTS = 100_000
ROLES = ("planner", "implementer", "reviewer")
PRESETS = ("cheap", "balanced", "local", "custom")
DECISIONS = ("START", "ASK", "REFUSED")
# How long the user's answer to one question stays usable.
APPROVAL_LIFETIME_MINUTES = 60
# Every limit a plan can exceed, in the order a question names them.
LIMITS = (
    "per_run_approval", "workers", "workflow_profile", "role_lineup", "per_run_cost", "daily_cost",
)
_AUTHORITY_FIELDS = frozenset({
    "schema", "workers_max", "per_run_cost_cents", "daily_cost_cents",
    "allowed_workflow_profiles", "role_lineup", "per_run_approval", "keep_local", "billing",
    "authority_sha256",
})
_LINEUP_FIELDS = frozenset({"preset", "planner", "implementer", "reviewer"})
_PLAN_FIELDS = frozenset({
    "schema", "enrollment_sha256", "summary_sha256", "workflow_profile", "workers",
    "models", "effort", "budget_cents", "plan_sha256",
})
_ASK_FIELDS = frozenset({
    "schema", "plan_sha256", "limits", "local_date", "asked_at", "requesting_thread_id", "ask_sha256",
})
_MODEL = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_DATE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")


class AdmissionError(ValueError):
    """An authority or plan value that cannot be admitted, by its named field."""


def workflow_profile_for(workers: int) -> str:
    """The Workflow Profile of a governed run with this many lane workers."""

    if type(workers) is not int or not 0 <= workers <= MAX_WORKERS:
        raise AdmissionError("plan:invalid")
    return ZERO_WORKER_PROFILE if workers == 0 else ONE_LANE_PROFILE if workers == 1 else LANES_PROFILE


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sealed(core: Mapping[str, Any], field: str) -> dict[str, Any]:
    value = {key: item for key, item in core.items() if key != field}
    return {**value, field: sha256(value)}


def seal_valid(value: Any, field: str) -> bool:
    return bool(
        isinstance(value, Mapping)
        and value.get(field) == sha256({key: item for key, item in value.items() if key != field})
    )


# ---------------------------------------------------------------- money


def cents(value: Any, *, field: str) -> int:
    """A positive dollar amount, as the user states it, in whole cents."""

    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise AdmissionError(field + ":invalid")
    text = str(value).strip()
    if text.startswith("$"):
        text = text[1:].strip()
    try:
        amount = Decimal(text)
    except InvalidOperation as error:
        raise AdmissionError(field + ":invalid") from error
    if not amount.is_finite() or amount <= 0:
        raise AdmissionError(field + ":invalid")
    result = int((amount * 100).quantize(Decimal(1), rounding=ROUND_HALF_UP))
    if not 1 <= result <= MAX_CENTS:
        raise AdmissionError(field + ":out_of_range")
    return result


def dollars(value: int) -> str:
    return "$" + str(value // 100) + "." + format(value % 100, "02d")


# ---------------------------------------------------------------- lineups


def lineup_presets(
    chat_model: str, second_model: str, *, local_models: Sequence[str] = (),
) -> dict[str, dict[str, str]]:
    """The suggested lineups over the two enrolled models (ADR 0012).

    Cheap is the default: the model the user chats with plans and reviews and
    the second model writes the code.  Balanced keeps the chat model on the
    code and has the second model review it.  Local is offered only when two
    local models are available; it is what a project kept on this machine
    uses.  In every preset the reviewer differs from the model that writes
    the code.
    """

    presets = {
        "cheap": {
            "planner": chat_model, "implementer": second_model, "reviewer": chat_model,
            "description": chat_model + " plans and reviews; " + second_model + " writes the code.",
        },
        "balanced": {
            "planner": chat_model, "implementer": chat_model, "reviewer": second_model,
            "description": chat_model + " plans and writes the code; " + second_model + " reviews it.",
        },
    }
    local = list(dict.fromkeys(model for model in local_models if isinstance(model, str)))
    if len(local) >= 2:
        presets["local"] = {
            "planner": local[0], "implementer": local[1], "reviewer": local[0],
            "description": "Local models only: " + local[0] + " plans and reviews; "
            + local[1] + " writes the code.",
        }
    return presets


# ---------------------------------------------------------------- authority


def build_authority(
    *,
    workers_max: int,
    per_run_cost_cents: int,
    daily_cost_cents: int,
    allowed_workflow_profiles: Sequence[str],
    lineup: Mapping[str, Any],
    per_run_approval: bool,
    keep_local: bool,
) -> dict[str, Any]:
    """One sealed standing-authority record, refused by its first invalid field."""

    allowed = set(allowed_workflow_profiles) if isinstance(allowed_workflow_profiles, (list, tuple, set)) else None
    core = {
        "schema": AUTHORITY_SCHEMA,
        "workers_max": workers_max,
        "per_run_cost_cents": per_run_cost_cents,
        "daily_cost_cents": daily_cost_cents,
        "allowed_workflow_profiles": (
            [profile for profile in WORKFLOW_PROFILES if profile in allowed] if allowed is not None else None
        ),
        "role_lineup": {key: lineup.get(key) for key in sorted(_LINEUP_FIELDS)} if isinstance(lineup, Mapping) else None,
        "per_run_approval": per_run_approval,
        "keep_local": keep_local,
        "billing": "budget_reserved",
    }
    if allowed is not None and not allowed <= set(WORKFLOW_PROFILES):
        raise AdmissionError("allowed_workflow_profiles:unknown")
    value = sealed(core, "authority_sha256")
    issues = authority_issues(value)
    if issues:
        raise AdmissionError(issues[0])
    return value


def authority_issues(value: Any) -> list[str]:
    """Why a standing-authority record is not valid; empty when it is."""

    if not isinstance(value, Mapping) or set(value) != _AUTHORITY_FIELDS:
        return ["authority:shape"]
    issues = []
    if value.get("schema") != AUTHORITY_SCHEMA:
        issues.append("authority:schema")
    workers = value.get("workers_max")
    if type(workers) is not int or not 1 <= workers <= MAX_WORKERS:
        issues.append("workers_max:out_of_range")
    per_run, daily = value.get("per_run_cost_cents"), value.get("daily_cost_cents")
    for field, amount in (("per_run_cost", per_run), ("daily_cost", daily)):
        if type(amount) is not int or not 1 <= amount <= MAX_CENTS:
            issues.append(field + ":out_of_range")
    if type(per_run) is int and type(daily) is int and daily < per_run:
        issues.append("daily_cost:below_per_run_cost")
    profiles = value.get("allowed_workflow_profiles")
    if (
        not isinstance(profiles, list)
        or not profiles
        or len(set(profiles)) != len(profiles)
        or any(profile not in WORKFLOW_PROFILES for profile in profiles)
    ):
        issues.append("allowed_workflow_profiles:invalid")
    lineup = value.get("role_lineup")
    if not isinstance(lineup, Mapping) or set(lineup) != _LINEUP_FIELDS:
        issues.append("role_lineup:shape")
    else:
        if lineup.get("preset") not in PRESETS:
            issues.append("role_lineup:preset")
        if any(not isinstance(lineup.get(role), str) or not _MODEL.fullmatch(lineup[role]) for role in ROLES):
            issues.append("role_lineup:model")
        elif lineup["implementer"] == lineup["reviewer"]:
            issues.append("role_lineup:reviewer_wrote_the_code")
    for field in ("per_run_approval", "keep_local"):
        if not isinstance(value.get(field), bool):
            issues.append(field + ":invalid")
    if value.get("billing") != "budget_reserved":
        issues.append("authority:billing")
    if not issues and not seal_valid(value, "authority_sha256"):
        issues.append("authority:seal")
    return issues


# ---------------------------------------------------------------- plans


def build_plan(
    *,
    enrollment_sha256: str,
    summary_sha256: str,
    workflow_profile: str,
    workers: int,
    models: Mapping[str, str],
    effort: str,
    budget_cents: int,
) -> dict[str, Any]:
    """The frozen plan an admission and its run both bind by digest."""

    core = {
        "schema": PLAN_SCHEMA,
        "enrollment_sha256": enrollment_sha256,
        "summary_sha256": summary_sha256,
        "workflow_profile": workflow_profile,
        "workers": workers,
        "models": {role: models[role] for role in ROLES if role in models},
        "effort": effort,
        "budget_cents": budget_cents,
    }
    if (
        not all(isinstance(core[field], str) and _SHA256.fullmatch(core[field])
                for field in ("enrollment_sha256", "summary_sha256"))
        or workflow_profile not in WORKFLOW_PROFILES
        or type(workers) is not int or not 0 <= workers <= MAX_WORKERS
        or not core["models"]
        or set(models) - set(ROLES)
        or any(not isinstance(model, str) or not _MODEL.fullmatch(model) for model in core["models"].values())
        or type(budget_cents) is not int or not 1 <= budget_cents <= MAX_CENTS
    ):
        raise AdmissionError("plan:invalid")
    return sealed(core, "plan_sha256")


# ---------------------------------------------------------------- admission


def _exceeded(plan: Mapping[str, Any], authority: Mapping[str, Any], reserved: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if authority["per_run_approval"]:
        rows.append({"limit": "per_run_approval", "allowed": None, "requested": None,
                     "text": "you asked to approve every governed run before it starts"})
    if plan["workers"] > authority["workers_max"]:
        rows.append({"limit": "workers", "allowed": authority["workers_max"], "requested": plan["workers"],
                     "text": "the plan uses " + str(plan["workers"]) + " workers and your limit is "
                     + str(authority["workers_max"])})
    if plan["workflow_profile"] not in authority["allowed_workflow_profiles"]:
        rows.append({"limit": "workflow_profile", "allowed": list(authority["allowed_workflow_profiles"]),
                     "requested": plan["workflow_profile"],
                     "text": "the plan's workflow " + plan["workflow_profile"] + " is not one you allowed ("
                     + ", ".join(authority["allowed_workflow_profiles"]) + ")"})
    for role, model in plan["models"].items():
        expected = authority["role_lineup"][role]
        if model != expected:
            rows.append({"limit": "role_lineup", "allowed": expected, "requested": model, "role": role,
                         "text": "the plan runs " + model + " as the " + role + " and your lineup names "
                         + expected})
    if plan["budget_cents"] > authority["per_run_cost_cents"]:
        rows.append({"limit": "per_run_cost", "allowed": authority["per_run_cost_cents"],
                     "requested": plan["budget_cents"],
                     "text": "the plan's budget is " + dollars(plan["budget_cents"])
                     + " and your per-run limit is " + dollars(authority["per_run_cost_cents"])})
    if reserved + plan["budget_cents"] > authority["daily_cost_cents"]:
        rows.append({"limit": "daily_cost", "allowed": authority["daily_cost_cents"],
                     "requested": plan["budget_cents"], "committed": reserved,
                     "text": dollars(reserved) + " of today's " + dollars(authority["daily_cost_cents"])
                     + " limit is already committed, and this plan's " + dollars(plan["budget_cents"])
                     + " budget would go past it"})
    order = list(LIMITS)
    return sorted(rows, key=lambda row: order.index(row["limit"]))


def build_ask(decision: Mapping[str, Any], *, asked_at: str, requesting_thread_id: str | None) -> dict[str, Any]:
    """The question one ASK decision puts to the user, which an approval names.

    It records the plan, every limit the question names and the day it was
    asked, so an approval starts that plan once, that day, and only while no
    limit beyond the ones the user saw is exceeded.
    """

    if not seal_valid(decision, "admission_sha256") or decision.get("decision") != "ASK":
        raise AdmissionError("ask:invalid")
    return sealed({
        "schema": ASK_SCHEMA,
        "plan_sha256": decision["plan_sha256"],
        "limits": [row["limit"] for row in decision["exceeded"]],
        "local_date": decision["local_date"],
        "asked_at": asked_at,
        "requesting_thread_id": requesting_thread_id,
    }, "ask_sha256")


def ask_open(ask: Any, *, now: datetime, requesting_thread_id: str | None) -> bool:
    """Whether a recorded question can still be answered: by the task it was
    put to, within APPROVAL_LIFETIME_MINUTES of asking it."""

    if (
        not isinstance(ask, Mapping)
        or ask.get("schema") != ASK_SCHEMA
        or not seal_valid(ask, "ask_sha256")
        or ask.get("requesting_thread_id") != requesting_thread_id
    ):
        return False
    try:
        asked = datetime.strptime(str(ask.get("asked_at")), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return timedelta(0) <= now.astimezone(timezone.utc) - asked <= timedelta(minutes=APPROVAL_LIFETIME_MINUTES)


def approval_covers(
    ask: Any, plan: Mapping[str, Any], exceeded: Sequence[Mapping[str, Any]], local_date: str,
) -> bool:
    """Whether the question the user approved still covers this plan today."""

    return bool(
        exceeded
        and isinstance(ask, Mapping)
        and set(ask) == _ASK_FIELDS
        and ask.get("schema") == ASK_SCHEMA
        and seal_valid(ask, "ask_sha256")
        and ask.get("plan_sha256") == plan["plan_sha256"]
        and ask.get("local_date") == local_date
        and isinstance(ask.get("limits"), list)
        and {row["limit"] for row in exceeded} <= set(ask["limits"])
    )


def admit(
    plan: Mapping[str, Any],
    authority: Mapping[str, Any],
    *,
    reserved_today_cents: int,
    local_date: str,
    onboarding: Mapping[str, Any],
    approval: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare one frozen plan with the standing authority.

    START when the plan is within every limit, or exceeds some and the user
    approved the question that named them today (approval is that ask
    record); ASK when it exceeds a limit without such an approval, naming
    each one; REFUSED while the onboarding admission the profiles give is
    refused, whatever the limits say.  The daily limit counts the budgets
    already admitted today in full.
    """

    if not seal_valid(plan, "plan_sha256") or set(plan) != _PLAN_FIELDS or plan.get("schema") != PLAN_SCHEMA:
        raise AdmissionError("plan:seal")
    issues = authority_issues(authority)
    if issues:
        raise AdmissionError(issues[0])
    if type(reserved_today_cents) is not int or reserved_today_cents < 0:
        raise AdmissionError("reserved_today:invalid")
    if not isinstance(local_date, str) or not _DATE.fullmatch(local_date):
        raise AdmissionError("local_date:invalid")
    if not isinstance(onboarding, Mapping) or onboarding.get("status") not in ("ADMITTED", "REFUSED"):
        raise AdmissionError("onboarding:invalid")
    exceeded = _exceeded(plan, authority, reserved_today_cents)
    refusals = sorted(str(issue) for issue in onboarding.get("issues") or [])
    approved = approval_covers(approval, plan, exceeded, local_date)
    if onboarding["status"] != "ADMITTED" or refusals:
        decision = "REFUSED"
    elif exceeded and not approved:
        decision = "ASK"
    else:
        decision = "START"
    core = {
        "schema": ADMISSION_SCHEMA,
        "decision": decision,
        "approved": approved,
        "approval_sha256": approval["ask_sha256"] if approved and approval is not None else None,
        "exceeded": exceeded,
        "refusals": refusals,
        "plan_sha256": plan["plan_sha256"],
        "authority_sha256": authority["authority_sha256"],
        "onboarding_sha256": onboarding.get("report_sha256"),
        "budget_cents": plan["budget_cents"],
        "reserved_today_cents": reserved_today_cents,
        "local_date": local_date,
        "billing": "unknown",
    }
    return sealed(core, "admission_sha256")


def refusal_sentence(issue: str) -> str:
    """A user-facing sentence for one onboarding refusal the profiles give."""

    kind, _, rest = issue.partition(":")
    if kind == "onboarding_minimum_unmet":
        return "governed runs need two different models that passed onboarding; " + rest + " has"
    if kind == "model_not_onboarded":
        return rest + " has not been onboarded yet"
    if kind == "model_not_passed":
        model, _, reason = rest.rpartition(":")
        model, _, detail = model.partition(":")
        return model + " has not passed onboarding (" + (detail + ":" + reason if detail else reason) + ")"
    if kind == "model_not_local":
        return rest + " is not a local model, and this project is kept on your machine"
    return issue


# ---------------------------------------------------------------- notices


def _label(text: str) -> str:
    return text.replace("\\", "/").replace('"', "'").replace("\n", " ")[:120]


def plan_diagram(
    plan: Mapping[str, Any], checks: Sequence[Mapping[str, Any]],
    lanes: Sequence[Mapping[str, Any]] = (),
) -> str:
    """The plan as a Mermaid flowchart the requesting task can show.

    A zero-worker run is the governed task, the project's checks and the
    verdict.  A run with lanes fans out to one worker per lane, checks each
    lane, runs the project's checks on the joined tree, and shows the one
    repair round a failed check gets before the verdict.
    """

    models = plan["models"]
    root = models.get("planner") or models.get("implementer") or next(iter(models.values()))
    lines = [
        "flowchart LR",
        '  ask["Your task"] --> run["Governed task: ' + _label(root) + " (" + _label(plan["effort"])
        + "), " + str(plan["workers"]) + ' workers"]',
    ]
    previous = ["run"]
    if lanes:
        worker = models.get("implementer") or root
        previous = []
        for lane in lanes:
            node = "lane_" + re.sub(r"[^A-Za-z0-9]", "_", str(lane["id"]))
            argv = "; ".join(" ".join(check["argv"]) for check in lane.get("checks") or [])
            lines.append("  run --> " + node + '["Lane ' + _label(str(lane["id"])) + ": "
                         + _label(worker) + '"]')
            lines.append("  " + node + " --> " + node + '_checks["Orch Dork checks lane '
                         + _label(str(lane["id"])) + ": " + _label(argv) + '"]')
            previous.append(node + "_checks")
    for index, check in enumerate(checks, 1):
        node = "check" + str(index)
        label = ('["Orch Dork runs ' + _label(str(check["id"])) + ": " + _label(" ".join(check["argv"]))
                 + (" on the joined tree" if lanes else "") + '"]')
        for position, source in enumerate(previous):
            lines.append("  " + source + " --> " + node + (label if position == 0 else ""))
        previous = [node]
    for position, source in enumerate(previous):
        lines.append("  " + source + " --> verdict" + ('["Verdict"]' if position == 0 else ""))
    if lanes:
        lines.append("  " + previous[-1] + ' -.->|a check fails| repair["One repair round, then every check again"]')
        lines.append("  repair --> verdict")
    return "\n".join(lines)


def ask_text(admission: Mapping[str, Any]) -> str:
    reasons = "; ".join(row["text"] for row in admission["exceeded"])
    return (
        "This governed run needs your approval before it starts: " + reasons + ". "
        "Say so and I will start exactly this plan (" + admission["plan_sha256"][:12] + ") once; "
        "the approval lapses after " + str(APPROVAL_LIFETIME_MINUTES) + " minutes or at the end of the day."
    )


def refusal_text(admission: Mapping[str, Any]) -> str:
    return (
        "Governed runs are refused for now: "
        + "; ".join(refusal_sentence(issue) for issue in admission["refusals"])
        + ". Orch Dork's advisory features keep working."
    )


def start_text(admission: Mapping[str, Any], authority: Mapping[str, Any]) -> str:
    committed = admission["reserved_today_cents"] + admission["budget_cents"]
    within = "it was approved" if admission["approved"] else "it is within your standing limits"
    return (
        "Started because " + within + ". Billing is not observable here, so its "
        + dollars(admission["budget_cents"]) + " budget counts in full against today's "
        + dollars(authority["daily_cost_cents"]) + " limit (" + dollars(committed) + " committed today)."
    )
