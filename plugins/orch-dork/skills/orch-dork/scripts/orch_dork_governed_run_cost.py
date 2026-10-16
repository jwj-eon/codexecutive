#!/usr/bin/env python3
"""The cost summary every governed run ends with (Issue 195, FR69).

Codex reports token usage per thread and never a price, and neither
OpenCodex nor the model catalog carries one, so a run's billing is unknown
and is reported as unknown: no token count here is turned into a dollar
figure, and cumulative or cached counts are labeled as token counts.

The summary names each role's usage from the per-thread totals the
watcher's owner connection observed (the governed task's root and every lane
or repair worker it spawned), the limits the run ran under (its reserved
budget, the daily limit, its workers and the machine-wide worker cap), and a
frontier-only savings estimate, labeled as an estimate and counted in
tokens: the work that ran on models other than the frontier model the user
chats with, which a frontier-only run would have sent to that model.

The module is pure: it reads no file, starts no process and calls no model.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence


SCHEMA = "orch-dork/governed-run-cost-summary/v1"
ROLES = ("planner", "implementer", "reviewer")
TOKEN_FIELDS = ("input", "cached_input", "output", "reasoning_output", "total")
# Codex's thread/tokenUsage/updated names, by the summary's names.
_USAGE_KEYS = (
    ("inputTokens", "input"),
    ("cachedInputTokens", "cached_input"),
    ("outputTokens", "output"),
    ("reasoningOutputTokens", "reasoning_output"),
    ("totalTokens", "total"),
)
_MAX_TOKENS = 10 ** 12


def thread_totals(token_usage: Any) -> dict[str, int] | None:
    """One thread's cumulative totals from a thread/tokenUsage/updated payload.

    None when the payload does not carry every count as a non-negative
    integer; a partial count is never completed by guessing.
    """

    total = token_usage.get("total") if isinstance(token_usage, Mapping) else None
    if not isinstance(total, Mapping):
        return None
    totals: dict[str, int] = {}
    for key, name in _USAGE_KEYS:
        value = total.get(key)
        if type(value) is not int or not 0 <= value <= _MAX_TOKENS:
            return None
        totals[name] = value
    return totals


def _dollars(cents: Any) -> str | None:
    if type(cents) is not int or cents < 0:
        return None
    return "$" + str(cents // 100) + "." + format(cents % 100, "02d")


def _empty() -> dict[str, int]:
    return {name: 0 for name in TOKEN_FIELDS}


def cost_summary(
    *,
    threads: Sequence[Mapping[str, Any]],
    usage: Mapping[str, Any],
    frontier_model: str | None,
    budget_cents: Any,
    daily_cents: Any,
    run_workers: int,
    machine_workers: int,
) -> dict[str, Any]:
    """The run's cost summary from its threads and their observed totals.

    threads lists every thread the run used, each with its role, model and,
    for a worker, its lane; usage maps a thread id to its totals from
    thread_totals, or to None when Codex reported none for it.
    """

    per_role: dict[tuple[str, str], dict[str, Any]] = {}
    missing: list[str] = []
    on_frontier = _empty()
    elsewhere = _empty()
    for thread in threads:
        role = str(thread.get("role"))
        model = str(thread.get("model"))
        row = per_role.setdefault((role, model), {
            "role": role, "model": model, "threads": 0, "lanes": [], "tokens": _empty(),
            "observed_threads": 0,
        })
        row["threads"] += 1
        lane = thread.get("lane")
        if isinstance(lane, str) and lane not in row["lanes"]:
            row["lanes"].append(lane)
        totals = usage.get(str(thread.get("thread_id")))
        if not isinstance(totals, Mapping):
            missing.append(str(thread.get("thread_id")))
            continue
        row["observed_threads"] += 1
        bucket = on_frontier if frontier_model is not None and model == frontier_model else elsewhere
        for name in TOKEN_FIELDS:
            row["tokens"][name] += int(totals[name])
            bucket[name] += int(totals[name])
    if not threads or len(missing) == len(threads):
        usage_status = "unavailable"
    elif missing:
        usage_status = "partial"
    else:
        usage_status = "observed"
    roles = sorted(per_role.values(), key=lambda row: (
        ROLES.index(row["role"]) if row["role"] in ROLES else len(ROLES), row["model"],
    ))
    estimate = _estimate(frontier_model, on_frontier, elsewhere, usage_status)
    budget = _dollars(budget_cents)
    daily = _dollars(daily_cents)
    cap = {
        "per_run_budget": budget,
        "daily_limit": daily,
        "run_workers": run_workers,
        "machine_workers": machine_workers,
    }
    return {
        "schema": SCHEMA,
        "billing": "unknown",
        "actual_cost": "unknown",
        "usage_status": usage_status,
        "threads_without_usage": len(missing),
        "per_role": roles,
        "cap": cap,
        "estimate": estimate,
        "text": _text(roles, cap, estimate),
    }


def _estimate(
    frontier_model: str | None, on_frontier: Mapping[str, int], elsewhere: Mapping[str, int],
    usage_status: str,
) -> dict[str, Any]:
    if frontier_model is None or usage_status == "unavailable":
        return {
            "label": "estimate", "basis": "tokens", "status": "unknown",
            "frontier_model": frontier_model, "tokens_on_frontier_model": None,
            "tokens_moved_off_frontier_model": None,
            "text": "Estimate unavailable: Codex reported no token usage for this run.",
        }
    moved = int(elsewhere["total"])
    kept = int(on_frontier["total"])
    if moved:
        text = (
            "Estimate: " + format(moved, ",") + " tokens of this run's work ran on models "
            "other than " + frontier_model + ", which a frontier-only run would have sent to "
            + frontier_model + "; " + format(kept, ",") + " tokens ran on " + frontier_model
            + ". This is a token count, not a dollar figure."
        )
    else:
        text = (
            "Estimate: all " + format(kept, ",") + " tokens of this run ran on "
            + frontier_model + ", so it saved nothing against a frontier-only run."
        )
    if usage_status == "partial":
        text += " Some threads reported no usage, so the counts are lower bounds."
    return {
        "label": "estimate", "basis": "tokens",
        "status": "lower_bound" if usage_status == "partial" else "observed",
        "frontier_model": frontier_model,
        "tokens_on_frontier_model": kept,
        "tokens_moved_off_frontier_model": moved,
        "text": text,
    }


def _text(roles: Sequence[Mapping[str, Any]], cap: Mapping[str, Any], estimate: Mapping[str, Any]) -> str:
    parts = []
    for row in roles:
        if row["observed_threads"]:
            parts.append(
                row["role"] + " " + row["model"] + ": " + format(row["tokens"]["total"], ",")
                + " tokens over " + str(row["threads"]) + " thread" + ("s" if row["threads"] != 1 else "")
            )
        else:
            parts.append(row["role"] + " " + row["model"] + ": usage not reported")
    usage = "; ".join(parts) if parts else "no usage reported"
    limits = []
    if cap.get("per_run_budget"):
        limits.append(cap["per_run_budget"] + " budget reserved for this run")
    if cap.get("daily_limit"):
        limits.append("daily limit " + cap["daily_limit"])
    limits.append(str(cap["run_workers"]) + " of at most " + str(cap["machine_workers"])
                  + " workers on this machine")
    return (
        "Billing is not observable here, so the actual cost is unknown. Usage by role: "
        + usage + ". Limits: " + ", ".join(limits) + ". " + str(estimate["text"])
    )


__all__ = ["SCHEMA", "TOKEN_FIELDS", "cost_summary", "thread_totals"]
