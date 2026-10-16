---
name: orch-dork
description: Coordinate, run, and verify decomposable Codex work through a frozen subagent plan and host-computed verdicts. Use when the user explicitly asks to orchestrate, delegate, parallelize, use subagents, make orchestration the default, inspect an orchestration trace, work the ticket list, or run or verify work as a governed run; when applicable global or project instructions require observable delegation; or when the work is worth splitting into independently owned lanes or worth substantive independent verification.
---

# Orch Dork

Orch Dork turns suitable work into a bounded, observable delegation graph, runs it, and reports a verdict the host computes from observed evidence. It also keeps coherent work atomic and refuses work when required authority, evidence, routing, capacity, or safe ownership is unavailable.

This file is the entire first load, and it carries only decisions, boundaries, and entry points. Every procedure, wire schema, and exact gate semantic lives in a reference you load lazily, and no reference creates a second policy. A missing, malformed, stale, or inconsistent reference is a named unknown or refusal: never guess, fall back, or load another generation.

## When this skill triggers

Trigger on exactly one of:

- An explicit request to orchestrate, delegate, parallelize, use subagents, use
  Orch Dork, make orchestration the default, inspect an orchestration trace,
  work the ticket list, or run or verify work as a governed run.
- An applicable global or project instruction that requires observable
  delegation.
- Your own judgment that the work is worth splitting into at least two
  independently ownable lanes, or worth substantive independent verification by
  the project's own checks.

Ordinary chat, a direct answer, one coherent low-impact edit, and a bare keyword mention of orchestration do not trigger it.

Your judgment is a declaration you make before any evidence exists. The contract records it as a declared judgment input, never as model inference evidence, and it decides only whether to load this skill: it never stands in for a gate, a check, an observation, or a verdict. A judgment that names splitting requires at least two declared independently ownable lanes with disjoint writes; a judgment that names verification requires a declared substantive change and at least one named project check. Without those declarations, do not trigger.

A triggered request may still classify as atomic. "Not triggered" and "triggered, atomic" are different outcomes, and only the second runs ticket admission.

These rules decide new work in a requesting task. A task already bound to an admitted ticket, a frozen plan, an activated controller stage, or a qualification driver is past them: it continues through the journey and driver it already selected, and it never re-enters intake, drafts another summary, or starts a second run.

## Select the lifecycle journey

Before loading any reference, read the MCP resource `orch-dork://lifecycle` from the `orch-dork` server, choose the one journey whose `when` matches the request, and read only `orch-dork://lifecycle/<journey-id>`. For new work, continue through the public tool its `entry` names. For an existing run, use its `run_id` directly with the requested read, steer, revise or stop tool. Load only the skill sections and references that journey lists.

For a new request whose input is plain work or tickets in any format, that journey is the one whose `entry` is `prepare_work_summary`: its summary is what the run freezes. A task already executing an admitted or frozen plan keeps its own journey instead.

The requesting-task journey owns summary preparation and standing plan admission. The ticket-admission, advisory-scan, and native-controller procedures below belong to their own journeys; do not add those gates to a requesting-task start.

Lifecycle-bearing tool results carry one `orch-dork/agent-next-invocation/v1` projection beside the unchanged canonical report. Its `disposition` is exactly one of `INVOKE`, `AWAIT_EVIDENCE`, `AWAIT_DECISION`, `STOP`, or `TERMINAL`. `INVOKE` names one existing tool, operation, and input schema; build that input from canonical evidence yourself. The projection grants no authority, is never evidence or a receipt, and is refused if passed back as tool input. Where the two seem to differ, the canonical report governs.

If the resources are absent, a read or publication is refused, or a projection's `contract_generation_sha256` differs from the journey you read, stop with `LIFECYCLE_GUIDANCE_UNAVAILABLE`. Never guess the next step or load another generation's guidance.

## Contract map

Load only the reference the selected branch needs:

- [policy.md](references/policy.md) owns wire schemas and exact gate semantics.
- [execution.md](references/execution.md) owns native launch, controller,
  workspace, recovery, rollover, local-route, campaign, and handoff procedures.
- [project-ground.md](references/project-ground.md) owns enrollment, adapters,
  hooks, gateways, mutation authorization, and migration.
- [observability.md](references/observability.md) owns public evidence, privacy,
  dogfood records, and release boundaries.
- [contract-evaluation.md](references/contract-evaluation.md) owns the trigger
  and forward evaluations, the first-load budget, and source, staged, and
  installed generation checks.

## Intake and ticket lists

Input may be a plain request, a free-form ticket file, a supplied issue body, or tickets in any other format. Draft the goal, the lanes, and the checks yourself, then let the host own the summary:

- Intake is only for new work in the requesting task. Once a run is bound by admission, a frozen plan, an activated controller, or a qualification driver, that task stays on its selected journey to terminal; do not call `prepare_work_summary` or `start_governed_run` again to start a second run.
- Call `prepare_work_summary` with the arbitrary `input_text` plus your drafted goal and lanes, or with normalized ticket rows. A `PREPARED` result returns the work summary, its `summary_sha256`, the `intake_sha256`, and the `start_arguments` for the run.
- Show that returned summary in the requesting task before starting anything, then call `start_governed_run` with those `start_arguments` and the optional `intake_sha256`. The run and its plan bind the summary digest; raw input text is never the frozen object.
- Normalized ticket rows carry `id`, `status` of `ready`, `blocked`, or `complete`, `depends_on` ids, `writes` repository-relative paths, `goal`, and `checks` that name enrolled checks. The host selects ready rows with nonempty, disjoint write ownership in order and bundles them as lanes; each lane owns its row's `writes`, and the hook refuses a worker's write to another lane's paths. Empty ownership is skipped, including verification-only rows; it cannot grant a read-only lane. Completed dependency rows may have empty ownership. Do not pick lanes yourself, widen `writes`, or invent a check.
- Only after the host records Verified may you call `propose_ticket_status_update` with the `run_id` and `edits` of `{ticket_id, before, after}` against the unchanged optional ticket file. It returns the exact diff and a proposal hash to show the user.
- Apply it only with `confirm_ticket_status_update` carrying that exact `confirm_proposal_sha256` after the user explicitly confirms that proposal. Standing authority is never that confirmation, and no verdict other than Verified reaches this step.
- Nothing here calls GitHub. A supplied issue body is ordinary input text.

## Run governed work from this task

For local setup, model management, past runs or a live plan diagram, call
`open_local_ui` and share its expiring loopback link only in this task.
The packaged page needs no sign-in or external assets. It confirms setup,
standing-limit changes, onboarding probes and any opt-in that moves the user's
own Codex to V1; every run view is read-only and Stop stays in chat.
When the browser is on another of the user's own machines, pass
`view: "tailnet"` to open the same session through an existing Tailscale
Serve HTTPS mapping on the headless host. A `tailnet_mapping_missing`
refusal carries the one-time `tailscale serve --bg --https=8197
http://127.0.0.1:8197` command — show it and run only after the user
confirms; other tailnet refusals name what to fix, and never change
Tailscale beyond that command.
The chat path remains complete: use `enroll_project` and
`confirm_enrollment` for setup and settings, `onboard_model` for any listed
or typed model (with `re_onboard: true` only when requested), and
`read_onboarding` for results. Before probing, explain the short trivial task,
the user's login and token spend, and that no project content is sent.
Run views show canonical digests, evidence tiers, unknown facts and
contradictions; the host-local run record remains authoritative if a diagram
disagrees. Never treat the view as admission or proof of a successful check.

To enroll a project, call `enroll_project` with its root, show the user the proposal it returns, ask only what it lists, pass exactly the user's answers to `confirm_enrollment`, and follow onboarding with `read_onboarding`; never invent a check command.

For a new governed run in an enrolled project, prepare and show the summary as described in Intake and ticket lists, then call `start_governed_run` with its returned `start_arguments`. The lineup's implementer is `model` for zero workers; with lanes its planner is `model` and its implementer is `worker_model`. Each lane names enrolled checks, optionally narrowed by `selectors`. Within the standing limits it starts at once: show its notice and plan diagram. `APPROVAL_REQUIRED` names each exceeded limit; ask, and only on the user's yes call again with `approve_plan_sha256`. A refusal names the onboarding or self-test reason; offer the advisory run its `advisory_offer` describes and start it only after explicit confirmation, with no governed claim.

For an existing run, use its `run_id` directly with read, steer, revise or stop; preparation and start apply only to new work. Call `read_governed_run` until `TERMINAL`, then report the verdict, reason, check results, each lane's result, any repair round, the cost summary, and the record location as given: Verified, Failed checks, Interrupted — not verified, Stopped by you, or Refused. Those come from the checks Orch Dork ran and the hooks' and owner connection's records, never from the governed task's own claims. Steer with `steer_governed_run` using the user's exact words; direct typing in the governed task is recorded too. Show any revision offer and call `revise_governed_run` only on explicit acceptance, passing an exact `approve_plan_sha256` when the revision exceeds standing limits. When the user says stop, call `stop_governed_run`. Orch Dork's hooks pass every task they do not govern through unchanged; see [project-ground.md](references/project-ground.md).

## Improve project defaults

Use the `project-improvements` journey when the user asks to improve this project's Workflow Profile, worker count or role models. Read [project-improvements.md](references/project-improvements.md) for the evidence and promotion path. Show the exact proposal, its supporting and contradicting runs and any coupled changes before asking for approval. Approval, canary approval and adoption are separate explicit decisions; standing run authority supplies none. No current run changes its own policy. Adopted defaults fill omitted choices in new work; explicit choices win, and a failed adopted run suspends defaults at the next host intake.

## Choose the branch

Classify before the first implementation mutation:

- **Atomic:** one coherent operation, tightly coupled shared state, a direct
  answer, or coordination cost greater than the benefit. Root-owned, zero
  workers, no orchestration trace.
- **Orchestrated:** at least two independently verifiable lanes with disjoint
  ownership that can later be joined deterministically.
- **Refused:** required authority, evidence, model, capacity, or ownership is
  unavailable.

For every substantive triggered ticket, call `evaluate_ticket_admission` with fresh `classification-policy/v2` evidence, then `audit_orchestration_classification`. Continue only from `ATOMIC_ADMITTED` (execute in root; worker count zero, trace not applicable) or `ORCHESTRATION_PLAN_REQUIRED` (root implementation blocked until every pre-spawn gate passes). `REFUSED` and `RECLASSIFICATION_REQUIRED` stop before mutation. Ticket, scope, criteria, authority, prerequisite, resource, root, or classification changes require fresh ticket admission. Bind the admission hash to the first mutation and completion.

`recommend_first_wave` before an initial freeze and `record_wave_outcome` after a realized outcome are advice and feedback only: neither freezes a plan, consults capacity, alters a ceiling, permits workers, or grants authority.

Before any two-plus-lane freeze or expansion, call `evaluate_split_decision`. Require explicit contracts, independently verifiable acceptance, disjoint ownership, an acyclic graph, and a Sol join regardless of the recommendation. Shared mutable or strict serial state stays atomic. One-worker work stays with Sol. The soft cap is four; larger graphs need deterministic shards, distinct evidence channels, or named heterogeneous capability gain. Elapsed time alone never assigns work to root.

## Select the evidence mode

Ordinary invocation is `mode: advisory`. It may classify, freeze, validate, coordinate, observe bounded native files, and report completed work. It cannot intercept native completion or issue terminal qualification.

Use `mode: governed` only when the host-owned `GovernedNativeController.advance` seam or an independently qualified equivalent owns exact native-action state as the single execution owner. It consumes staged governed-attempt reports, commits shared capacity, and materializes the hook binding; a read-only MCP response is never enforcement.

Keep `advisory`, `controller_ready`, `runtime_observed`, and `terminally_qualified` distinct. Submitted conformance and provider-free fixtures never become terminal facts.

## Verify routing and authority

Require native collaboration tools and every selected evaluator. Use the stdio launcher in [execution.md](references/execution.md) only when the session tool route is unavailable; never silently switch policy.

Resolve root model, effort, turn, and collaboration surface from authoritative current-turn evidence through `observe_current_orchestration_route`: it reads the exact current `session_meta` and `turn_context` and reports `root_route_evidence_tier`, `worker_route_evidence_tier`, and `worker_route_verified`. Never infer root routing from defaults, catalogs, callers, or earlier runs. A live attempt that awaits separate human approval uses `evaluate_live_route_handoff`: persist the whole `READY_FOR_HUMAN_AUTHORIZATION` report from `prepare`, call `authorize` on the distinct approval turn with that report unchanged, and re-observe with the returned `dispatch_route_identity_sha256` as `expected_identity_sha256` before the first live effect and every downstream gate.

Any model the user's Codex can spawn may fill any role once onboarded (ADR 0012): a root is admitted when it is a registered orchestrator or has an onboarded profile, and a node names an onboarded model as `<role>.onboarded:<model>` or `<role>.onboarded.<effort>:<model>` whose profile digest the frozen plan binds; a model without a profile is a named onboarding step before freeze (`model_not_onboarded`). Every governed task runs on V1: another surface refuses `routing:root_surface_not_v1:<reason>` and a profile that cannot reach V1 refuses `model_cannot_reach_v1:<reason>`. Governed runs need two different onboarded models; a review whose independence is required is labeled `same_family` or `family_unknown`, never refused. The registry's root-model/surface matrix judges only historical replay, and no environment variable admits or re-surfaces a root. Sol/V2 and Astra/V2 are `RESTART_REQUIRED`; surfaces cannot change in place, and a catalog without the exact hosted worker selector is `RESTART_REQUIRED` too.

The forward `implementer.governed-worker/v1` default is exactly `openrouter/qwen-qwen3.8-27b` at explicit `xhigh` with no inherited history, and WorkerPort 0.1.8 also accepts explicitly frozen `medium` effort carried unchanged from the installed host-preparation constructor into the task request, route observation, registration, plan, and native evidence. A hosted acceptance task must explicitly pin both `model` and `thinking`. Local Qwen is offline and is never a probe or fallback target. Do not change Sol integration or adjudication routes, substitute, inherit, retry, replace, or fall back.

Governed native actions require the direct collaboration surface described in [execution.md](references/execution.md): without it, preserve the observation, record `DIRECT_ACTION_SURFACE_REFUSED`, and stop before controller activation, capacity reservation, grant publication, or native action. The governed startup self-test proves through `hooks/list` that every hook event the lifecycle requires is present, enabled, user-trusted, and hash-equal to the installed generation's bytes, and that a synthetic ungoverned event passes through unchanged; a failed check refuses governed mode with a named reason and offers an advisory run only after the user explicitly confirms it. Installation is never trust. The diagnostic `observe_current_local_task_hook_trust` remains available but is not a lifecycle gate, and neither are checkout capture, plugin attribution, external-executor projection, argv ancestry, or owner-gate reconciliation under ADR 0007.

Parent approval and the effective sandbox remain the authority boundary. Delegation may narrow authority but never broaden it.

## Use the advisory scan path

A read-only project scan with two through sixteen independent lanes enters at `evaluate_advisory_scan` with `orch-dork/advisory-scan-program/v2`, operation `prepare`, which returns one finite logical plan and one `TaskSpecV2` per lane while creating no worker and making no provider call. Native creation stays a separate parent-authorized act after the ordinary route, capacity, lifecycle, admission, ownership, and workspace gates. After termination, bind an exact-hash `orch-dork/attempt-observation/v1` manifest through `observe_native_advisory_scan` and finalize with `native_observation` as `status: observed`; `status: unknown` is only for a genuinely unavailable record or observer, with its allow-listed reason, and never a recast of a failing or contradictory report.

`COMPLETED_ADVISORY` means every lane drained and every required handoff is valid, and it still leaves `qualification_status: ADVISORY_ONLY` and `claim_permitted: false`. Missing usage, packet, or custody evidence stays unknown without erasing completed work; a failed lane, invalid handoff, membership mismatch, or incomplete root verification is `FAILED`. Advisory v1 and v2 are separate from strict logical-wave v2 and v3: never feed an advisory unknown into them, reinterpret it as zero, or relax their typed-packet, exact-usage, routing, custody, or terminal rules. [policy.md](references/policy.md) owns the exact program and report shapes.

## Freeze an orchestrated plan

Non-scan orchestration freezes one finite `orch-dork/logical-plan/v1`, or the explicit compatibility `orch-dork/plan/v1`, after a read-only planning pass. `finite_dag/v1` is the default and schedules ready nodes dependency-first within fresh capacity; `first_completed_worker/v1` is an explicit compatibility opt-in for two to four dependency-free lanes; `adaptive_finite_dag/v1` is a bounded root-owned revision sequence in which workers propose and only root or Sol approves N+1.

The frozen plan declares the authoritative root route, the exact worker route and no-history policy, disjoint lane scopes, dependencies, deliverables, verification, protected resources, acceptance criteria, complete acceptance-resource closure, the integration owner and release conditions, and zero retries, fallbacks, and replacements.

Call the plan, admission, ownership, capacity, lifecycle, and spawn-wave gates named in [policy.md](references/policy.md), including `validate_orchestration_admission`, `validate_orchestration_ownership`, and `validate_orchestration_spawn_wave`, and require matching hashes and PASS at every one. Worker slots exclude the active root. Submitted capacity remains `capacity_authoritative: false`, `capacity_claim_permitted: false`, and `capacity_scope: advisory`; only `adapt_native_capacity_observation` binds the host-signed authoritative form. Each lane is read-only or write-capable with its `LaneWorkspace` routed through the proven adapter, never a prompt promise, and every brief begins with `orch-dork/worker-preamble/v2`, enforces `context_budget_tokens` and the 1,200-token handoff cap, and carries a root-escalation escape hatch. Shared mutable coupling, changed acceptance, or an architecture decision stops as `ROOT_ESCALATION_REQUIRED` for fresh ticket admission.

## Execute and join

After freeze, root coordinates; it does not absorb implementation work. Spawn all initial ready lanes before waiting, with one fresh exact-parent creation result each; any failed, missing, ambiguous, duplicate, or reused result aborts without retry, replacement, or fallback. Give each worker only its frozen brief and scope, and require focused verification after its final mutation plus a typed handoff. Use the declared `integration_owner` regardless of completion order, or the `first_completed` worker as the compatibility integrator. Send exactly one release after each other owner completes, since shared visibility does not grant ownership, and verify again after every release and after the last integration mutation. Semantic joins deduplicate identical claims while preserving disagreement, evidence quality, unknowns, and interface conflicts; consequential conflicts return to root, Sol, or a declared adjudicator.

Adaptive lanes use exact `TaskSpecV2`, bounded `HandoffReceiptV1`, independent `VerificationReceiptV1`, and `ClaimLedgerV1` through `validate_logical_worker_program` and the dependency-wave procedures in [execution.md](references/execution.md); governed substantive waves use strict v3 and typed advisory waves use v2 compatibility. A completed direct read-only `wait_agent` observation is admitted. Require sanitized `resource.access` records. Submitted custody remains `coverage: unknown` and `claim_permitted: false`; only an independent host-signed `orch-dork/custody-observer-receipt/v1` establishes full custody. Never assign terminal reconstruction to root, an integrator, or another attempt member: a pre-terminal view is partial and `UNBOUND`.

## Governed execution

Before credentials, grant reservation, or model dispatch, require `evaluate_execution_readiness` to return `READY_FOR_AUTHORITY`. Governed work also requires the enrolled project-ground path in [project-ground.md](references/project-ground.md); missing ground is read-only. Bind a self-sealed PASS `pre_implementation` adapter report through `prepare_governed_native_activation` and submit only `READY_FOR_ACTIVATION` unchanged to `advance_governed_native_controller`, never the generic active-controller tool; controller activation and independent hard pre-spawn admission are still required, and `REFUSED` means no payload and no unchanged retry.

The staged governed attempt is fail-closed in order: `pre_spawn` binds fresh admission, plan, closure, versions, readiness, ground, capsule, budget, TaskSpecs, and independent v3 route preflights, with capacity derived only by installed `build_capacity_admission_program` from that exact passing pair; `worker_start` binds fresh creation, exact no-history routing, and a zero-tool TaskSpec acknowledgement; `progress` binds monotonic typed ingress, total usage, tool allowlists, and completion reserve, and stops on unknown, regressed, or exhausted budget; `terminal` requires a clean full v3 wave, strict handoffs, independent verification, claim ledgers, usage, timing, custody, trace, capsule, and dogfood spine. [execution.md](references/execution.md) owns each stage's exact inputs.

The hard-bound host controller alone seals one capacity-bound, single-use root action with canonical hook evidence; compatibility governed-run/v1 cannot qualify. `GovernedNativeController.advance` stays host-owned and exact-action only under `governed-native-controller-program/v1`, each action bound by its `native-action-receipt/v1` and the `PostToolUse` report, with root the only native task-creation actor and workers holding no spawn authority.

## Conditional procedures

Each item is an entry point whose exact contract lives in the named reference. Load one only when its condition holds.

- Campaigns and sweeps: seal `orch-dork/campaign/v1` through `evaluate_experiment_campaign` and verify that seal before binding a result. A finding outside the sealed question uses only the exploratory result variant and can never claim a default change. `run_sweep_campaign` and `summarize_sweep_campaign` project the ordinary append-only trace ledger, where `pass@k` and `pass^k` stay separately labeled exact rationals. Live grants, reservations, terminations, and the parameterized v4 axes with their exact ceilings are in [execution.md](references/execution.md).
- Record and replay: seal one `record-replay-plan/v1` with its baseline score policy and holdout tolerance before a campaign's first model call, use `record_model_call` at that boundary, and run `replay_campaign` only over the complete hash-keyed ledger. Bodies stay ledger-local, and a holdout disagreement beyond the sealed tolerance is labeled `hypothesis_generation_only`.
- Live-transport recovery: derive any recovery tranche through `orch_dork_live_recovery` and `derive_terminal_predecessor_capsule` before binding authority. The legacy v1 packet and the successor v2 packet stay replay-only; only a sealed qualified v3 packet creates an active scope, and `orch_dork_dispatch_packet.grant_from_packet` or `grant_from_v8_packet` returns additive standing grant v5 without a digest argument. Local-Qwen structural measurement is retained for closed historical replay only.
- Qualification rehearsal and successor drivers: the release tier runs `tests.test_orch_dork_qualification_rehearsal` before CI, release, or fresh qualification. `orch_dork_qualification_lifecycle_rehearsal.py` owns the real-hook startup and projected MCP calls, `orch_dork_qualification_rehearsal.py` still seals the earlier transport boundary at `before_network_model_native`, and `orch_dork_qualification_governed_inputs.py`, `orch_dork_qualification_route_canary.py`, and `orch_dork_qualification_bootstrap.py` remain typed consumers. `orch_dork_qualification_successor.py` is the sole app-server driver between `thread/start` and `turn/start`: it consumes whole typed reports with the canonical `--enrollment-registry-root` and the complete `project-enrollment-program/v1`, and the fresh root reaches `READY_FOR_ONE_ATTEMPT` only through the repository-owned first-action authorization. Never split that chain, substitute a binding file, import test fixtures, or transport, translate, or hash reports in agent code. See [execution.md](references/execution.md#qualification-caller-rehearsal--projected-provider-free-gate).
- Owner sessions: installed `run_qualification_owner_session` retains the creating WebSocket through preparation, authorization, execution, and terminal recording. Detach, resume, replacement tasks, and connection loss are terminal.
- Deepening, learned policy, and capsules: `evaluate_deepening_policy` disposes a typed runtime decomposition, where `DENY` stops expansion, `DEFER` waits for named missing evidence, and only `ACCEPT` proceeds to the independent ordinary revision, admission, and spawn gates; `evaluate_learned_policy` is advisory and both ordinary gates still dispose; `evaluate_coordinator_capsule` persists one sealed state with exactly one next action, and resumption after compaction starts only from its validated identity, cursor, hashes, unknowns, and reserve.
- Task creation: seal `evaluate_task_creation_intent`, persist its nonce, and make at most one native call. Make no second create call in that turn after failure or ambiguity. An immediate empty inventory stays pending. Use the rollover CAS procedure only at a recorded safe boundary.
- Hostile input, process containment, workspaces, deadlines, brief calibration, `brief_shape_sha256`, `orch-dork/brief-deadline-calibration/v1`, `WorkerTransport.invoke(WorkerCall) -> WorkerResult`, and local-model routing live in [execution.md](references/execution.md). Luna stays the default, and an optional adapter never authorizes a model call or live activation. The handoff deadline begins at `release_sent`, and recovery cannot make a spent grant reusable.

## Evidence and completion

Follow [observability.md](references/observability.md). Label runtime, UI, submitted, inferred, sealed, unknown, and contradictory facts. Never expose prompts, messages, session bodies, credentials, private reasoning, signing material, or unsanitized traces. A `custom_tool_call_output` is evidence only when its typed contract says so.

`qualify_orchestration_trace` PASS proves submitted structural conformance only. It remains `qualified: false` and `claim_permitted: false`. Only the governed external controller may combine separately bound terminal observation, valid custody, and submitted conformance into a completion decision.

Lead user reports with the task outcome and put machine evidence in artifacts or the registry. Missing evidence is unknown, not failure or success, unless its contract explicitly requires it.

For real dogfood runs, keep the host-local append-only corpus outside source at `$HOME/.local/state/orch-dork/dogfood-corpus.jsonl`. Append a verdict from `/path/to/record.json` and always provide `--host HOST`. If the root dies, derive the exact hash-bound mechanical spine with `scripts/orch_dork_dogfood_recovery.py`; a spine is not a verdict. The labeler role is the provider-neutral `BlindLabeler`, not a human-only role: a human uses the checked worksheet writer, and any sufficiently capable model may instead receive one sealed `orch-dork/dogfood-blind-labeler-packet/v1` in a fresh packet-only context and return one strict `orch-dork/dogfood-model-answer/v1`, sealed on acceptance as `orch-dork/dogfood-model-verdict/v1` in the separate host-local `$HOME/.local/state/orch-dork/dogfood-model-verdicts.jsonl` chain. Structured transport is formatting evidence only; the importer still performs the complete semantic validation. Never sign a model answer as human or concatenate either chain across hosts. The standing floor counts qualified blind independent verdicts once per real run while reporting human and model strata separately. No provider or model allowlist is permitted, and export or import authorizes no model call.

## Contract generation

Run the versioned trigger matrix, including its opaque ticket-file, issue-body, and plain-request prompts, and the forward evaluations in [contract-evaluation.md](references/contract-evaluation.md) against source, staged, and installed inventories. Preserve the not-triggered, atomic, orchestrated, refused, stale-admission, leakage, first-load-budget, and terminal-evidence boundaries. The host's own intake and ticket-status tests accept that seam; this contract never restates it.

The inventory records this file's measured first-load bytes (tokens are not measured) beside the lazily loaded reference bytes; exceeding the recorded budget is a named refusal, not a warning. A missing frontmatter or reference, stale generation, source and install mismatch, unavailable evaluator, or active task holding older bytes is a named unknown, refusal, or read-only stop. Preserve last-known-good evidence. An installed contract change becomes active only in a fresh task.
