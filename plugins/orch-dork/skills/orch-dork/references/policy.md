# Orch Dork policy schemas

## Contents

1. Classification-audit schema
2. Ticket-admission schema
3. Atomic task-creation intent schema
4. Governed-run entry schema
5. Worker-lifecycle schema
6. Live-view schema
7. Project-enrollment schema
8. Immutable executable project-ground schema
9. Project-adapter schema
10. Model-portable worker-port schema
11. Plan and acceptance-resource closure schemas
12. Trace schema
13. Event ordering
14. Evidence boundary
15. Admission and spawn-wave schemas
16. Finite logical-plan schema
17. Advisory scan and native-observation schemas
18. Adaptive finite-DAG and typed-contract schemas
19. Limit-policy schema
20. Profile-lifecycle schema
21. Efficiency-evaluation schema
22. Budget schema
23. Cancellation and recovery schema
24. Bounded dependency graph schema
25. Safe root-rollover schema
26. Observability-gallery schema
27. Governed run-state telemetry schemas
28. Flexible work intake and confirmed ticket status schemas

## Classification-audit schema

`audit_orchestration_classification` consumes and returns
`orch-dork/classification-audit/v1`. Each substantive-task record binds plugin
invocation/version, advisory or governed mode, effective global/project
instruction hashes, atomic/orchestrated/refused judgment, concrete reason,
confidence in basis points, decomposition evidence, policy version, authority
scope, optional human/project-policy override, and actual worker/trace
behavior. Missing invocation or classification remains an explicit review
signal.

The deterministic audit flags multiple independently ownable deliverables kept
atomic, tightly coupled work orchestrated without benefit, decomposition based
only on worker count or token ratio, unjustified refusal, authority or safe
ownership gaps ignored, worker/lane mismatch, and atomic work that spawned or
fabricated a trace. These are review signals rather than proof. An override may
select a different mode only with a recorded reason and an unchanged authority
scope hash. The evaluator launches no workers. A conforming atomic record is
root-owned with zero workers and `trace_status: not_applicable`.

## Ticket-admission schema

`evaluate_ticket_admission` consumes
`orch-dork/ticket-admission-program/v2` and returns the sealed
`orch-dork/ticket-admission/v2` decision for one exact ticket. This
`classification-policy/v2` gate runs before the first implementation mutation
and is provider-free, read-only, deterministic, and idempotent. The older
`audit_orchestration_classification` v1 interface remains available only for
historical/advisory receipts.

The admission identity binds `ticket_id`, `ticket_spec_sha256`,
`acceptance_criteria_sha256`, `authority_scope_sha256`,
`writable_scope_sha256`, `root_task_id`, `invocation_identity_sha256`,
`classification_evidence_sha256`, `candidate_lanes_sha256`, and the policy
version. The decision is exactly one of `ATOMIC_ADMITTED`,
`ORCHESTRATION_PLAN_REQUIRED`, `REFUSED`, or
`RECLASSIFICATION_REQUIRED`. Atomic admission requires concrete negative
decomposition evidence and permits no workers or orchestration trace.
Orchestration-required admission prevents root implementation until plan,
ownership, capacity admission, and structured spawn-wave validation pass.

Candidate resources type shared seams as `shared_mutable_core`,
`strict_serial_dependency`, `integration_only`, or `read_only_contract`.
Only the first two establish production coupling; shared policy, MCP,
documentation, integration, or frozen read-only contracts do not collapse
otherwise independent lanes into atomic work.

Admissions expire at ticket boundaries. An unchanged admission may survive
compaction, but changed ticket/spec, criteria, authority or writable scope,
root, invocation, classification evidence, candidate resources, prerequisite
repair, or material scope produces `RECLASSIFICATION_REQUIRED`. The canonical
seal excludes lifecycle events to avoid a circular digest; every emitted event
still carries the final `admission_sha256`.

The sanitized append-only lifecycle is
`orch-dork/ticket-admission-events/v2`: `ticket.claimed`,
`admission.issued`, optional `admission.invalidated`,
`implementation.started`, the first write-mode `resource.access` observed by
the controller/adapter, and `ticket.completed` or `completion.bound`. The same
hash and identity must bind implementation start, first write, and completion.
Missing, malformed, stale, or contradictory bindings fail closed.

Model-facing ownership validation uses the injected native task id to read
Codex 0.160's exact `state_5.sqlite` task index. Its canonical task workspace
supplies filesystem authority; an optional caller root must match it. Missing,
archived or unreadable task state refuses, with no caller-root fallback or
recursive rollout search. The native-home path travels only in the private
host job, outside model arguments.

One owned cancellable process bounds the complete public analysis to five
seconds plus bounded cleanup. Across all resources, expansion admits at most
10,000 directory entries, 64 path levels and 100,000 traversal or comparison
work units. Directory and pattern caches reuse enumeration across lanes;
foreign symlink prefixes refuse before enumeration outside the workspace.
Exhaustion produces failure with no partial safe result. Trusted Python callers
retain bounded local analysis and purely symbolic analysis without a root.

## Atomic task-creation intent schema

`evaluate_task_creation_intent` consumes
`orch-dork/task-creation-program/v1` and returns
`orch-dork/task-creation-report/v1`. It is provider-free and never creates,
stops, archives, hands off, or mutates a live task. The sealed
`orch-dork/task-creation-intent/v1` nonce binds the saved project ID,
authoritative initial working directory, host, permission profile, prompt
marker, bounded creation window, parent and supervisor identities, requested
role, purpose, and every authoritative host/store to search.

Persist one accepted nonce in an idempotent
`orch-dork/task-creation-ledger/v1`, then supply at most one normalized native
call receipt. `failed`, `timed_out`, `ambiguous`, or `malformed` receipts all
produce `OUTCOME_UNKNOWN`; they prohibit a second same-turn call and any
fallback target. A `created` receipt is not enough by itself: its returned task
ID and every bound target field must appear in authoritative inventory.

Delayed `orch-dork/task-creation-reconciliation/v1` evidence must cover every
host/store named by the intent. An immediate empty result remains pending;
zero matches can be confirmed only by a settled observation after the creation
window. One exact match advances only to read-only candidate verification.
Multiple matches require quarantine until all confirmed duplicates except one
are observably stopped or archived. Creation grants no lease or mutation
authority. Changing any target field requires a new separately authorized
intent; post-creation directory or UI-profile changes cannot repair custody.

## Governed-run entry schema

`evaluate_governed_orchestration_run` consumes
`orch-dork/governed-attempt-program/v1` and returns
`orch-dork/governed-attempt-report/v1`. The closed program has exactly
`schema`, `operation`, `identity`, `predecessor_receipt`, and `payload`.
`identity` binds run, attempt, root, exact root model/effort, source version,
installed version, task-loaded version, and the fresh-task fact. Every allowed
transition returns a content-addressed `orch-dork/governed-attempt-receipt/v1`;
the receipt's `next_action` is the only action it authorizes.

The staged operations are:

- `pre_spawn`: real AdmissionKernel evaluation over raw snapshot/plan/native
  facts; exact admission projection of the logical plan; logical-plan and
  acceptance-resource closure; exhaustive Markdown manifest when required;
  execution readiness; project-ground session health; coordinator capsule;
  positive Sol-ingress/total/tool limits and native budget reservation; and a
  wave-program/v3 with no creation/terminal observations but complete runtime-
  observed route preflights and TaskSpecs. It emits only
  `SHARED_CAPACITY_ADMISSION_REQUIRED`.
- `capacity_admission`: host-only atomic CAS reservation of the current
  dependency-ready wave against the one persisted shared authority. It binds
  the lower configured concurrency budget and global 32 maximum, requires a
  digest-bound commit and fresh exact readback, and is unavailable through the
  read-only MCP projection. Its program is derived only by the installed
  `build_capacity_admission_program` from the exact passing pre-spawn
  program/report pair; callers do not supply its schema, identity, receipt,
  operation, or payload independently. Only its `SPAWN_AUTHORIZED` permits
  creation.
- `worker_start`: one exact fresh creation and one runtime-observed no-history
  route per delegated lane. The route observation's strict terminal JSON must
  hash to the non-replayed TaskSpec acknowledgement and report zero tool calls.
  Any early tool or routing mismatch refuses work authority. Only
  `WORK_AUTHORIZED` permits substantive tools.
- `progress`: exact predecessor receipt, typed incremental packets, observed
  budget records, monotonic Sol ingress/total/tool counts and per-lane tool
  sequence, and every observed tool within that lane's TaskSpec allowlist.
  Unknown, regressed, unaccounted, exhausted, reserve-cutoff, replayed, or
  undeclared activity produces a sealed `STOP_REQUIRED` receipt.
- `capacity_settlement`: consumes exact host-signed cleanup releases for every
  lane in the admitted wave, canonicalizes legacy error/interruption outcomes
  to failed/cancelled, atomically removes only those active identities, and
  verifies readback before another wave, recovery, or terminal qualification.
- `recovery`: consumes only the cleanup-settled receipt for a failed or
  cancelled wave and requires a new attempt ID, exactly-next plan revision
  linked to the failed plan hash, and a completely fresh `pre_spawn`. It never
  resumes, follows up, or lets root reacquire failed lane scope inside the
  prior attempt.
- `terminal`: cleanly drained full v3 wave; runtime-bound strict JSON
  `HandoffReceiptV1` for every delegated lane; independent clean-context
  `VerificationReceiptV1`; `ClaimLedgerV1`; bound attempt observation with
  known usage, timing, custody, membership, and observed tool names; exact run
  trace and capsule; and a dogfood spine re-derived from the root session.
  Only this stage may issue `TERMINALLY_QUALIFIED`.

Every stage recomputes the prior receipt seal and exact full identity digest
(run, attempt, root, model, effort, all generation fields, fresh-task fact)
plus plan bindings. Caller timestamps never prove native ordering. Failures issue no
spawn/work/continue/terminal authority and never retry, replace, fall back, or
upgrade to advisory success. The read-only evaluator cannot itself intercept a
native tool: hard mode additionally requires an external dispatch owner or a
qualified hook/sandbox/gateway composition to obey the receipt.

`orch-dork/governed-run-program/v1` and its report remain replay-compatible,
but report `governance_mode: compatibility_replay`, never set
`terminal_claim_permitted`, and cannot qualify a new run.

## Governed native controller schemas

The host-only public seam consumes
`orch-dork/governed-native-controller-program/v1` and returns
`orch-dork/governed-native-controller-report/v1`. The program has exactly
`schema`, `controller_id`, `operation`, `expected_cursor`, and `payload`.
Operations are `activate`, `stage`, `observe`, and `inspect`; every mutation
requires the exact current RunEngine `{run_id, seq, event_hash}` cursor.
`activate` requires a null cursor and binds active enrollment, installed
generation, ticket admission, authority scope, root/session, plan, canonical
TaskSpec identity, hook definition and registration, action adapter, a
host-signed freshness/replay-checked hook-trust receipt, and the sealed
project-ground template. Unknown fields and inline trust assertions fail
before state creation. Completion must be the exact pending/unbound value, and
the declared read-only tools must be a subset of the controller's closed
true-read-only set.

Each stage persists an `orch-dork/governed-native-controller-event/v1` intent
before invoking the provider-free governed-attempt evaluator, then persists
the exact result. `spawn`, `continue`, and `stop` may return one
`orch-dork/governed-native-action/v1` only when a closed proposal names the
action ID, next-action kind, root actor, and recognized adapter. The adapter
derives exact current-wave lanes, TaskSpecs, route, native operation, and
complete tool input from sealed receipts. The action seal includes the
canonical input hash and predecessor receipt. It is an authorization packet,
never native execution evidence.
The controller validates the governed-attempt `PROGRAM_SCHEMA` during
cursor/identity continuity before persisting that intent. A wrong schema is a
cursor-preserving `STAGE_REFUSED`; the deeper evaluator retains the same
independent fail-closed schema validation.
Production binds the genuine governed-attempt evaluator, closed action adapter,
signed observer adapter, and canonical trust/replay stores directly; these are
not caller-replaceable constructor dependencies. A spawn action additionally
requires its receipt's physical lane IDs, store ID, and authority-state hash to
match live canonical reservations. Its provisional grant records the exact
capacity-ledger event cursor; the atomic PreTool claim re-verifies that cursor,
so any intervening reservation or release changes the head and permanently
stales the action.

Every observation requires both a closed
`orch-dork/native-action-receipt/v1` and the exact durable PostToolUse report
whose root session, official tool-use ID, action ID, tool-input hash, normalized
actual outcome, raw-result digest, and controller match flag pass. The durable
record has a closed schema and its own canonical content seal. Completed may advance.
Failed, cancelled, or timed-out permits only identity-bound signed capacity
cleanup; unknown or contradictory evidence retains occupancy and terminalizes.
The companion
`orch-dork/governed-native-hook-binding/v1` carries only the controller cursor,
canonical-store identity, root/session, reviewed hook digest, status, action
ID, tool, lanes, and input hash—never raw input. Its action grant is stored in
the same canonical SQLite database and atomically changes `AUTHORIZED` to
`DISPATCHED` before PreToolUse allows once. PostTool requires the same
`tool_use_id` and the bound PreTool event/report digests. PostTool reopens and
validates the create-only closed/self-sealed PreTool record, and controller
observation validates that same record again. Initial issuance is
`PROVISIONAL` before the stage result and becomes `AUTHORIZED` only when the
immediately succeeding event tip matches; only that provisional state is
crash-recoverable. `WAITING`, `BLOCKED`, and `TERMINAL`
permit no mutation; `ACTIVE` permits only the exact root action. A final
unmatched intent reduces to permanent `OUTCOME_UNKNOWN`, not a safe retry.
One narrower authority-only transition may later mark that grant
`TERMINAL_OUTCOME_UNKNOWN`: it requires the exact sealed
`partial_native_failure_terminalization` result from the same terminal owner,
an independently verified empty shared-capacity authority at a later canonical
cursor, and the original claimed spawn as the sole unsettled grant. The
transition changes only the grant state. It retains the tool-use claim and all
pre-action evidence, keeps outcome and result fields unset, mints no native
authority, and never reclassifies the historical outcome as success, failure,
or cancellation.

The controller uses `SQLiteRunStore`, `FilesystemArtifactLedger`, and the
Control Tower shared-capacity reader/committer. It creates no second occupancy
ledger and makes no native, model, provider, hosted, credential, task-creation,
retry, fallback, or replacement call.
Its plugin-data owner singleton rotates only from a sealed terminal hook/event
tip with zero active lanes, no pending intent/action/cleanup, and no
`AUTHORIZED`, `DISPATCHED`, or `OUTCOME_UNKNOWN` grant. A
`TERMINAL_OUTCOME_UNKNOWN` grant is settled for ownership only and therefore
does not block a later distinct owner; an active or otherwise unknown
predecessor does.
SQLite also records sealed append-only histories for every grant transition and
hook projection. Every hook invocation verifies those histories, the complete
outer RunEngine chain, and exact owner schema/store identity before re-deriving
canonical owner/identity/tip/lifecycle/read-only policy. Missing or resealed
JSON, a rewritten/deleted grant snapshot, a missing projection head, and
projection rollback all deny and cannot be healed from JSON.
The controller additionally mirrors each run marker and each grant-history
transition into a host-local, store-bound, read-only create-once witness root
outside plugin data. Grant witnesses are paired pre-commit intents and
post-commit seals in one global sequence; only the exact trailing uncommitted
intent is recoverable. Witness inventory must equal SQLite history, and the
sealed run origin must equal its run marker and external witness. These records
carry hashes and stream coordinates only—never occupancy or lane authority—so
the Control Tower remains the sole capacity ledger.
Terminal qualification uses a host-signed, freshness/replay-checked
`attempt-observation` receipt referenced by content hash.

## Research-manifest schema

`orch-dork/research-manifest/v1` records one declared exhaustive selection as
sorted relative paths, byte sizes, and SHA-256 digests plus exact claim-to-
source paths and used claim IDs. `filesystem_all` is recursive and case-
insensitive; `ripgrep_default_visible` reproduces the exact case-sensitive,
ignore-aware `rg --files -g '*.md'` inventory used by a research run. Its
corpus digest covers the file rows and its manifest digest covers the body.
`validate_markdown_manifest` independently re-reads the root and refuses an
addition, deletion, change, dishonest count, path escape, symlink, non-regular
file, unmapped claim, unknown used claim, or size/count bound violation. It
stores no document body and performs no model or network call.

## Execution-readiness schema

`evaluate_execution_readiness` consumes
`orch-dork/execution-readiness-program/v1` and returns the sealed provider-free
`orch-dork/execution-readiness-receipt/v1`. The program binds the exact executor,
controller, project adapter, policy, MCP descriptor, finalizer, evidence schema,
environment runner, readiness evaluator, lifecycle policy, interpreter,
repository and working directories, import paths, disposable root, loopback and
nested-sandbox observations, frozen plan, and authority scope.

The failure replay requires timeout, cancellation, provider exception, missing
usage, finalizer exception, partial evidence, and cleanup failure. Each case
persists either terminal or durable-unknown evidence before its error propagates.
The lifecycle replay orders owner work before release, `release_sent`, delivery,
sender binding, duplicate delivery, expiration, late completion, and integrator
failure; its deadline origin is exactly `release_sent`. Preserved Issue 17
finalizer drift and Issue 28 barrier-clock records are mandatory immutable
regressions with failed, nonreusable grants.

`READY_FOR_AUTHORITY` means only that this exact closed implementation and
environment passed the provider-free prerequisite. It does not grant authority,
inspect credentials, reserve or consume a grant, make spent authority reusable,
or dispatch a model. Missing, unavailable, unknown, stale, or mismatched facts
produce a named stop. Changing any bound implementation, environment, plan,
authority scope, or lifecycle policy changes the readiness identity and requires
a new provider-free run; setup defects are not model attempts and never trigger
retry or fallback.

## Worker-lifecycle schema

`evaluate_worker_lifecycle` consumes
`orch-dork/worker-lifecycle-program/v1` and returns the sealed provider-free
`orch-dork/worker-lifecycle-report/v1`. It binds one root and required slot
count to a runtime-observed `orch-dork/worker-retirement-capability/v1` fact,
plus two fresh `orch-dork/capacity-observation/v1` inventories immediately
before freeze and spawn. Capability is `supported`, `unsupported`, or
`unknown`; unknown follows the unsupported branch. Partial, ambiguous,
changed, or stale observations stop with the plan unfrozen.

Both lifecycle and plan admission consume the same normalized inventory
module. Lane capacity is concurrent and at most 32 non-root lanes may occupy
slots. Terminal status alone never releases capacity. A host-signed active-only
observation releases a completed, failed, or cancelled record only when that
same signed payload carries the closed shared release receipt bound to
`lane_id == worker_id`, `run_id == attempt_id`, route `native_luna`, the
canonical terminal state, zero owned descendants, and cleanup
`complete` or `not_required`. Missing, unsigned, malformed, or contradictory
proof remains occupied; identities remain visible and nonreusable. A caller-
submitted v1 terminal is likewise not proof of release. The
legacy inputs `errored` and `interrupted` normalize to `failed` and
`cancelled` before receipt construction; `released` is representation only.
The v2 `retained_until_shutdown` accounting mode is retired and refused. Because
v1 is caller-submitted, even a clean report is advisory and exposes
`capacity_authoritative: false`, `capacity_claim_permitted: false`,
`capacity_scope: advisory`, and `capacity_evidence_tier: submitted`. An
advisory admission may schedule within those declared slots under parent
authority when local policy permits, but it cannot support authoritative
capacity or governed-success claims.

`adapt_native_capacity_observation` is the only public adapter from a
host-signed `orch-dork/native-capacity-observation/v1` payload to authoritative
v2 inventory. The payload binds an independent observer, exact root, capacity,
retirement capability, worker rows, slot-accounting mode and surface, a
five-minute-or-shorter observation/evaluation/expiry interval, source pointer
and digest, and its compatibility `observation_sha256`. The enclosing Ed25519
envelope binds its own five-minute validity and replay nonce; the adapter uses
only host-owned trust and replay state. It compares its own evaluation instant
with both intervals. A bare self-seal, malformed/expired signature, unavailable
host state, non-independent observer, or root mismatch returns no authoritative inventory. A passing
`orch-dork/native-capacity-adapter-report/v1` sets
`capacity_authoritative: true`, `capacity_claim_permitted: true`, and the
closed `capacity_evidence_tier: runtime-observed`; signing strength remains in
the dedicated receipt, key, trust-generation, and authority-source fields.

`orch-dork/collaboration-inventory/v2` declares `active_only` only through
`orch-dork/slot-accounting-capability/v1`: it binds the exact root and surface,
`active_agents_excluding_root`, canonical occupied statuses, a runtime-observed
source pointer and SHA-256, and an observed/evaluated/expiry interval no longer
than five minutes. Only `running` and `pending_init` occupy active-only slots.
Terminal identities remain nonreusable. Any missing, submitted-only, stale,
overlong, malformed, or contradictory capability refuses before freeze.
A structurally valid raw v2 inventory may still guide advisory scheduling, but
its literal `runtime_observed` field cannot self-promote authority: only the
native-observation adapter path carries `capacity_adapter_sha256`,
`capacity_observation_sha256`, `capacity_signed_receipt_sha256`, signing key,
and trust generation into an authoritative report.

The supported branch consumes one `orch-dork/worker-retirement/v1`. The
worker must already be terminal with zero owned live processes and zero
pending deliveries. Its exact release request must have one successful
receipt, and a later fresh inventory must prove the worker is `shutdown` or
absent, every other worker is unchanged, and free slots increased by one.
Completion alone, a delayed/failed/ambiguous receipt, or stale inventory never
releases capacity.

The unsupported branch requires an `orch-dork/one-wave-root/v1` declaration
before freeze, limited to currently free slots. When a later wave is needed,
the declaration binds a checkpoint hash to Issue 37's accepted creation
intent and Issue 29's rollover report. One matching successor stays read-only
until the predecessor is independently terminal and the lease transfer is
proven; duplicates remain quarantined. The report never permits replacement,
worker reuse, plan shrink, root implementation fallback, or a second creation
call, and records zero live retirements, task operations, launches, models,
and hosted calls.

## Coordinator-capsule schema

`evaluate_coordinator_capsule` consumes
`orch-dork/coordinator-capsule-program/v1` and returns
`orch-dork/coordinator-capsule-report/v1`. Initialize and update operations seal
the small `orch-dork/coordinator-capsule/v1`; resume, wait, handoff, and replay
operations are read-only decisions. The capsule binds one ticket or frozen wave
to its acceptance, ticket admission, plan, execution lease, authority or grant
state, source/install versions, worker and integration state, event cursor,
artifact hashes, unresolved unknowns, completion reserve, seven-category
efficiency telemetry, policy, append-only event log, and exactly one next action.
It contains no prompts, conversation history, private reasoning, credentials, or
authorization secrets.

Each mutation supplies the expected version, exact prior capsule hash, and one
event; successful CAS increments the version once and preserves the contiguous
event log. Stale writers, changed ticket identity or scope, a regressing cursor,
contradictory lease, incomplete evidence, oversized capsule, or invalid seal
returns `STOPPED` without a replacement capsule. Post-compaction resume validates
one capsule read and restores only durable facts at the recorded cursor; it does
not require broad discovery or repeat completed checks.

An unchanged cursor and invariant within the configured no-change budget returns
`WAIT_NO_CHANGE` with no user update, polling, or worker message. Changed state
returns one `record_transition` action. Setup, core work, waiting, integration,
validation, cleanup, and rollover telemetry remain distinct; unknown is encoded
as `known: false` with a null value. Context and completion-reserve thresholds
produce a pre-critical `checkpoint_rollover` action. `HANDOFF_COMPLETE` requires
an independently re-read newer successor lease plus the exact capsule version
and hash. Every report is provider-free and performs zero task, worker, lease,
authority, credential, or model actions.

The canonical historical replay covers three sanitized audited coordinator
records and exactly 18 compactions. It passes only with bounded wakeups, zero
duplicate routing updates, preserved failed-run facts, and one deterministic
next action per record. The aggregate comes from Issue 39's canonical audit
origin; it does not invent or expose conversation content.

## Live-view schema

`project_orchestration_live_view` consumes
`orch-dork/live-view-program/v1` and returns
`orch-dork/live-view-report/v1`. The frozen `orch-dork/live-view-plan/v1`
records planned root/node/edge identity, routing, ownership, checks, stable task
pointers, and its canonical hash. Each projection receives the complete
contiguous event prefix plus the prior cursor and prefix hash. A mismatch fails
the append-only check; there is no mutable cursor guess.

Closed event kinds observe root/worker identity, node and edge states,
ownership, verification, releases, typed wall-time/overlap facts, raw token
components, and qualification. Every event names one of `observed`, `inferred`,
`submitted`, `unknown`, or `contradictory` plus a submitted, runtime-observed,
or sealed-runtime tier and stable source pointer. The report renders a Mermaid
graph and Markdown tables with planned and observed facts kept distinct. It
supports planned, active, waiting, completed, failed, cancelled, timed-out,
unreleased, released, integrating, and blocked node states. Root, child,
qualification, and source navigation links are included only when supplied.
Unknown values remain unknown, contradictions fail, and forbidden session,
prompt, private-reasoning, credential, or authorization fields fail closed.

## Project-enrollment schema

`evaluate_project_enrollment` consumes the closed
`orch-dork/project-enrollment-program/v1` and returns
`orch-dork/project-enrollment-report/v1`. The read-only MCP seam resolves one
exact project identity, external record locator, repository binding, adapter
digest, registry compare-and-swap expectation, and maintenance state. It never
creates a directory or file, enrolls or removes a project, executes an adapter,
changes a hook or sandbox, reads a credential, reserves authority, creates a
task/worker, or contacts a model.

Identity binds project, host, optional environment and saved project,
workspace, repository kind, optional worktree, canonical initial root, and the
observed root device/inode and Git-marker kind. The external record path is
derived from that logical identity without trusting repository data. The small
`orch-dork/project-binding/v1` manifest contains only project ID, protocol,
binding generation, enrollment identity hash, argument-array adapter command,
adapter digest, and `required: true`. Unknown fields, shell commands, path
escape, symlinks, missing or mismatched adapter bytes, ambiguous nested roots,
and an external registry inside the project are refused.

The explicit module/CLI apply seam stages canonical JSON and activates only the
external `orch-dork/project-enrollment-record/v1` through an exact locked
compare-and-swap. A record contains the logical and observed identity, active
generation, manifest and adapter hashes, last-known-good locators, monotonic
version, append-only events, and its seal. Initial partial staging is inert
until the external record activates; an exact rerun may complete it. Existing
active state is idempotent only when every identity and digest agrees. Changed
active state requires reconciliation or later migration and is never
overwritten.

`inspect` returns `ACTIVE` only when the record, live identity, repository
manifest, adapter bytes, and binding generation all agree. Missing, corrupt,
unreadable, permission-denied, stale, deleted, or compare-and-swap-losing state
is read-only by name. `unenroll` is an explicit no-active-writer maintenance
operation that changes the external record to an append-only tombstone last
and preserves repository files by default. Issue 40 supplies this enrollment
layer only; adapter execution and mechanical mutation enforcement remain
separate later gates.

## Immutable executable project-ground schema

Issue 41 adds one closed provider-free execution seam:
`authorize(operation, live_context) -> orch-dork/project-ground-decision/v1`.
This executable interface is available to trusted host callers only. It is
not advertised or dispatched as a model-facing MCP tool. A model request to
`authorize_project_ground` receives the standard invalid-tool error before
any adapter source read, snapshot creation or process launch (Issue 205).
A matching caller-supplied digest establishes byte identity, not authority.
The operation is an exact `orch-dork/project-ground-operation/v1` object with
`kind`, JSON `input`, and a source pointer. The context is an exact
`orch-dork/project-ground-context/v1` object carrying project identity,
binding, authority, writable scope, lifecycle hashes, environment identity,
bounded timeout/output limits, and a plugin-owned snapshot root. Secrets,
credentials, authorization material, prompts, copied conversation, private
reasoning, sensitive configuration keys, unknown fields, and path escapes are
refused before execution.

The adapter command remains an argument array. The first verified source read
is atomically copied to `sha256/<prefix>/<digest>` and made non-writable; an
admitted or explicitly bound call never reopens the mutable repository path.
Missing, corrupt, unreadable, permission-denied, non-immutable, or rolled-back
snapshot state is denied by a named reason and cannot fabricate a generation.
Execution evidence binds the immutable locator and exact source digest to the
interpreter, cwd, environment digest, timeout, process group, input/output
digests, bounded cleanup, and exit status. Output is one bounded JSON object;
malformed, sensitive, schema-mismatched, or unbounded output is denied.

Adapter authority and writable scope may be omitted (preserved) or narrowed;
any added grant, broader scope, or changed approval/sandbox value is denied.
Provided ticket-admission, acceptance-closure, execution-readiness, lease,
active-controller, capsule, and final-evidence hashes are echoed and must
match any adapter-declared lifecycle binding. The evaluator and its policy
descriptor execute no provider/model call, reserve no authority, and expose no
repository mutation entry point. This is the provider-free Issue 41 lane;
Issue 42 supplies the local hook/gateway composition and Issue 43 supplies the
explicit migration/recovery and replay boundary.

## Mechanical project-ground enforcement schema

`evaluate_project_ground_enforcement` consumes one exact
`orch-dork/project-ground-enforcement-program/v1` and returns
`orch-dork/project-ground-mutation-decision/v1`. The program binds the official
hook event to a gateway-produced state record, closed tool-coverage policy,
protected resources, exact gateway receipts, and completion state. The state
contains plugin-hook trust/hash/status, enrollment, ticket admission and plan
permission, immutable adapter report, execution readiness, single-owner lease
and compare-and-swap state, active-controller report, coordinator capsule,
authority/writable-scope hashes, workspace baseline, lifecycle cursor, and
sandbox coverage.

`SessionStart` returns `HEALTHY` only when all state is exact and seals an
`orch-dork/project-ground-session-health/v1` record. `PreToolUse` returns
`ALLOW` or `DENY` and binds the canonical tool-input hash. Supported hook
classes are shell, `apply_patch`, MCP, ordinary local functions, and code-mode
nested calls. `write_stdin`, child processes, hosted tools, specialized paths,
computer use, and external processes require an exact gateway receipt or
declared sandbox coverage. Unknown or incomplete coverage denies mutation.

Binding, enrollment, adapter snapshot, lease, admission, evidence seal, hook
state, and capsule are mandatory protected semantic resources. Direct writes
require one exact input-hash-bound maintenance gateway. `PostToolUse` returns
`OBSERVED`, persists only sanitized hashes, and invalidates prior final
verification without claiming rollback. `Stop` and `SubagentStop` return a
continuation decision until final verification, governed controller, and an
independent `BOUND` terminal observation agree. The MCP descriptor is
read-only; only the trusted synchronous hook or project-native gateway owns a
mutation boundary.

## Project-ground migration and recovery schema

`evaluate_project_ground_maintenance` consumes
`orch-dork/project-ground-maintenance-program/v1` and returns
`orch-dork/project-ground-maintenance-report/v1`. Operations are `inspect`,
`diagnose`, `migrate`, and `recover`. The read-only MCP evaluator binds the
external active-generation record and compare-and-swap expectation, exact
project identity, pinned/target protocols and security generations,
source/installed runtime hashes and versions, immutable artifact, target
binding, all six migration stages, exact recovery source/destination, fresh
admission, bounded repair/rerun counts, live diagnostics, and timing budget.

Compatibility is `EXACT_PIN`, `COMPATIBLE_PIN`, `MIGRATION_REQUIRED`,
`INCOMPATIBLE`, `UNSUPPORTED_NEWER`, `ROLLBACK_BLOCKED`, or
`SOURCE_INSTALL_MISMATCH`; no implicit latest selection exists. A mutable
maintenance apply requires `READY_TO_MIGRATE` or `READY_TO_RECOVER`, no active
writer, one lock and compare-and-swap, and exact current bytes. Migration
stages the new immutable artifact, replaces the repository binding, and writes
the new external record last. Any later activation failure restores the prior
binding and preserves the prior record and content-addressed generation.

Recovery accepts only the exact active last-known-good locator and digest,
matching project identity, unchanged expected destination, no conflicting user
change, and fresh admission. Diagnostics cover enrollment, manifest, adapter,
installed plugin, hook, sandbox/gateway, lease, scope, admission, capsule, and
drift with exactly one safe next action. Immutable decisions may be cached, but
generation, lease, and scope are rechecked. Known timing is measured against a
declared budget; unknown timing is null. The closed provider-free replay keeps
historical failures immutable and requires every disposable and Model
Coordinate case by name.

## Hostile-input and resource-bound schema

Issue 49 defines one canonical provider-free profile,
`orch-dork/hostile-input-profile/v1`, in
`skills/orch-dork/scripts/orch_dork_hostile_input.py`. Parser, MCP,
dispatcher, adapter, registry, enrollment, maintenance, and fuzz surfaces may
select stricter limits but never widen, truncate, silently drop, retry, or
fallback around this profile. Structured UTF-8 JSON is bounded at 262,144
bytes; strings at 65,536 bytes; keys at 256 bytes; paths at 4,096 bytes;
nesting at 32; composite nodes at 4,096; object/array members at 256; and
batches at 64 entries. Canonicalization rejects BOMs, invalid UTF-8, duplicate
keys, non-finite numbers, and trailing data before schema expansion or side
effects.

The MCP frame/dispatcher contract is 262,144 bytes, 32 operations, 64 queued
entries, 16 in flight, two seconds for parsing, and ten seconds for complete
local dispatch. The immutable adapter process owns one group with at most eight
descendants, 256 MiB RSS, one second CPU, ten seconds hard wall, and 65,536
bytes per output stream. Registry chunks bind 256 records, 4,096 claims/edges,
and 64 source locators; enrollment/maintenance binds 262,144-byte manifests,
64 paths, 32 generations/transitions, and one staged operation. Unknown
cleanup or telemetry is `UNKNOWN` and blocks qualification.

Stable denial reasons and body-free evidence are part of the wire contract.
Fuzz campaigns use seed `0x4F524348`, exactly 2,048 generated cases per
surface plus the bytewise fixed corpus, a 60-second campaign budget, and no
external entropy. Crash evidence contains only the surface, case ID, seed,
input size/hash, bound, reason, exit/signal class, elapsed time, output size,
process-group count, and cleanup status; it never contains prompts, input
bodies, credentials, environment values, private reasoning, or unsanitized
traces. A denial cannot grant authority, alter a lease, broaden writable scope,
or make a projection authoritative.

## Project-adapter schema

`evaluate_orchestration_project_adapter` consumes
`orch-dork/project-adapter-program/v1` and returns
`orch-dork/project-adapter-report/v1`. A required adapter is identified by
exact ID, version, and configuration hash. The versioned declarative
`orch-dork/project-adapter/v1` definition covers project kind, inert focused
and final verification rules, protected resources, workspace root and baseline
policy, declared external systems/actions, and approval checkpoints. The
generic plugin does not execute commands or infer project-specific checks or
authority.

The pre-implementation phase refuses a missing, unavailable, invalid,
identity- or configuration-mismatched adapter before work. Root and delegated
boundaries carry exact sandbox-scope hashes, approval policy, and external-
action grants; delegation may omit grants but cannot modify or add them. A
post-implementation report binds exact-or-unknown workspace observation,
focused/final results, checkpoint dispositions, and external action outcomes.
Any observed action must be declared and covered by the same exact grant in
both root and delegated boundaries. `create_adapter_evidence_bundle` seals
requirement, definition and configuration, boundary, outputs/failures, and
report with the existing closed evidence-bundle implementation.

## Model-portable worker-port schema

`evaluate_orchestration_worker_port` consumes the exact closed
`orch-dork/worker-port-program/v1` fields `schema`, `program_id`, `operation`,
and `payload`, and returns `orch-dork/worker-port-report/v1`. Operations cover
canonical call/result/manifest validation, capability compatibility,
declarative adapter and workspace evaluation, sealed evidence, frozen paired
qualification, and release activation. Every report fixes `provider_free:
true`, zero model calls and command execution, no workspace mutation, no
candidate application, and no route promotion.

The canonical transport contract uses strict closed
`orch-dork/worker-call/v1`, `orch-dork/worker-result/v1`, and
`orch-dork/model-manifest/v1` objects. `tool-free-canary`, `bounded-coding`, and
`multi-worker` remain distinct; missing coding support is
`UNSUPPORTED_CAPABILITY`, never silent degradation. The adapter projection may
translate only `edit` to `edit_patch` and `test` to `focused_test`; the strict
transport value and hash remain authoritative.

Workspace evaluation is pure: submitted server-owned disposable-worktree,
registered lane policy, allowlisted operation, candidate-diff, drift,
cancellation, and cleanup records are validated without executing them.
Evidence must have the exact non-null required section/hash sets, agree with
the canonical call assignment and base revision, bind an unapplied candidate
diff, and exclude credential values, raw authorization, private reasoning, and
session bodies. Missing or contradictory evidence cannot become success.

Qualification freezes exact Qwen and Luna manifests and matches repeated
RouteWeave and ReleaseForge rows on task, revision, prompt, budgets, tools,
evaluator, suite, and repetition before the first model call. Public and
hidden rows require exact 20/20 and 100/100 scores, independently accepted
patches, lifecycle/capability/scope conformance, and reliability,
critical-path-latency, and Sol-burden gates. Missing evidence is
`INCONCLUSIVE`. Two-worker and four-worker-plus-integrator phases remain
separately gated. Release activation is only a provider-free readiness
decision until an exact served checkpoint/runtime and explicit finite hosted
authority exist; it never changes the Luna default itself.

## Centralized Control Tower schema

`evaluate_orchestration_control_tower` consumes the exact closed
`orch-dork/control-tower-program/v1` fields `schema`, `program_id`, `operation`,
and `payload`, and returns the exact closed
`orch-dork/control-tower-report/v1`. Operations are `prepare`, `advance`, and
`inspect`. A well-formed business refusal is an envelope `PASS` carrying a
sealed zero-intent refusal; malformed or hostile contracts are envelope
`FAIL` with stable non-reflecting issues.

Issues 144–147 enable all five provider-free Workflow Profiles plus the
direct-run capacity scheduler. A TaskBrief can become `READY_TO_FREEZE`, immutable
`PLANNING_REQUIRED`, or `REFUSED`. A planning resubmission is one sealed
`orch-dork/planning-submission/v1` containing the exact still-live planning
requirement and one typed logical-plan proposal. The direct tracer may collapse
only the exact canonical one-node proposal to `direct/v1`; a general proposal
must arrive inside the sealed `finite_dag/v1` workflow submission with its exact
planning requirement, Topology Closure submission, and declared integration
node.
Starting a ready preparation lands the canonical RunEngine `started` fact and
emits bound dispatch intents with zero observed executions. A validated
WorkerResult produces a hash-verified ArtifactRef and HandoffReceipt before its
applied fact; an independent VerificationReceipt then supplies reviewer
evidence and terminal completion. Inspection exposes bounded event identities,
fact digests, ArtifactRefs, and sanitized immutable artifact records, never
event payloads, artifact bodies, host paths, or private reasoning.

`parallel_join/v1` additionally requires one sealed
`orch-dork/parallel-join-submission/v1`. It closes the admitted information
units, exact producer partition, every result-relevant relation, typed relay
delivery, criterion ownership and verification, join obligations, declared
artifact consumers, and typed unknowns. The compiler emits two or more
producer TaskSpecs and one join TaskSpec in one canonical `finite_dag/v1`
logical plan. The preparation embeds one `orch-dork/topology-closure/v1`; its
digest is bound by the compilation receipt and enclosing preparation seal. A
cross-node relation passes only through co-location, a plan-revision-fresh
acknowledged serial relay, an owning join that receives both sides, or a named
irrelevance proof. Generic visibility, conversation history, private
reasoning, and presumed integrator knowledge do not close it.

Every declared artifact edge produces a sealed
`orch-dork/context-manifest/v1` with required logical artifact IDs, no optional
refs by default, forbidden conversation/private-reasoning context, exact plan
revision freshness, purpose, and a required runtime consumer acknowledgment.
The create-only filesystem Artifact Ledger and its equivalent in-memory test
adapter bind each byte digest and size to media type, content schema, producer
run/node/TaskSpec, privacy, custody evidence, source lineage, consumers, and
retention. Portable records contain content identities, never host paths.
Reusing identical bytes with different provenance refuses. Reads revalidate digest and size;
producer and integrator ingress charges artifact bodies plus the canonical
ArtifactRef/HandoffReceipt envelope and is bounded before publication or join.

Producer dispatches may be concurrent only when their declared dependencies
are ready. A serial relay releases only its dependent producer. Integration is
not emitted until every declared producer handoff exists, and the join must
partition all input refs into consumed and explicitly unused sets, report
conflicts, and discharge exactly its owned criteria. Only the join artifact is
eligible for final independent verification and canonical completion. The
exact Issue 111 r5 16-item round-robin acceptance-unit cut refuses during
preparation because each corroboration witness is separated from its anchor;
the co-located, fully relayed, and join-owned variants are passing controls.

The closed `orch-dork/workflow-profile/v1` registry contains exactly
`direct/v1`, `execute_verify_repair/v1`, `parallel_join/v1`, `best_of_n/v1`,
and `finite_dag/v1`. Each content-addressed entry binds applicability rules,
topology invariants, parameter schema, compiler, repair ceiling, required
verification, and canonical output-plan schema. All five lower to one verified
logical plan and use the same Artifact Ledger, RunEngine, cancellation,
inspection, and terminal conjunction; no entry owns another lifecycle or state
authority.

`execute_verify_repair/v1` freezes `max_repairs` from zero through two. The
compiler declares the complete serial Repair-node ceiling before start. A
`REPAIR` disposition creates only the next TaskSpec-bound intent with a fresh
idempotency key, explicit failed checks, immutable acceptance and scope digests,
permitted source refs, newly charged context, and complete artifact lineage.
Its result receives new independent verification. Replayed repair intents,
reused bytes under different provenance, widened scope, undeclared or third
repairs, and hidden retry/fallback/replacement behavior refuse without state
advancement. `ESCALATE` terminates non-success and emits no new work.

`best_of_n/v1` freezes two through eight equal-budget candidates, distinct
candidate independence groups, a different comparator group, a declared
winner-or-synthesis policy, and one evidence-bound `direct/v1` baseline. Only
opaque option labels and content-addressed ArtifactRefs enter the comparator;
candidate node IDs, WorkerResult identities, handoffs, and completion order do
not. The comparison records exactly winner, synthesis, tie, or escalation.
Winner and synthesis continue to ordinary layered verification; tie and
escalation terminate non-success with no repair or replacement.

`finite_dag/v1` requires the exact live planning requirement, a revision-one
canonical proposal, the closed Topology Closure submission, and one matching
integration node. Node count, acyclicity, dependencies, ownership, authority,
retry/fallback/replacement zeros, acceptance checks, and budget envelope are
revalidated before freeze. Topology Closure admits the exact `finite_dag/v1`
profile identity as well as `parallel_join/v1`; only roots are initially
dispatchable and every later node is released from canonical applied facts.

New profiles require `orch-dork/review-disposition/v1`. Evidence layers are
ordered orchestration invariants, deterministic checks, execution-grounded
checks, independent review, then human approval. The only decisions are
`PASS`, `REPAIR`, and `ESCALATE`; a later layer cannot erase an earlier failure.
When the TaskBrief names a human approval, the sealed review contract requires
independent PASS evidence at that layer. An integrator consumes only admitted
ArtifactRefs and bounded primary evidence; every TaskSpec keeps empty tools and
write scope, executor capabilities keep empty side effects, and requested merge,
publication, deployment, credential, or other external effects refuse before
run state exists.

Duplicate, stale, replayed, widened, drifted, and post-terminal inputs refuse
without retry, fallback, replacement, or hidden state. Cancellation lands a
request fact, emits cleanup, records complete or typed-unknown cleanup, and
only then lands `terminated`; no cleanup event follows terminality. The
Control Tower has no model, hosted, credential, tool, repository, release,
installation, or activation path.

For scheduled direct work, `enqueue` starts the ordinary canonical run in a
queued mode and emits no dispatch intent. One separately configured sealed
capacity vector tracks logical runs, live sessions, GPU memory, process slots,
integration slots, tokens, context tokens, hosted calls, and wall time as
independent hard ceilings. This provider-free generation requires hosted-call
capacity to be exactly zero. The total-token dimension includes context,
output, and handoff reservations; the context dimension remains separately
binding. A current sealed scheduler cursor plus a bounded
`schedule` operation may append one reservation batch to the dedicated
`ct-scheduler` RunEngine stream and return only those already-bound intents.
Selection is deterministic by dispatch count and run identity; spare capacity
never creates a run, node, retry, fallback, replacement, or worker reuse.

The queue, capacity inspection, and per-run classifications are rebuilt from
the scheduler reservation stream and canonical queued-run streams. They are
explicitly `run_state_authoritative: false` and cannot write a run. A
reservation remains charged through cancellation until observed cleanup lands
the terminal fact. A terminal typed-unknown cleanup remains visibly
`cleanup_unknown` and keeps its reservation charged because a possibly live
descendant cannot be treated as free capacity; an expired intent is not
replaced. SQLite keeps each event
reservation and commit in one transaction, so process or connection death
rolls an incomplete claim back while concurrent writers resolve through one
cursor-bound CAS. Legacy committed sentinels are removed only during startup
recovery, and a commit-time validation failure explicitly releases its claim.
A durable RunStore refuses a volatile Artifact Ledger. Accepted worker facts
carry the exact result digest plus bounded usage, timing, and runtime summaries;
unknown usage/timing, per-dimension overflow, timeout, and output-body overflow
refuse without publication or state advancement. SQLite remains single-host;
Postgres is still required before multi-host writers. The Issue 148 learning
records below are inactive projections; the topology laboratory and every
promotion or activation path remain blocked behind Issue 149 and later
authority.

## Inactive Strategy cards and route learning

Issue 148 adds two pure evaluators behind the Control Tower's closed
`orch-dork/control-learning-inspection-query/v1`. `kind: route` evaluates one
deterministic routing or factored-run request. `kind: strategy` evaluates one
candidate, lifecycle-decision, or retrieval request. Neither kind needs a run
and both are explicitly submitted advisory projections. `kind:
terminal_projection` additionally requires an existing terminal RunEngine
stream plus one complete factored-run program and one candidate proposal. The
Control Tower re-derives the stream, terminal outcome, TaskBrief fingerprint,
project, privacy and risk classes, registered profile, exact route digest,
cut/count, executor group and model, context and budget choices, verification
policy and terminal evidence, usage, latency, rework, cost, integration load,
RunEngine event refs, and applicable human disposition. It rejects any
cross-binding drift before invoking either evaluator. A successful stream binds
the passing verification receipt; a failed stream binds its typed failed or
escalated disposition; a cancelled stream binds the observed cleanup evidence
and records correctness as not applicable rather than inventing a verifier
pass.

Both pure evaluators reject a canonical request envelope larger than 262,144
bytes before dispatching an action. A well-formed Control Tower inspection can
therefore return outer `status: PASS` with decision `EVALUATOR_REJECTED` when
the nested advisory evaluator rejects its own closed request; this is a visible
business rejection, never permission to append, mutate, or retry.

The returned `orch-dork/control-learning-inspection/v1` is content-addressed,
`projection_only: true`, and `append_permitted: false`. It cannot add a
post-terminal run fact, alter a historical event, activate a card, select a
production route, mutate policy, dispatch work, explore, or grant authority.
The verified append-only RunEngine stream remains the sole run-state
authority; an embedding application may persist the sealed projection only in
a separately governed measurement ledger.

A terminal source may propose exactly one sealed
`orch-dork/strategy-card/v1` in `candidate` state. It binds task fingerprint,
project and privacy scope, registered profile, terminal outcome and
verification, source and evidence refs, supporting and contradicting lineage,
confidence and basis, expiry, usage, feedback, runtime generation, and exactly
one of useful strategy or failure pattern. Observations are quoted
non-executable evidence. Activation, retirement, and quarantine are immutable
decision records requiring either an exact Owner review bound to the card or a
sealed preregistered rule with at least two lineage-distinct qualifying
outcomes. One source run cannot support itself twice, and contradiction is
preserved rather than averaged.

Retrieval derives lifecycle by replay; it never writes lifecycle state. It
accepts active, unexpired, conflict-free cards for the exact project and only
when privacy stays equal or narrows: a `local_only` card cannot enter
`hosted_restricted` or `hosted_standard`, while a card already admissible for a
hosted scope may be used in a stricter local context. Tamper and duplicates
fail closed, results rank deterministically and stop at three, exact context
charges must fit before any advice is returned, and every advisory exposes its
sources while granting no truth, evidence, execution, tools, or authority.

Factored run evidence keeps route choices—profile, cut and count, executors,
context, budget, verification, sizing ref, and stopping ref—separate from
outcome correctness, rework, latency, usage, cost, integration load,
privacy/authority events, and human disposition. The rule router has fixed
safety-first precedence over exactly the five registered Workflow Profiles.
An unknown safe family resolves to `direct/v1`; an unsafe family refuses. A
learned sizing/stopping recommendation is consumed only with its valid sealed
promotion record and remains advisory to the ordinary split and deepening
gates. Contextual-bandit observations remain inactive, cannot add an
unregistered action, require lineage-disjoint offline and shadow evidence, and
never override the deterministic route or initiate production exploration.
Every accepted model-backed WorkerResult, including best-of-N candidates and
declared Repair nodes, preserves its already validated usage, timing, and
runtime receipt in the canonical event stream so terminal projection cannot
silently infer missing calls.

Issue 186 extends the record with the role and profile dimension: a run whose
plan binds a routing policy records the v2 factored run, whose route record
names the policy's registry generation and digest and the role and resolved
profile behind every node, and whose separate sealed
`orch-dork/factored-role-outcome-record/v1` attributes acceptance, repair passes,
elapsed time, cost, escalations, and human disposition per role and profile.
The Control Tower derives those rows from the verified stream and the plan's
policy and refuses any drift. A producing profile is credited with acceptance,
and with a required human approval, only for work in the verified
deliverable, and with a rejection or an escalation only when it is the sole
producer; a missing value is a typed
unknown with a named reason (`not_dispatched`, `not_observed`, `not_reviewed`,
`not_attributable`, `run_cancelled`, or `cost_unpriced`), never zero or success.
The run-level outcome fields keep their v1 bytes, and an execute-verify-repair
route may count its declared repairs as lanes.

## Closed topology laboratory and inactive Champion/Challenger

Issue 149 adds two pure evaluators behind the Control Tower's closed
`orch-dork/control-optimization-inspection-query/v1`. `kind: topology` accepts
one `orch-dork/topology-lab-program/v1`; `kind: promotion` accepts one
`orch-dork/champion-challenger-program/v1`. The resulting
`orch-dork/control-optimization-inspection/v1` is a submitted inactive
projection. A well-formed outer inspection retains a nested evaluator refusal
as `EVALUATOR_REJECTED`; it does not repair, split, retry, or reinterpret that
refusal.

The topology evaluator admits only sealed `orch-dork/topology-candidate/v1`
records generated from a closed registry. The genome axes are exactly Workflow
Profile, lane count, dependency-aware cut, context policy, join class, finite
depth, executor roles, early-exit condition, model profile, and budget split.
The registry cannot add a profile, model, role, join, context policy, search
operator, or other executable behavior. Every candidate is content-addressed,
and candidate ordering follows the sealed axis order rather than process
completion; the ordered stream binds every candidate identity and decision.

Deterministic feasibility runs before scoring. It checks profile-specific lane
and depth rules, cut/dependency compatibility, join requirements, role
placement, context and early-exit compatibility, exact budget conservation,
and a passing sealed FR54 Topology Closure basis whose declared coverage
contains the candidate. The evaluator derives a same-candidate closure binding;
a failed, missing, or uncovered closure is a named prune, never a low score.
Exhaustive enumeration is the v1 path while the declared product remains
tractable. Any later tree,
evolutionary, Optuna, surrogate, or GPU adapter may propose only registry-valid
candidates and receives no grammar, authority, or activation privilege.

One-process and multi-process enumeration are the same pure function over the
same registry and evidence. Process count affects only CPU work partitioning;
it cannot alter candidate identities, prune decisions, canonical order, metric
records, direct baseline, or Pareto archive. Enumeration streams through a
bounded archive rather than retaining the complete candidate population, and
the public regression covers at least 100,000 candidates. These operating
system processes are not Orch Dork workers and make no provider call.

The content-addressed `orch-dork/topology-pareto-archive/v1` retains separate
axes for correctness and verified coverage, privacy/authority/safety,
critical-path time, tokens and cost, Sol ingress, integration and repair cost,
and evidence completeness. Dominance is component-wise under the declared
direction of each axis. An opaque reward, child count, process count, and
candidate generation order are forbidden objectives. Every archive carries
one feasible budget-matched `direct/v1` baseline. Only feasible nondominated
candidates may appear in an inactive future-Qwen selection record; that record
grants no dispatch, model call, authority, reservation, or terminal claim.
Structural v1 is CPU-only and does not unload, stop, replace, or reconfigure a
resident Qwen service.

The promotion evaluator seals one Champion and any Challenger with the exact
profile registry, compiler, prompt bundle, routing rules, model/runtime
identities, context policy, budgets, and verification policy. Its offline
corpus has nonempty frozen, recent-failure, adversarial, and holdout partitions;
fixture membership is disjoint and holdout lineage is disjoint from training
lineage. Per-fixture results bind safety, privacy, authority, correctness,
human usefulness and its human-review evidence, cost, latency, and source
evidence.

Offline comparison applies immutable gates in this order: all privacy,
authority, and safety checks; correctness; human usefulness; then cost and
latency among candidates that passed the earlier gates. Later gates are
`NOT_EVALUATED` after the first failure. Revalidation derives gate values,
precedence, and decision from the sealed metrics rather than trusting a
caller-resealed decision. The last-known-good Champion remains unchanged. A
passing Challenger is retained only as offline evidence and still requires a
separately specified shadow observation, separately authorized canary, and
forward activation.

Issue 186 binds the registry generation and the routing policy digest into v2
Champion and Challenger configurations and decides one role-default
Challenger's offline stage. The decision verifies that each sealed routing
policy, a reference plan's policy, routes the role through exactly its
configuration's default and no other profile, and that only that role's
routing and identities differ, derives the offline evaluation again
from the same sealed inputs, and permits no activation. The registry's
`role_default_change` replays the decision and refuses, by name, a change
without the Challenger record and the sealed decision, to a profile whose
exact tuple has no release qualification, or on any drift, and refuses every
change as `role_default:promotion_path_incomplete` until shadow observation, a
separately authorized canary, and forward activation are recorded. No run can
change the defaults that decided it, and no default changes.

Both nested evaluators and the Control Tower projection are provider-free and
content-bounded. Append, mutation, production intent, policy change, dispatch,
shadow, canary, activation, automatic suspension, model training, tools,
workers, release, installation, and authority remain inactive. Model calls,
hosted calls, retries, fallbacks, and replacements are exactly zero. No result
may modify the policy deciding its own current run.

## Clarified semantic-delta qualification

`orch_dork_semantic_delta` is an inactive qualification seam for
`semantic-plan-v2.1`. It does not replace the live `semantic-plan-v2` admission
contract. The clarification defines hidden coupling as a source-bound shared-
writer, ordering, compatibility, generated-artifact, or integration constraint
that superficial deliverable counting would miss. Dependency edges remain
separate ordering facts. Every acceptance criterion must map through a
deliverable to a nonempty canonical resource scope; acceptance bullets are not
lanes merely by count.

The delta readiness gate requires the preserved Issue 70 `FAIL`, the provider-
free Issue 71 validity receipt, 36 tasks disjoint from Issue 70, exact 12/12/12
hidden-positive/hidden-negative/ownership-control strata, six predeclared Sol
canaries, and a frozen future budget of 108 independent reviewer calls plus 36
fresh Sol calls. Provider-free readiness authorizes zero calls and keeps Issue
55, Issue 57, and installation blocked. Blind packets omit stratum, expected
output, labels, peer labels, prior Sol proposals, session history, and private-
reasoning requests. Any later collection requires separate exact finite
authority and stops after a failed canary without retry, replacement, or
fallback.

## Finite logical-plan schema

### First-wave recommendation contract

`recommend_first_wave` consumes closed
`orch-dork/wave-estimator-program/v1` evidence: one task and declared touch
set, declared independently verifiable acceptance units, one declared
capability profile, one passing sealed topology prior, a nonnegative scout
bound no greater than 32, and no more typed topology deltas than that bound.
It emits one sealed `orch-dork/wave-recommendation/v1` with `RECOMMEND` or
`REFUSE`, a one-to-thirty-two-lane candidate cut when recommended, per-lane
acceptance units and capability profile, confidence basis points, source hashes
for every recommendation element, and the exact scout allocation used.

The recommendation is advisory input only. It always reports no plan freeze,
worker permission, authority grant, capacity consultation, or ceiling change;
the split decision and every ordinary admission gate remain independently
required. `record_wave_outcome` validates an accepted selection as exact or an
overridden selection with a reason, binds typed realized acceptance, timing,
integration, and trace evidence, and requires the full validated trace document
to match the declared trace digest. Realized lane count, acceptance results,
wall time, and integration cost are re-derived from that document before the
full comparison is appended as `orch-dork/wave-recommendation-outcome/v1` in
the existing chained trace ledger. Invalid contracts and broken chains fail
before any append. Accepting a refusal records a zero-lane `not_run` outcome
with no trace; it can never be relabeled as a successful execution.

### Runtime deepening economic gate

Before root binds a typed decomposition proposal as a flat successor revision,
`evaluate_deepening_policy` consumes one closed
`orch-dork/deepening-policy-program/v1`. The program binds the proposal and
parent plan; the five separate FR47 marginal-value dimensions; remaining
executor, child, and wall-clock budget; an exact capacity observation;
critical-path position and dependency depth; root-owned parent authorization;
sealed Issue 104 decision and integration measurement records; and every gate
constant in force. Malformed inputs return a sanitized `DENY` failure without
a decision record or reflected input value.

A valid result is exactly `ACCEPT`, `DENY`, or `DEFER` and carries a sealed
`orch-dork/deepening-policy-decision/v1`. Every variant has the same named
basis: marginal value, budget, capacity, critical-path position, historical
measurements, and authorization preservation. The marginal basis keeps
verified-coverage gain, critical-path reduction, capability-diversity gain,
coordination cost, and shared-state risk separate; there is no weighted or
scalar score. Gate thresholds are copied into the sealed record as data.
Missing capacity, critical-path, or complete measurement evidence defers;
failed economic or authorization evidence denies.

Issue 104 records are admitted only through
`validate_deepening_measurement_record`, including their original seals and
decision-to-integration linkage. The policy records decision latency, replan
round trip, and integration wall-time comparisons against the supplied gates.
At every dependency depth, each proposed child remains an ordinary node:
read/write and tool scope may only stay equal or narrow, sibling write
ownership stays disjoint, workers cannot spawn, and no parent authority is
inherited. Depth is evidence only and is never compared with a hidden maximum.
The MCP evaluator is read-only and cannot apply a revision, schedule work,
change capacity, or grant authority. A local controller may persist a passing
evaluation with `append_deepening_policy_decision` in the existing chained
trace ledger before separately invoking the ordinary revision and admission
gates.

### Preregistered experiment-campaign contract

`evaluate_experiment_campaign` routes four read-only operations over closed
provider-free contracts: `seal_campaign`, `verify_campaign`, `seal_result`,
and `verify_result`. Sealing converts `orch-dork/campaign-draft/v1` into
`orch-dork/campaign/v1`; its digest covers the exact question, ordered
configuration grid and parameters, replicate count, ordered unique seeds, and
the complete rational-threshold decision rule. Verification recomputes that
material without repair, so any post-seal change fails.

Campaign results bind the exact campaign digest. The preregistered finding
variant must repeat the sealed question and metric and derives default-change
eligibility only from a sealed `pass` outcome plus the campaign's sealed pass
disposition. The exploratory variant contains only its label, summary, and
next campaign question; no default-change field exists, and adding one is an
open-contract failure. These operations execute zero runs and never change a
default. Sweep execution and ledger reporting belong to the separate harness.

`run_sweep_campaign` is that separate, one-way optional adapter. It verifies
the campaign seal, enumerates configuration rows in their sealed order and
each ordered seed exactly once, and gives every cell one closed
`orch-dork/sweep-replicate-request/v1`. The injected adapter must return one
sealed `orch-dork/sweep-replicate-receipt/v1` bound to the request, exact
configuration and seed, `evaluate_governed_orchestration_run`, and
`orch-dork/governed-attempt-program/v1`. V0 accepts only provider-free receipts
with zero model and hosted calls. An exception, malformed receipt, seal error,
or binding mismatch becomes one closed failed-replicate record; it is never
retried, reflected, or allowed to stop the remaining valid cells.

The harness appends the full sealed campaign registration and every replicate
record to the ordinary append-only trace ledger, then discards in-memory
adapter results and returns only `summarize_sweep_campaign` over that ledger.
The summary revalidates the chain, campaign and record seals, expected cell
identity, and uniqueness before deriving any count or score. Missing or
failed-closed cells produce an incomplete configuration and `null` reliability
and mean values rather than an extrapolation. For a complete configuration,
`k` is the sealed replicate count: `pass@k` is the exact finite-sample
probability of at least one success without replacement, while `pass^k` is the
exact probability that all `k` trials succeed at the empirical pass rate.
Both are reduced rational numbers with distinct labels and definitions. The
harness is not imported by policy, campaign-contract, or trace core modules
and owns no plan, spawn, retry, fallback, completion, or default authority.

### First live preregistered sweep

`orch_dork_live_sweep` is the provider-free controller for the first live half
of FR51. Its sealed Issue 111 campaign crosses three task families, lane counts
two and four, two cut strategies, and three ordered seeds: 36 campaign cells.
The historical v1 grant is the human-approved ceiling of 36 cells, 1,500,000
attributable local-Qwen tokens, and 14,400,000 ms from the conservative
pre-dispatch clock. Each family receives 12 cells and 480,000 reserved tokens;
each cell permanently charges 40,000 tokens before dispatch. Its exhausted
registration remains replay-valid but cannot start.

The separately authorized v2 successor grant binds that exact `ABORTED`
predecessor and permits exactly 36 cells, 3,000,000 additional attributable
local-Qwen tokens, and 14,400,000 ms from the first reserved dispatch. Qwen
preparation and review sessions are both zero. Each lane session permanently
charges 27,000 tokens, so two-lane cells reserve 54,000 and four-lane cells
reserve 108,000. Each 12-cell family receives 972,000 tokens; the 2,916,000
campaign reservation leaves 84,000 unreserved. Retry, fallback, replacement,
and hosted-call counts remain exactly zero. A larger re-sealed grant is invalid
rather than treated as fresh authority. Failure preserves the append-only
partial ledger and requires new authority; no rollback or silent reset exists.

The separately authorized v3 measurement successor binds the exact terminal
v2 canonical ledger, its path, and all three family-shard path and complete-file
hashes. It permits exactly 36 fresh cells, 3,000,000 additional attributable
local-Qwen tokens, and 5,400,000 ms elapsed from its first reserved dispatch.
That elapsed limit is an execution ceiling only; it is never a future proof
boundary and `calendar_wait_required` is false. Preparation sessions, review
sessions, hosted calls, retries, fallbacks, and replacements remain exactly
zero. Any differently re-sealed limit or copied predecessor path is refused.

The Issue 113 v4 instrument generalizes the same controller without touching
the historical grids. `build_live_campaign_draft` seals explicit
preregistration axes — families, lane counts one through thirty-two, cut
strategies, named workload buckets carrying `item_count` and
`coupling_density_bps`, and ordered seeds — into the campaign digest, and
refuses any malformed axis. N=1 is cut-degenerate: exactly one configuration
per family and bucket. Workload buckets order deterministically onto the
closed low/medium/high difficulty set the Issue 110 fitter consumes. Coupled
generators plant boundary-crossing finding groups (corroborating evidence,
upstream contract omissions, cross-item dependency cycles) at the sealed
density, so a lane honestly cannot decide a crossing item locally and
`expected_locally_decidable_findings` differs between cut strategies while
global truth stays cut-independent. `build_parameterized_live_grant` derives
the exact v4 grant from any sealed parameterized campaign: campaign-derived
run and family allocations, caller-supplied token/wall bounds, per-lane
reservation, zero retries/fallbacks/replacements/hosted calls, and no
predecessor binding. The fixed Issue 111 v1 grid remains byte-identical for
replay compatibility.

Completion draft v2 is the scored cell-failure seam. A well-observed lane
whose terminal JSON omits its required schema is submitted under
`malformed_lanes` with its raw terminal and its independently observed
FAIL-status runtime observation whose only issue is `terminal:schema_missing`.
The controller revalidates that observation's seal, route, zero-tool exact
usage, and terminal-hash binding; a lane whose terminal actually carries a
schema, or whose observation shows tools, wrong route, or other issues,
refuses the whole draft. An accepted v2 completion permanently records the
cell `failed` with evidence class `malformed_terminal`, a zero metric, all
lane usage including malformed lanes, and the campaign continues under the
unchanged zero-retry rule. Only untrustworthy observation — missing,
contradictory, or tampered route, usage, membership, source, or observer-seal
evidence — still stops the campaign terminally.
Shard, family, join, and campaign projections expose `malformed_runs`,
per-lane session counts, and both `observed_tokens` and
`well_formed_observed_tokens`, so all-cells and well-formed-only analyses
re-derive from the ledger alone. Canonical replicate records carry the
evidence class, and the Issue 110 manifest admits `malformed_terminal` cells
as failure evidence.

Terminal-content trust has one narrower v4 successor seam.
`record_live_evidence_failure` accepts only a complete reservation-bound set
of fresh lane observations whose local-Qwen route, xhigh effort, no-history
context, source seal, exact native usage, and zero-tool fact remain trustworthy.
Its allowlist is `terminal:json_missing`,
`terminal:not_closed_json_object`, and `terminal:conflicting_records`; at least
one lane must carry that sole issue and every other lane must have a fully
valid runtime observation. It appends one sealed
`live-sweep-evidence-failure-record/v1` with no score or outcome, permanently
attributes every observed token/session, and settles the reservation without
retry, fallback, repair, or replacement. Duplicate completion or evidence
settlement is refused. The operator aggregates the sealed same-cause counts
across family shards and owns any separately authorized repetition threshold;
the controller does not invent one.
A v2 draft additionally settles the two-sample stable cause
`terminal:json_missing_stable`: a sealed terminal-absence-stability
derivation (identical source digests observed at least the fixed 5,000 ms
grace floor apart by the same observer) binds to the failing lane and is
archived in the sealed `live-sweep-evidence-failure-record/v2` stability
facts. The stable cause is a distinct same-cause bucket; v1 drafts and
records remain byte-compatible, and the re-read adds no scoring authority.

An all-settled grid may join before its unused deadline. Join v3 includes
completion and evidence-failure usage in attributable totals, but creates
canonical replicate and replay-call records only for scored completions.
Evidence-failure cells remain missing with zero extrapolation, and their
presence forces family/campaign reportability and training eligibility false.
Any untrusted execution fact outside the terminal-only allowlist retains the
immediate stop behavior. Historical join, stop, shard, and report schemas are
unchanged when no evidence-failure record exists.

A one-lane wave is a sanctioned degenerate orchestration: `plan/v1` accepts
`expected_count` of exactly one with matching concurrency, the sole lane is
its own integrator with zero release events, and the two-through-four-lane
band is unchanged. This carries G10/FR49's mandate that the sizer may answer
one lane through the governed gates. `stop_live_campaign` accepts the v4
parameterized grant exactly as it accepts v3, over the campaign's own family
set, so a parameterized campaign's recorded early-stop threshold is
executable.

V1 token attribution includes every local-Qwen session undertaken for campaign
preparation or execution after the campaign is registered, even when no
measurement cell was reserved. `abort_live_campaign` is the fail-closed
pre-start incident transition for that grant: it accepts independently
observed session and usage hashes only when their exact total exceeds the
sealed grant, records the overage and zero reserved cells, and changes the
ledger state permanently to `ABORTED`. An aborted registration cannot start or
be silently reused; a successor campaign requires new explicit human
authority. V2 attribution is successor-execution-only and preparation/review
counts remain zero. V2 registration
re-reads the predecessor chain and binds its campaign, grant, replay plan,
registration, abort, complete-ledger and path digests, exact 2,442,060-token
attribution, 942,060-token overage, zero reserved cells, and no start record.

`register_live_campaign` appends the campaign and grant and registers one
campaign-bound replay plan before start. `start_live_campaign` refuses a
missing or invalid plan, fixes one deadline, and creates three independently
appendable family shards bound by path hash to the canonical start record.
`reserve_live_replicate` admits only the exact configuration, replicate index,
ordered seed, family allocation, and unspent cell. The module makes no model,
worker, command, or transport call. Native creation remains outside this
adapter and must pass the ordinary admission, plan, spawn-wave, custody, trace,
and terminal gates.

`complete_live_replicate` accepts a result only when those governed receipts
are present and every lane has an independently validated runtime observation
for `qwen-local/qwen-smart`, `xhigh`, no inherited context, no tool calls, a
terminal JSON body bound to the lane result, and exact observed token usage.
The sum must fit the permanent cell reservation and completion must precede the
global deadline. A malformed, mismatched, late, or over-budget result does not
append and cannot trigger a replacement.

`join_live_campaign` is root-owned integration. It revalidates all three shard
chains and bindings, then archives completed cells in sealed campaign and seed
order regardless of execution order. An early join requires all cells; at the
deadline an incomplete join is allowed but every absent completion remains a
missing run with `extrapolated_runs: 0`. Three sealed family summaries and one
canonical join record bind the exact counts, usage, source records, and replay
records. Public reports expose hashes and typed aggregates only. They label
verified-success score and outcome as replay-decidable, while custody, route,
timing, and token usage remain live-required. Complete canonical live records
are admissible `training` sweep examples for learned sizing/stopping; an
incomplete live campaign is never a training source.

An explicit Owner direction may end the unspent v2 campaign window before its
fixed deadline without changing that deadline or any prior timestamp.
`terminate_live_campaign` is the provider-free, successor-only recovery seam.
It requires the exact canonical and three family-shard complete-file hashes,
one structurally present completion, and a concrete contradiction whose bound
custody and trace hashes match that immutable completion while corrected hashes
differ. It permits exactly one finalizer invocation and zero Qwen, model,
hosted, token, reservation, retry, fallback, or replacement use.

The transition appends exactly one canonical Owner-termination record. It does
not rewrite a shard, delete the invalid completion, invoke the ordinary join,
or create family-summary, canonical-replicate, or replay-model-call records.
The record preserves the original deadline, truthful termination timestamp,
environment, limits, material risk, recovery trail, usage audit, and both sides
of the contradiction. Its terminal projection is
`INCOMPLETE_EVIDENCE_FAILURE`: the contradicted cell is quarantined, has no
reportable score or outcome, and is never training evidence; undispatched cells
remain undispatched and all missing runs have `extrapolated_runs: 0`. Any hash,
binding, evidence-class, or append mismatch refuses without mutation. A
successful transition blocks every later reservation, completion, or mutating
join. Append-only recovery has no rollback; a partial or failed append requires
fresh Owner authority.

For v3, `stop_live_campaign` is the immediate provider-free terminal seam for
an Owner stop, execution failure, resource limit, or evidence failure. It
requires exact canonical and shard hashes plus fresh drain evidence showing
zero campaign workers, dispatchers, result writers, `codex exec` producers,
active worker sessions, pending deliveries, and Qwen running, waiting,
capacity-blocked, and deferred requests. It appends one terminal stop record
without waiting for the unused execution ceiling, preserves every partial
reservation and completion, reports no extrapolation, and makes the campaign
non-reportable and training-ineligible. Reservation and completion refuse the
stop fence, and join returns its read-only terminal projection without append.

### Structural zero-tool live-lane transport

`orch_dork_live_zero_tool` is the Issue 133 measurement-only transport
boundary downstream of `orch_dork_live_sweep`; the live-sweep controller does
not import it and retains campaign, grant, reservation, settlement, and stop
authority. This local-Qwen wire contract is retained for historical validation
only and must not be invoked while that runtime is offline; a hosted successor
requires a separately specified and qualified wire contract. The closed
`orch-dork/live-zero-tool-request/v2` binds one
exact campaign, grant, reservation, lane assignment, request identity,
`qwen-local/qwen-smart`/`xhigh`/no-history route, strict lane-result JSON
Schema, output/total-token ceilings, response-byte ceiling, and timeout. The
namespaced request selector and logical route remain
`qwen-local/qwen-smart`; provider routing resolves that selector to the fixed
returned Responses wire identity `qwen-smart`. Both sides of that mapping are
closed transport material. The Responses body is re-derived from the sealed
assignment and has exactly the namespaced selector, no obsolete
`include_reasoning` field, an empty `tools` array, `tool_choice: none`, disabled
parallel tool calls, non-streaming/store-false execution, and no
previous-response or conversation identifier. Reasoning remains enabled at
`xhigh`, its visible summary remains disabled, and its exact token count remains
required. Immutable v1 requests retain their original
`include_reasoning: false` and one-message validation for replay only. A
caller-resealed request, native tool catalogue, alternate request selector or
response identity, or prompt-only promise fails validation.

The strict Qwen generation schema deliberately omits xgrammar-unsupported
`uniqueItems`. The semantic observer remains authoritative: both item arrays
must equal their sorted sets, remain disjoint, and contain only identifiers
from the sealed assignment. Provider acceptance therefore never substitutes
for semantic validity.

The v2 response observer accepts one completed assistant message with exactly
one `output_text` item, optionally preceded by one exact opaque OpenCodex 2.35
`ocxr1` reasoning envelope. The envelope has only an identifier, `reasoning`
type, empty summary, and bounded canonical encrypted content containing one
non-empty `txt` member. It may never carry visible summary/content or appear in
terminal output, a receipt, runtime observation, or campaign evidence. The
response must report the fixed `qwen-smart` wire model. The observer projects
the bound logical `qwen-local/qwen-smart` route into the sanitized receipt and
runtime observation. A missing envelope field, reordered or duplicate item,
visible or malformed reasoning, second message, tool item, continuation,
alternate alias, malformed terminal, source mismatch, or inexact usage
produces no receipt or runtime observation. The v1 observer continues to
refuse every reasoning item.

`invoke_loopback_once` grants no authority. After the ordinary external gate
supplies the exact matching campaign/grant/reservation binding, it accepts only
a literal HTTP loopback `/v1/responses` endpoint and dedicated credential,
performs one POST, follows no redirect, persists the bounded raw response to a
create-only owner file, and has fixed zero retry, fallback, and replacement
counts. Provider-free tests use an injected sender and make zero model calls.

Invocation report v2 treats a bounded non-200 as terminal transport failure,
not as an opaque exception. It preserves the exact response bytes only in the
owner file and exposes one closed
`orch-dork/live-zero-tool-transport-failure/v1` object: exact status and status
class, one of `redirect_refused`, `request_rejected`,
`credential_rejected`, `route_not_found`, `rate_limited`, `client_failure`,
`server_failure`, or `unexpected_status`, an allow-listed media type (or
`other`/`unknown`), elapsed milliseconds, response byte count, and response
digest. The public report contains no endpoint, credential, headers, request,
prompt, raw response, path, or private reasoning. It has no receipt or runtime
observation and does not infer whether the service invoked the model; attempted
usage remains `UNKNOWN`, `attempted_requests` remains one, and `model_calls` is
`null`. The failure permits only drain and terminal stop under the existing
authority—never retry, fallback, replacement, continuation, endpoint/key
substitution, or settlement.

The active response observer accepts exactly one completed response, at most
one exact hidden-reasoning envelope, one assistant message, one output-text
item from the fixed `qwen-smart` response-wire identity, no continuation, no
request or response tool, one closed schema-conforming terminal object, and
exact internally consistent usage within both ceilings. It projects the bound
logical `qwen-local/qwen-smart` route separately. Any other extra output,
visible/malformed/reordered reasoning, tool-call item, route mismatch,
error/incomplete state, malformed terminal,
unknown usage component, overage, duplicate JSON key, oversized body, source
digest mismatch, or authority cross-wire fails. A passing
`orch-dork/live-zero-tool-receipt/v1` contains only hashes, bindings,
allow-listed route and usage, terminal digest, and zero-tool/continuation
facts. It projects the same facts into a valid existing
`orch-dork/session-runtime-observation/v1`; neither public object contains the
prompt, assignment, raw response, endpoint, credential, session body, or
private reasoning. Normal tool-enabled worker execution is unchanged.

### Provider-free pre-authorization transport qualification

`qualify_zero_tool_transport(request, runtime_closure)` is the Issue 140
admission boundary between a deterministic zero-tool request and any new active
authority scope. It executes the bundled interpreter and shipped probe through
`orch_dork_process_containment`, with an environment restricted to `PATH` and
`LC_ALL`, against the exact installed OpenCodex Responses parser, OpenAI-chat
adapter, Responses bridge, and fixture provider. It performs no loopback POST,
credential lookup, network request, model call, hosted call, retry, fallback,
or replacement.

The probe uses fixed content-only and reasoning-rich upstream fixtures. It
requires the parser to preserve the closed tool-free/hidden-reasoning
semantics, the adapter and bridge to emit either one content-only Responses
message or the exact opaque-envelope-plus-message shape, and the ordinary
strict Orch Dork observer to accept the resulting model, usage, source, and
terminal bindings without copying the envelope. A separate schema-vocabulary pass
refuses unsupported structured-output keywords before process launch. The
runtime identity hashes package metadata, the bundled interpreter, named entry
modules, the complete installed OpenCodex `src` and imported `zod` source
trees, and the exact Orch Dork request, observer, qualifier, probe,
containment, and recovery sources. Added, removed, or changed bytes expire the
receipt.

The only public result is a closed
`orch-dork/zero-tool-transport-qualification/v1` report containing stable issue
codes, semantic case summaries, source-tree aggregates, and hashes. It contains
no host path, request or response body, prompt, environment value, credential,
endpoint, or private reasoning. A FAIL is diagnostic only and emits no active
authority scope, decision sheet, bundle, grant, registration, reservation, or
live call. Qualification proves deterministic local translation compatibility;
it does not predict network availability or stochastic model correctness.

### Failure-aware live-tranche succession

`orch_dork_live_recovery` is a provider-free policy boundary between a failed
measurement tranche and any proposed successor. The shipped Issue 111 v8
history specification pins the complete v4-v7 campaign/shard files and the v7
contract-failure artifact. Derivation revalidates their append-only chains,
campaign and grant seals, registration/start/terminal records, reservation and
completion records, shard source-path hashes, runtime observations, and exact
file/record digests. Missing or changed evidence refuses; an unsettled
reservation remains `UNKNOWN` and is excluded visibly rather than assigned a
narrative token count. A reservation is classified as a non-session only when
a sealed terminal join's reservation/completion/failure counts and exact live
model-call total prove that all unsettled slots made zero model calls; any
other non-evidence-failure unsettled reservation blocks derivation.

Population semantics distinguish outcomes by evidence class. A scored or
otherwise compliant single-response zero-tool lane may enter the matching
lane-count estimator. A response continued after a forbidden tool call is a
transport-failed lane: it informs the terminal transport rule but cannot enter
the normal-lane distribution, raise its estimate, excuse a later overage, or
be counted as an ordinary malformed terminal. The reproducible manifest seals
the resulting counts, distributions, exclusions, unknowns, predecessor
digests, and zero-call projection.

Every new successor additionally carries one
`orch-dork/live-recovery-terminal-predecessor/v1` capsule derived by
`derive_terminal_predecessor_capsule` from the exact immediate owner-private
terminal root. Derivation requires owner-only regular files and revalidates the
terminal-summary and authority-consumption seals, consumed/no-continuing-
authority facts, canonical and family-shard chains, stop projection, dispatch
and one-shot invocation reports, UNKNOWN attempted usage, undispatched second
lane, and raw-response digest. Its projection contains only closed facts and
hashes—never a host path, response body, request, credential, or private
reasoning. Missing, changed, open-permission, cross-wired, or re-sealed evidence
refuses.

The predecessor validator has two closed source profiles: the earlier
replay-compatible generation and the immutable Issue 111 r4 summary,
authority-consumption, and lane-dispatch generation. r4 artifacts are validated
under their own schemas before their policy facts enter the shared checks; the
capsule always retains the original source-generation seals, so normalization
cannot rewrite or re-authorize historical evidence.

`build_v8_successor_packet` emits additive packet v2 for deterministic replay.
It binds the exact current plugin version and zero-tool module digest, the
complete predecessor capsule, one N=2 cell, one cell in flight, fixed
token/byte/time ceilings, and zero preparation, review, retry, fallback,
replacement, or hosted calls. `validate_v8_successor_packet` re-derives that
capsule from the same required `terminal_predecessor_root`; a self-seal alone
is insufficient.

`build_v8_qualified_successor_packet` is the only authorization-ready generation. It
freshly executes and binds a passing installed-runtime qualification to packet
v3. `validate_v8_qualified_successor_packet`,
`v8_authority_scope_sha256`, `render_v8_decision_sheet`,
`write_v8_recovery_bundle`, and `grant_from_v8_packet` each independently
re-read the terminal root and re-run the exact qualification. Missing roots,
FAIL, source drift, report drift, or a stale qualification refuses. Legacy v1
and successor v2 packets and validators remain deterministic replay surfaces,
but neither generation can enter the active scope, authority-sheet, grant, or
bundle path. A v3 create-only bundle preserves the historical manifest,
sanitized predecessor capsule, qualification-bound packet, authority audit sheet, and
receipt under owner permissions without publishing host paths.

`orch_dork_standing_authority.standing_owner_policy` returns one closed,
versioned policy whose digest binds the eligible authority classes, exact
class-contract scope admission, one registration per binding, and no continuing
authority after terminality. `bind_standing_owner_authority` accepts only a
known class and valid semantic-scope digest, and derives its source digest from
the policy digest, class, and scope. Automatic grant conversion emits additive
live-grant v5 carrying that exact binding. Before any campaign-ledger append,
registration requires a transient `standing_authority_context`, reruns the
class-specific grant converter against its packet and required runtime roots,
and requires the regenerated campaign and grant to match exactly. It then
atomically creates an owner-only claim named by the source under fixed
owner-local standing-authority state. Missing context, mismatch, an existing
claim, unsafe state, or write failure refuses without fallback; a claim remains
consumed if a later ledger step fails. Explicit replay grants remain v4 and
carry no standing claim.

For ordinary tranche dispatch, `dispatch_runtime_closure_sha256` binds every
shipped Python/TypeScript runtime script and the semantic scope also binds the
fully derived grant execution contract. Complete canonical packet reproduction
is still required. Standing v5 registration receives that packet and plugin
root in its transient context; the root must equal the dispatch converter's
executing plugin root, never another checkout. Registration reruns
`grant_from_packet` and requires the exact campaign/grant before claiming the
source. Historical explicit tranche authority is an opaque
source-only digest: valid input remains replay-compatible after reproduction,
while malformed input refuses and never selects standing authority. Qualified
recovery retains its explicit source-plus-approved-scope pair and refuses any
mismatch.

`v8_authority_scope_sha256` derives the v3 standing-authority target from the campaign,
grant terms, transport runtime-closure digest, failure-aware historical
evidence, predecessor/manifest bindings, immediate terminal-predecessor capsule
digest, passing qualification digest, and terminal rule. It excludes
`prepared_at`, `plugin_version`, and the packet-artifact digest. The target
packet must still validate against the exact current runtime, OpenCodex source
closure, and terminal root. `grant_from_v8_packet` called without authority
hashes repeats both local qualifications, binds the exact scope through
`orch_dork_standing_authority`, and derives the matching bounded campaign grant
without a per-run Owner message. Automatic conversion emits standing v5;
explicit replay conversion remains v4. A standing binding may accompany a different
packet digest only when the derived scope matches exactly; any scope mismatch,
prior consumption, terminal PASS, or terminal failure requires a fresh
validated one-use binding. Malformed or mismatched explicit authority never
falls back to standing authority. Registration or a model call before that
binding is unauthorized.

### Hash-keyed record/replay and holdout demotion

Before the first model call, `seal_replay_plan` and `register_replay_plan`
bind one `orch-dork/record-replay-plan/v1` to the exact campaign digest. The
plan seals a baseline `orch-dork/replay-score-policy/v1` and a nonnegative
exact rational holdout tolerance. This pre-call registration is the campaign's
preregistered replay tolerance; neither `replay_campaign` nor holdout evidence
can supply or replace it later.

`record_model_call` runs at the optional adapter's model-call boundary after
the provider-free or live sweep campaign registration. Each closed
`orch-dork/model-call-record/v1`
binds its exact configuration, replicate index, seed, governed report digest,
baseline policy digest, derived baseline score, full bounded JSON request and
response, canonical request hash, and canonical response hash. The bodies are
lossless for the closed score policy and remain only in the local ledger.
Duplicate cells or request hashes fail before append. Public record reports
contain hashes, the exact rational score, and typed counts only; no request,
response, prompt, or generated text is projected. Request and response bodies
must each satisfy the hostile-input profile, and their combined sealed record
must satisfy the same canonical byte bound; combined overflow returns the
closed `model_call:record_too_large` reason before any append.

`replay_campaign` accepts only the campaign, ledger path, and one sealed score
policy. It exposes no model or transport callback. Replay requires exactly one
valid model-call record for every sealed configuration/seed cell, revalidates
each body hash and baseline score, and refuses an unrecorded cell or unscorable
response with zero model and hosted calls. An unchanged policy must reproduce
every recorded score exactly. An alternative policy emits a sealed
`orch-dork/counterfactual-replay/v1` containing only source record hashes,
request/response hashes, typed cell metadata, and exact rational scores; its
initial conclusion is `hypothesis_generation_pending_holdout` and can never
change a default.

`record_live_holdout` appends closed lineage-disjoint score observations and
then derives one `orch-dork/replay-holdout-conclusion/v1` from the replay,
holdout, and preregistered plan records. Absolute mean-score disagreement above
the sealed tolerance is automatically `hypothesis_generation_only`; agreement
is `holdout_consistent`. Both remain `default_change_eligible: false`.
`summarize_holdout_conclusion` revalidates the chain, all source seals and
cross-campaign bindings, and recomputes the means, disagreement, tolerance,
demotion, and label from ledger records. Its report exposes no recorded body.
The module is downstream of the sweep adapter and is never imported by policy,
campaign-contract, or trace core.

### Learned sizing, stopping, and promotion

`derive_training_manifest` consumes a closed
`orch-dork/learned-training-request/v1` and fixed append-only source prefixes.
Every requested sweep campaign must be complete and every configuration must
declare the exact `training` partition plus task family, difficulty bucket,
lane count, cut strategy, capability profile, and stopping margin. Sweep
inputs may include canonical completed live-sweep records, but their custody,
route, timing, and token facts remain live evidence rather than replay inputs.
Dogfood inputs remain in their host-local chains: the adapter reads each exact
declared head, requires the standing reportability floor of blind effective
records,
and projects only sealed entry hashes, compact task family/difficulty/action
features, and exact rational outcome scores. It never copies or combines
corpus files. The sealed `learned-training-manifest/v1` enumerates every source
record and lineage hash and proves that evaluation tasks, hidden tests, and
control outputs selected for training are all zero. Re-running derivation at
the same ledger checkpoints must reproduce the manifest byte-for-byte.

The dogfood reportability floor is twenty qualified blind independent real-run
verdicts, not twenty humans. Human records retain their original v1 chain and
model verdicts retain a separate provenance-typed chain. The provider-free
combined projection may count either source once per run only after exact
packet, evidence-reference, provenance, blindness, host, and chain validation;
it reports source-specific rates and refuses cross-source duplicates. An
abstention, non-blind answer, malformed output, unresolved spine, or rejected
answer never satisfies the floor. A model verdict remains judgment evidence,
not runtime fact, terminal qualification, authority, or a benefit claim.

`build_model_request` emits the closed
`orch-dork/dogfood-model-request/v1` transport artifact. It binds the exact
packet and rubric digests, a static instruction-template digest, the rendered
packet-only instruction, one Draft 2020-12 JSON Schema and its digest, the
packet context policy, and its own canonical digest. The schema fixes every
answer field inside one closed required top-level `answer` envelope,
packet/rubric constants, closed verdict values, verdict-versus-abstention
applicability, and every evidence-reference item to an identifier present in
that packet. The two complete closed answer objects are a nested supported
`anyOf`, never an unsupported root union or `oneOf`; all object properties are
required, optional justification values are explicitly nullable, every object
sets `additionalProperties: false`, and repeated packet-local identifiers use
one `$defs` enum. The importer unwraps only the exact one-field envelope before
running the unchanged flat-v1 semantic checks. The request contains no provider/model
selection, aggregate, prior label, peer verdict, source path, credential, raw
session, or private reasoning. `verify_model_request` re-derives every field;
a changed instruction, schema, digest, or context policy is refusal evidence.

The request is provider-free and makes zero model calls. A transport may use
its schema to constrain formatting, but that does not establish intelligence,
semantic validity, blindness, context isolation, or zero tool use. Only the
existing answer normalizer plus packet/provenance/chain validation may accept
a verdict. Surrounding prose is never stripped, parsed around, or repaired.

`fit_learned_policy` is a deterministic empirical lookup fitter, not a model or
third-party framework. For each observed task-family/difficulty pair, blind
dogfood outcomes may calibrate lane-count ranking only among counts backed by a
complete sweep action; cut, capability profile, and stopping margin always come
from that sweep evidence. It emits both a first-wave sizing rule (one through
thirty-two lanes, cut, capability profile) and a deepening stopping-margin
rule. `evaluate_learned_policy` is the public read-only
inference seam. A known pair receives those two advisory signals; an unknown
family or difficulty pair falls back to `standing-defaults/v1`. Either way the
ordinary split and deepening gates remain required, and the evaluator cannot
freeze a plan, mutate a default, permit workers, or grant authority.

`evaluate_policy_promotion` re-derives the training manifest and requires the
candidate policy to bind it exactly. Evaluation must be a later registered and
complete sweep campaign, use only the exact `evaluation` partition, bind the
candidate and `standing-defaults/v1` in one candidate/default pair per family,
and carry lineage hashes disjoint from every training example. Only a sealed
preregistered `campaign-result/v1` whose decision-rule outcome is `pass` and
whose own contract marks it default-change eligible can enter comparison;
exploratory findings, replay/holdout conclusions, stale evidence, incomplete
campaigns, and lineage overlap refuse before a promotion record exists.

Exact rational family comparisons produce one sealed append-only
`learned-policy-promotion/v1`. A candidate that beats no family is durably
`BEATEN` with `candidate_retained: false`. A candidate that transfers across
all evaluated families is `PROMOTE_GLOBAL`. Mixed transfer is
`PROMOTE_PER_FAMILY`: only winning family rules remain candidates, a closed
family classifier maps losing families to the standing defaults, and unknown
families also fall back. Promotion records express eligibility only;
`default_changed` remains false and actual default mutation is outside this
provider-free layer.

Use `orch-dork/logical-plan/v1` when semantic planning identifies any finite
positive number of independently ownable workers. The plan records an exact
worker list, dependencies, resources, verification, explicit authority, and a
profile. An optional positive `task_node_budget` freezes the root-approved
maximum cumulative node count across later plan revisions and must be at least
the current `logical_worker_count`; it is an economic/run budget, not live
capacity. The plan deliberately contains no live-capacity or
maximum-concurrency value; `validate_logical_worker_program` reports live
capacity as `not_consulted`. The supported profiles are `single_worker/v1` for
atomic Sol work, `first_completed_worker/v1` for the historical two-to-four-
worker contract, and `finite_dag/v1` for a larger dependency program. Workers
always have `workers_can_spawn: false`.

For hard governed admission the otherwise compatibility-optional fields are
mandatory: `planner.effort`; closed `project` identity (project/protocol,
binding generation and manifest digest, exact workspace root and digest,
required resource surfaces, research-manifest requirement, source pointer);
closed `generation` identity (source, installed, and task-loaded versions plus
fresh-task fact); and `acceptance_resource_closure`. The closure accepts path,
semantic, generated, install, and publication surfaces. Every surface required
by project identity must appear in an exactly owned compatible phase before
the v3 preflight can authorize spawn.

Under `first_completed_worker/v1` the trace qualifier selects the integrator
at runtime: whichever lane finishes first performs integration. A plan that
pre-designates an integrator node in the plan body under that profile is
still structurally invalid. The declaration path is the plan's frozen
`acceptance_resource_closure.integration_owner`: when it names a lane, that
lane integrates whether or not it finishes first, every other planned lane
releases to it, and a trace that integrates through the wrong lane issues
`integration:declared_integrator_not_designated`. When integration must belong
to a known node -- a dedicated join, a different model profile, or work that
depends on every lane -- use `finite_dag/v1` with `dependency_ordered`
integration instead.

Every node's declared `deliverables` must fall inside that node's own
`owned_resources`. Custody derives lane scope from `owned_resources` alone,
so a deliverable outside it makes each required write an out-of-scope access;
plan validation rejects this at freeze rather than after the wave runs.

`run_logical_worker_waves` accepts replay-only
`orch-dork/wave-program/v1`, advisory compatibility `orch-dork/wave-program/v2`, and
hardened `orch-dork/wave-program/v3`. Each
supplied observation contains a fresh collaboration inventory, exact creation
receipts, terminal results with exact-or-unknown usage pointers, and structural
custody events. The controller deterministically selects ready worker IDs up to
free capacity, computes custody through the existing custody validator, and
emits `orch-dork/wave-report/v1`. It never launches providers or polls. Partial
or ambiguous waves are terminal failures with reuse and replacement forbidden.

V3 is required for governed substantive delegation. Before consuming an
observation it requires one passing observer-bound route preflight for every
distinct subagent model profile and checks the preflight route against the
frozen logical-plan routing table. A fresh canary returns
`HandoffPreflightCandidateV1`, which carries no native route, session, usage,
tool-count, source, or evidence-tier claim. The session-runtime observer binds
exact rollout bytes, no-history route, candidate schema and terminal JSON
digest, and native usage/tool count; only then does the controller derive the
incremental packet and project `HandoffPreflightV1`. A submitted evidence tier
cannot satisfy v3. Every wave composes wave-routing v3 against
the exact creation membership and validates live progress prefixes with unique
packet IDs/digests, monotonic usage, and positive completion reserve before
custody or terminal acceptance. Every terminal then requires observed budget
evidence and a status-compatible typed handoff; free-form terminal text is
forbidden. Failure authorizes no retry, replacement, or fallback.

V2 is the typed advisory logical-wave path. Its caller-authored runtime tier
does not prove independent observation or permit a terminal claim. Advisory
`plan/v1` runs may instead use the admitted spawn-wave and submitted-trace
contracts. V1 reports `deprecated: true`, `qualification_scope: replay_only`,
and migration target `orch-dork/wave-program/v3`.

Each sanitized `route_preflights` report row identifies the model profile,
TaskSpec, projected preflight and handoff/packet digests, independent runtime
observation digest, session and source pointer. Candidate mode additionally
reports `candidate_sha256`; `observed_route` and `observed_usage` are always the
normalized facts that reached the projected preflight gate, never raw session
content.

`orch-dork/wave-routing-program/v3` binds the frozen expected
membership to observed sessions. Every expected member is an exact
`{lane_id, role, worker_id, session_id}` record; every lane repeats that bound
identity beside its extracted session-routing report. The verifier requires
complete set equality, unique worker and session IDs, exact own-session
agreement, frozen model/effort agreement, and a valid sealed
`orch-dork/session-runtime-observation/v1`. Canonical leading-slash
collaboration task paths are preserved as native worker IDs.

This logical-plan path is the policy-server freeze-and-qualify surface for a
dependency program; no caller-authored bridge through `orch-dork/plan/v1` is
needed. That compatibility schema cannot honor ordering or capacity waves, so
any non-empty lane `dependencies` fails its plan validation with
`orchestrated:dependencies_require_finite_dag_logical_plan` before freeze. The
named refusal prevents a hashed dependency from becoming decorative evidence.

`evaluate_sol_replan` consumes `orch-dork/replan-program/v1` and returns
`orch-dork/replan-report/v1`. It binds the active logical-plan hash and
revision to one persisted Sol root and a closed history of plan revisions,
node results, artifacts, custody pointers, exact-or-unknown usage, and hard
limit decisions. A submitted revision must be exactly next, link the active
plan hash, be authored by that bound Sol, and carry explicit provider-free
replan authority and decision basis. The report records retained, added,
removed, and dependency-changed nodes. Failed work is never rewritten; only
transitive dependants block, and unrelated ready nodes remain schedulable.
Partial acceptance, scope change, or additional authority stays in an explicit
bounded Sol decision state. No retry, replacement, fallback, resume, or nested
delegation is inferred.

`run_active_orchestration_controller` consumes
`orch-dork/active-controller-program/v1` and returns
`orch-dork/active-controller-report/v1`. It replays a closed ordered event
stream through mechanical admission, scheduling, membership, custody, release,
duplicate-prevention, and external-terminal-handoff rules. Capacity,
completion, failure, release, authority, timeout, and terminal-observation
events advance the controller without model-driven polling. Only ambiguity,
conflict, partial acceptance, replan, authority or scope expansion, quality
tradeoff, and final semantic acceptance wake Sol. Each wake emits a versioned
`orch-dork/sol-decision-packet/v1` containing only post-cursor material changes,
worker/dependency state, new evidence pointers, bounded options, authority,
exact-or-unknown usage and context telemetry, and completion reserve. Project
adapters may add stricter blocks and protected resources but cannot weaken the
core lifecycle. Unsupported active enforcement or adapter failure is explicit;
governed use never silently becomes advisory.

## Advisory scan and native-observation schemas

`evaluate_advisory_scan` owns a separate read-only workflow for bounded project
scans. It consumes the closed `orch-dork/advisory-scan-program/v1` record with
exactly `schema`, `operation`, `scan_id`, `root`, `objective`, `lanes`,
`authority`, `protected_resources`, `limits`, and `runtime`. It never creates a
worker, contacts a provider, grants authority, mutates a resource, retries,
falls back, or issues a qualification claim.

`prepare` requires `runtime: null`, parent-granted read-only authority, positive
context/output/handoff/tool limits, and two through sixteen unique lanes. Each
lane declares exactly its ID, objective, read and excluded scopes, deliverable,
verification list, and allowed tools. A passing report returns one validated
`finite_dag/v1` logical plan plus one exact read-only `TaskSpecV2` and digest per
lane. The preparation receipt binds the logical-plan digest and complete lane
to TaskSpec-digest map. Its state is `execution_status: NOT_STARTED`,
`handoff_status: NOT_STARTED`, and `qualification_status: ADVISORY_ONLY`.

`finalize` recomputes that preparation from the unchanged program and requires
an exact matching receipt. Its `runtime` has exactly `preparation`,
`creation_results`, `terminal_results`, and `root_verification`. Creation
membership is total and unique and binds every fresh worker to the declared
root. Every terminal binds the same worker, a terminal status, the exact
same-TaskSpec `HandoffReceiptV1`, exact-or-unknown usage with a source pointer,
zero or more valid `IncrementalClaimPacketV1` records, and complete-or-unknown
custody with a source pointer. Root verification must cover the exact lane set.

Completion and qualification are intentionally orthogonal. All completed lanes
with valid handoffs and root verification return `COMPLETED_ADVISORY`,
`execution_status: DRAINED`, and `handoff_status: COMPLETE` even when usage,
packets, or custody are explicitly unknown. Those gaps remain sorted in
`evidence_unknowns`; `qualification_status` stays `ADVISORY_ONLY` and
`claim_permitted` stays false. A failed/cancelled/timed-out lane, invalid
handoff, membership mismatch, or incomplete root verification returns
`FAILED`. Unknown evidence is never rewritten as zero, and a failed lane is
never rewritten as advisory completion.

`orch-dork/advisory-scan-program/v2` is additive. Preparation emits v2
preparation and report receipts; finalization adds exactly one
`native_observation` field to the v1 runtime fields. An `observed` binding
carries one complete sealed `orch-dork/native-scan-observation/v1` report. The
finalizer verifies both seals and exact scan, root, lane, parent, created-worker,
route, and usable terminal membership before retaining a compact digest-bound
projection in its own receipt. Missing exact usage may remain explicitly
unknown; another lane-level observer failure is contradictory and fails.

An `unknown` binding contains exactly `status`, `reason`, and `source_pointer`.
The reason is either `native_session_records_unavailable` or
`native_observer_unavailable`. It may preserve an otherwise completed advisory
result, but remains namespaced in `evidence_unknowns` and never permits a
qualification claim. Omission, open fields, arbitrary reasons, invalid seals,
or observed contradictions fail. A caller must not replace a failing observer
report with unknown. V1 programs and deterministic receipts remain unchanged
for replay.

`observe_native_advisory_scan` composes existing runtime observers without
searching the session store. Its closed
`orch-dork/native-scan-observation-program/v1` contains exactly `schema`, one
independent `observer_id`, one existing exact-hash
`orch-dork/attempt-observation/v1` manifest, and `signing`. The manifest must
declare two through sixteen full-file-hash child sources. The adapter first
requires the canonical attempt observer to bind the graph, then invokes the
canonical session-runtime observer against each declared child path and exact
worker ID. A source digest mismatch refuses the whole observation.

The `orch-dork/native-scan-observation/v1` report contains only attempt and
session digests, root/lane/worker/parent IDs, allow-listed route facts, terminal
schema and digest, exact-or-unknown usage, line/hash pointers, stable issue
codes, and counts. It emits no filesystem path, prompt, message, terminal body,
reasoning, credential, or private signing material. Top-level `status: PASS`
means the bounded observation operation and graph binding succeeded;
`observation_status` separately says `COMPLETE` or `PARTIAL`, and
`qualification_evidence_status` separately says `EVIDENCE_COMPLETE` or
`EVIDENCE_INCOMPLETE`. `claim_permitted` is always false.

`signing.mode` is either exact `none` or exact `host` with bounded issuance,
expiry, and nonce fields. Host mode reads only the fixed provisioned observer
authority and signs a compact attestation over the observation digest and lane
source-digest map with `FileHostSigner`; callers cannot supply a key or trust
root. Missing or invalid authority refuses signing without exposing a host path
or secret.

These v1/v2 advisory contracts do not replace or relax wave-program v2/v3.
Wave v2 continues to require typed packets and observed budget evidence; wave
v3 continues to require independent runtime routing, preflight, progress,
custody, and terminal qualification. An advisory unknown cannot satisfy either
contract. Codex remains the physical worker-lifecycle authority; Orch Dork's
observation binding is evidence and logical policy, not process control.

## Adaptive finite-DAG and typed-contract schemas

`adaptive_finite_dag/v1` is a bounded sequence of root-owned revisions of one
`finite_dag/v1` logical plan. It is not a recursive worker tree. A worker may
propose a split but cannot create workers, approve the proposal, make a plan
effective, or decide terminal success. The existing
`orch-dork/decomposition-proposal/v1` wire shape is the compatibility seam
named `PlanPatchRequestV1`; only the current root/Sol may approve its compact
patch, and the provider-free controller binds the exact successor revision.

`evaluate_adaptive_finite_dag` consumes the closed
`orch-dork/adaptive-finite-dag-program/v1` object with exactly these fields:

- `schema`, `controller_id`, `current_plan`, `decomposition_proposal`, and
  `proposal_approval`;
- `limits`, containing exactly `max_logical_depth`, `max_node_retries`,
  `max_active_revisions`, `max_nodes`, `max_sol_ingress_tokens`, and
  `max_total_tokens`;
- `consumption`, containing exactly `logical_depth`, `active_revisions`,
  `node_retries`, `completed_node_ids`, `running_node_ids`,
  `failed_node_ids`, `sol_ingress_tokens`, and `total_tokens`;
- `revision_history`, whose entries contain exactly `revision`,
  `plan_sha256`, and `source_pointer`;
- `termination` and `verification`, each containing exactly `status`,
  `decided_by`, `role`, and `source_pointer`.

The current hard controller maxima are logical depth 2, retries per node 2,
and active revisions 3. They cannot be configured upward. Every run must also
supply positive `max_nodes`, `max_sol_ingress_tokens`, and `max_total_tokens`
limits; v1 defines no universal defaults for those deployment bounds.
Proposal token allocations are reservations, not observed consumption. On a
bound N+1 revision, the report increments effective depth and active revision
count and reports projected token totals separately from the unchanged
observed counters. Those reservations are checked against the global
Sol-ingress and total-token limits. The proposal's wall-clock minutes are
checked against its evidence `budget_remaining_minutes`. V1 has no parent
remaining-token field, so it does not mechanically represent per-child/parent
token reallocation or token conservation. A follow-up contract version must add
explicit parent and child token-ledger fields before making that stronger claim.

Before binding N+1, the controller requires the active logical plan and
history to agree; the proposal to pass the existing decomposition validator;
the current root/Sol approval to bind proposal and base-plan hashes; child
read/write scopes to remain inside the parent; the successor graph, node count,
depth, revision count, retry counters, and token reservations to remain within
limits; and retained content plus authority to validate. A denial leaves the
current plan effective. Workers remain `workers_can_spawn: false`, and no
retry, replacement, fallback, or nested swarm is inferred from a revision.

The proposal parent must be pending or running, never completed or failed, and
every original parent predecessor must already be completed. Each approved
child inherits the union of those original predecessor edges and its local
child edges. The semantic join must depend on every proposed child. On a
successful bind, a running parent is removed from `running_node_ids` and becomes
the pending acceptance carrier behind that join. The binder—not a later
controller mutation—assigns its semantic acceptance resource/deliverable,
refreshes the exact authority worker set, and records exact hashes for the bound
parent and authority. Retained-content verification fails on any later change.

The binder copies every approved child `model_profile`, the exact identifier
of one registered node profile; only a root-labor profile
(`reviewer.root-labor/v1`) binds `executor: sol`, while every other profile
binds `executor: subagent` for canonical governor routing, and the
expand-step alias values resolve only through the registry's historical
replay adapter. Child `effort_profile` and
`tools` remain validated PlanPatch evidence only in v1. They are not fields in
the bound logical-worker schema and are not mechanically enforced there;
downstream `TaskSpecV2` must explicitly bind effort/tool policy before execution.

Approval decisions are fail-closed but distinct: absent, non-object, rejected,
or non-current-root records are `PROPOSAL_UNAPPROVED`;
`PROPOSAL_TAMPERED` is reserved for a current approved root/Sol record whose
proposal digest changed; a stale proposal/base-plan binding remains
`PROPOSAL_STALE`.

Final acceptance is `ACCEPTED` only when the controller records successful
termination, every non-optional effective node is complete, no required node
is running or failed, and the bound root/Sol records passed final
verification. Worker declarations cannot satisfy either terminal authority.

The adaptive communication contracts are closed, provider-free objects:

- `TaskSpecV2` is `orch-dork/task-spec/v2` with exactly `schema`, `id`, `kind`,
  `goal`, `rationale`, `non_goals`, `dependencies`, `input_refs`, `read_scope`,
  `write_scope`, `deliverable`, `acceptance_checks`, `executor`,
  `model_profile`, `allowed_tools`, `risk`, `budgets`,
  `may_request_decomposition`, and `failure_policy`. `kind` is one of `probe`,
  `execute`, `join`, `verify`, or `adjudicate`; `allowed_tools` is explicit and
  bounded.
- `ArtifactRefV1` is `orch-dork/artifact-ref/v1` with exactly `schema`, `uri`,
  `sha256`, `size_bytes`, and `media_type`. Its URI must be content-addressed
  and agree with the digest; artifact bytes are never embedded.
- `HandoffReceiptV1` is `orch-dork/handoff-receipt/v1` with exactly `schema`,
  `disposition`, `task_spec_sha256`, `result_summary`, `claims`,
  `artifact_refs`, `checks`, `conflicts`, `unknowns`, `requested_decisions`,
  and `raw_trace_ref`. It is a bounded index into content-addressed evidence,
  not a transcript. Every claim, check, conflict, and raw-trace evidence
  pointer must also appear in its top-level `artifact_refs` index. Its current
  executable cap is 4,800 canonical bytes and 1,200 estimated tokens for every
  task kind, with a 2,048-byte result summary.
- `VerificationReceiptV1` is `orch-dork/verification-receipt/v1` with exactly
  `schema`, `task_spec_sha256`, `subject_handoff_sha256`, `artifact_refs`,
  `diff_refs`, `acceptance_criteria`, `check_results`,
  `implementer_identity`, `verifier`, `disposition`, `pass`, and `findings`.
  A pass requires a different verifier in a clean context, the exact valid
  same-TaskSpec complete handoff named by `subject_handoff_sha256`, coverage of
  every handoff artifact in the verification artifact index, evidence-backed
  required checks, artifacts, and a diff for `execute` tasks.
- `ClaimLedgerV1` is `orch-dork/claim-ledger/v1` with exactly `schema`,
  `task_spec_sha256`, `claims`, and `artifacts`. Every reproduced or verified
  claim cites evidence present in the ledger's artifact index.
- `IncrementalClaimPacketV1` is
  `orch-dork/incremental-claim-packet/v1`: a compact TaskSpec-bound sequence,
  evidence-indexed claims and checks, observed cumulative token/tool usage,
  and a source pointer. It is capped at 2,400 canonical bytes and 600 estimated
  tokens and fails at the packet boundary when a TaskSpec budget is exceeded.
- `HandoffPreflightV1` is `orch-dork/handoff-preflight/v1`: one tool-free
  canary binding the exact expected and observed route, session, valid typed
  handoff, contiguous incremental packets, cumulative observed usage, and
  runtime-observed source evidence. Only a passing report has
  `spawn_permitted: true`.
- `HandoffPreflightCandidateV1` is
  `orch-dork/handoff-preflight-candidate/v1`: the closed worker-authored
  terminal precursor containing exactly `schema`, `preflight_id`,
  `task_spec_sha256`, `capability_profile`, and `handoff_receipt`. Its public
  validator proves only typed candidate validity, always reports
  `spawn_permitted: false`, and rejects every worker/caller-authored runtime
  fact. Wave v3 may enrich it only from a passing exact-terminal independent
  session observation.

Each validator accepts its optional canonical seal field on input and returns a
normalized sealed record on `PASS`. The seal fields are `task_spec_sha256`,
`artifact_ref_sha256`, `handoff_sha256`, `verification_sha256`, and
`ledger_sha256`, plus `packet_sha256` and `preflight_sha256` for the runtime
contracts and `candidate_sha256` for the observer-bound precursor. Unknown
fields, embedded transcripts, prompts, terminal or tool history, raw outputs,
session bodies, or private reasoning fail closed and are not reflected into
the report.

Propagation is evidence-gated: a downstream node consumes declared artifact
and claim indexes only after an independent clean-context verification receipt
passes against the exact subject handoff. A semantic `join` deduplicates
identical hash-bound claims but
preserves disagreements, evidence quality differences, unknowns, and interface
conflicts. It never chooses truth by silent majority vote. A consequential
conflict routes to a declared `adjudicate` node or to root/Sol; that decision
must cite the competing evidence and cannot expand authority or scope. Only
the resulting independently verified receipt may propagate.

The future differentiated context targets are ordinary handoffs 600–1,200
tokens, join handoffs 1,500–2,500, the PlanPatch view shown to Sol 300–600,
and a final Sol packet 4,000–8,000. These are design targets, not current v1
enforcement; the executable v1 handoff validator applies the uniform 1,200-
token cap above.

The public MCP surface exposes one `evaluate_adaptive_finite_dag` tool and one
`validate_adaptive_contract` tool. The latter requires `contract_kind` to be
one of `TaskSpecV2`, `ArtifactRefV1`, `HandoffReceiptV1`,
`VerificationReceiptV1`, `ClaimLedgerV1`, `IncrementalClaimPacketV1`, or
`HandoffPreflightV1` or `HandoffPreflightCandidateV1`. Both argument objects
are closed, read-only, idempotent, provider-free, and accept no worker
transcript/history.
`VerificationReceiptV1` calls additionally require the exact
`handoff_receipt`; all three runtime contract kinds require the exact
`task_spec`.

## Model-combination evidence-integrity schemas

The read-only MCP surface also exposes `evaluate_evidence_policy`,
`evaluate_route_policy`, and `evaluate_campaign_policy`. Each accepts one
closed `program` with an exact schema, closed operation enum, and bounded
payload. The evaluators use only the standard library, perform no filesystem,
transport, provider, or model I/O, and return sanitized typed reports.

Evidence policy covers produced-evidence identity, closed failure origin with
an explicit candidate-quality-evidence flag, advisory novelty versus exact
claim use, and bounded Evidence Reveal. A generated marker is never an
execution receipt; advice generation never implies use; and reveal selectors
must exist in one hash-bound fresh manifest and remain within the byte cap.

Route policy covers quorum over stable opaque independence groups, serving-
epoch comparison, and pre-work TaskSpec delivery acknowledgement. Duplicate,
changed, missing, or overclaimed group identity fails. Cross-epoch observations
remain descriptive while causal attribution is refused. A delivery record
binds TaskSpec digest, lane, worker, session, acknowledgement order, and a
single-use identity; missing, late, mismatched, or replayed records fail.

Campaign policy covers a finite compare-and-swap series ledger, anti-Goodhart
evaluator integrity, and risk-aware batch disposition. Draw and token budget
are reserved and permanently charged at draw time for every terminal outcome.
Every sensitive criterion needs an effective falsifying witness; constant,
oracle/shortcut, and abstention probes cannot win or qualify. Risk and
compatibility derive from facts, every input has exactly one deterministic
disposition, and high, unknown, or incompatible items are extracted for root
review.

## Limit-policy schema

`evaluate_orchestration_limits` consumes
`orch-dork/limit-policy-program/v1` and returns
`orch-dork/limit-policy-report/v1`. The versioned policy has three closed,
separately reported categories: hard authority or safety limits, soft
efficiency targets with declared remediations, and a completion-only reserve.
The append-only ledger records incurred or reserved usage by plan revision and
wave. Uncached input, cached input, output, and reasoning tokens remain
separate raw dimensions with their own hard ceilings. A versioned integer
microunit weighting may add a derived cost ceiling or target but never replaces
or hides a raw ceiling.

Hard exhaustion returns the exact `AUTHORITY_REQUIRED` or `SAFETY_BLOCKED`
disposition. Missing ledger, reserve, or candidate telemetry returns
`TELEMETRY_REQUIRED`; unknown is never zero. Soft overruns admit required work
when hard limits and completion reserve permit it, applying only declared
remediation. Optional or ordinary execution is blocked before it would spend
capacity protected for integration, verification, external observation,
cleanup, and final Sol review. Reports preserve incurred usage and completed
work and reconcile exact-or-unknown records across revisions and waves.

## Profile-lifecycle schema

`evaluate_orchestration_profile` consumes
`orch-dork/profile-lifecycle-program/v1` and returns
`orch-dork/profile-lifecycle-report/v1`. The exact versioned profile binds the
collaboration surface/version, plan schema, Sol and worker routing, context
policy, controller, adapters, and the complete active lifecycle feature set.
Its durable closed states are `UNSUPPORTED_OR_BLOCKED`, `PROVIDER_FREE_READY`,
`HOSTED_CANARY_AUTHORITY_REQUIRED`, `CANARY_RUNNING`, `ACTIVE_DEFAULT`, and
`SUSPENDED`.

Provider-free success cannot infer hosted authority. One exact grant plus one
clean, independently observed, `BOUND`, sealed-runtime, hash-verified canary
activates only the matching profile without a later promotion message.
Tampering, mismatched profile identity, reuse, or retry blocks activation. A
verified correctness or lifecycle regression suspends only the matching
profile; cost or latency regression is recorded as efficiency-only. Prior
transitions are hash-linked immutable input, active unavailability never
becomes a governed advisory fallback, and recovery eligibility does not itself
reactivate a suspended profile.

## Efficiency-evaluation schema

`evaluate_orchestration_efficiency` consumes
`orch-dork/efficiency-evaluation-program/v1` and returns
`orch-dork/efficiency-evaluation-report/v1`. Its immutable contract declares a
finite matched `baseline`/`active` sample and exact order; fixture, model,
effort, context, plan and authority bindings; correctness checks; four raw
token components and versioned cost weights; critical-path timing; zero-retry
failure policy; and closed decision and terminal rules. Trial evidence must be
`BOUND`, sealed-runtime, source-hash verified, and receipt verified.

The evaluator owns progress and emits hashed append-only transitions. Complete
evidence closes automatically as exactly `EFFICIENCY_PROVEN` or
`EFFICIENCY_NOT_PROVEN`. At a closed or deadline-bounded snapshot, missing,
incompatible, contradictory, incomplete, or unknown evidence closes
`INCONCLUSIVE`; an open finite collection remains `COLLECTING`. Accepted
quality, raw attributable token components, weighted cost, critical-path
latency, and lifecycle reliability are primary. Sol share is secondary and has
no threshold. Cost or latency misses do not control safety activation, while a
verified active correctness or lifecycle regression emits a separate exact
profile-suspension signal. A terminal seal binds the contract, history, all
trial evidence, metrics, unknowns, contradictions, and outcome. The run
registry stores only a compact rebuildable projection of this authoritative
report.

## Budget schema

`evaluate_orchestration_budget` consumes `orch-dork/budget-program/v1` and
returns a tamper-evident `orch-dork/budget-report/v1`. Its closed dimensions
are hosted calls, tokens, cost in integer microunits, wall time in milliseconds,
turns, children, depth, and concurrency. Each runtime amount is `known` with a
non-negative integer or `unknown` with a reason and source pointer. Only
runtime-observed or sealed-runtime records can establish consumption. The
controller reserves every admitted node first and emits `NOT_STARTED` with
dependency and budget reasons when a limit is exhausted or unknown. Rejected
local replay attempts are counted separately and cannot consume hosted calls.

## Cancellation and recovery schema

`evaluate_orchestration_recovery` consumes
`orch-dork/recovery-program/v1`. Cancellation and timeout are distinct
append-only events bound to an affected node and owned process group. Cleanup
has closed checks for owned processes, temporary credentials, locks, tunnels,
configuration, and recovery markers. A signal or forced exit never proves
cleanup; dirty checks produce `CLEANUP_FAILED`, and unknown or submitted checks
produce `RECOVERY_REQUIRED`. A later recovery request must use a different
plan identity, bind the failed plan hash, name its policy, and carry explicit
recovery-scoped authority. Usage and persisted tasks remain historical facts.

## Bounded dependency graph schema

`qualify_orchestration_graph` consumes `orch-dork/execution-graph/v1` and
returns `orch-dork/execution-graph-report/v1`. The graph declares finite nodes,
typed dependency/artifact/release edges, deterministic joins, exact authority,
and explicit node-count, depth, concurrency, and turn bounds. Every observed
join partitions all declared input edges into accepted inputs or excluded
failed/timed-out/cancelled inputs with source pointers and matching reasons.
An `all` join requires all inputs; a bounded `quorum` join continues only when
its threshold is met. Observed releases must exactly equal those derived by
the chosen integration profile. Unknown or extra graph events fail closed.

## Safe root-rollover schema

`evaluate_root_rollover` consumes `orch-dork/root-rollover-program/v1` and
binds `orch-dork/root-rollover-checkpoint/v1`. The checkpoint is a compact,
privacy-safe contract over plan/ticket state, worker outcomes, custody,
releases, hash pointers, usage, context, capacity, authority, limits, worktree,
routing, safe-boundary evidence, and the next action. Successor creation has
one attempt and one unique marker. Ambiguous outcomes are reconciled against a
bounded inventory without a same-turn retry. The successor must be read-only,
no-history, route-exact, checkpoint-exact, authority-exact, and worktree-exact.
Mutation ownership moves only after an independently terminal frozen
predecessor through `orch-dork/execution-lease/v1` compare-and-swap. The report
keeps continuity, capacity recovery, and context reduction independent and
prevents automatic rollover loops.

The `transfer-lease` controller operation accepts
`orch-dork/root-rollover-lease-transfer/v1`, locks the durable lease, verifies
the expected owner/version/checkpoint and independently observed frozen
terminal predecessor, then atomically replaces it with the single successor
owner. A repeated identical call is idempotent; a stale owner, version, or
checkpoint is a conflict and leaves the lease unchanged.
An explicitly approved later rollover may compare-and-swap from an
`active_successor` lease when that successor is the exact expected owner and
version; the new sealed checkpoint replaces the prior checkpoint only in the
same atomic transfer after that owner is independently terminal.

## Observability-gallery schema

`orch_dork_observability.py` replays closed
`orch-dork/observability-scenario/v1` fixtures and emits
`orch-dork/observability-gallery-report/v1`. It is provider-free and has no
authority to observe a live task, issue a policy decision, or promote a run.
It projects already-sanitized evidence into the same user-facing boundary used
by the skill.

Every scenario declares one advisory or governed mode, a durable disposition,
and typed claims. Evidence class is exactly one of `runtime`, `ui`,
`submitted`, `inferred`, `sealed`, `unknown`, or `contradictory`; evidence tier
is exactly one of `submitted`, `runtime-observed`, or `sealed-runtime`.
Class/tier combinations are validated. Unknown claims require a reason and no
value. Contradictory claims require at least two conflicting values. Absolute
source pointers with a digest are read-only hash-verified during replay.

A contradiction always displays `FAILURE`. Failure, cancellation, and policy
blocks retain their actual disposition. A required unknown displays `UNKNOWN`
instead of success. Advisory success displays `ADVISORY_ONLY` and never grants
a claim. Only a governed success backed by sealed-runtime disposition evidence
plus required runtime/sealed facts displays `SUCCESS` with
`claim_permitted: true`. Forbidden private-reasoning, session, credential,
secret, or raw-authorization fields fail replay.

The canonical gallery and public wording are in
[observability.md](observability.md). Scenario fixtures live under the shipped
`runtime/observability-scenarios/` directory and include success, missing evidence,
contradiction, cancellation, wrong routing, budget exhaustion, blocked extra
work, and the preserved Issue 17 canary timeout.

## Plan schema

Use this exact top-level shape:

```json
{
  "schema": "orch-dork/plan/v1",
  "decision": {
    "mode": "orchestrated",
    "reason": "Four independent implementation surfaces"
  },
  "root": {
    "model": "gpt-5.6-sol",
    "effort": "xhigh",
    "coordination_only_after_freeze": true
  },
  "children": {
    "expected_count": 4,
    "max_concurrency": 4,
    "max_depth": 1,
    "context_policy": "none",
    "model": "openrouter/qwen-qwen3.8-27b",
    "effort": "xhigh",
    "retries_allowed": 0,
    "fallbacks_allowed": 0
  },
  "lanes": [
    {
      "id": "api",
      "objective": "Implement the API surface",
      "deliverables": ["Completed API behavior"],
      "owned_resources": ["src/api/**"],
      "excluded_resources": ["src/ui/**"],
      "dependencies": [],
      "verification": ["Run the focused API tests"]
    }
  ],
  "integration": {
    "strategy": "first_completed_worker",
    "release_required": true,
    "final_verification": ["Run the integrated test suite"]
  },
  "protected_resources": ["existing user changes"],
  "acceptance_criteria": ["All requested behavior works"],
  "acceptance_resource_closure": {
    "schema": "orch-dork/acceptance-resource-closure/v1",
    "workspace_root": "/absolute/project/root",
    "binding": {
      "acceptance_criteria_sha256": "sha256",
      "writable_scope_sha256": "sha256",
      "integration_resources_sha256": "sha256",
      "final_verification_sha256": "sha256"
    },
    "requirements": [
      {
        "id": "api",
        "criterion": 0,
        "resource": "src/api/**",
        "phase": "implementation",
        "surface": "path",
        "generated": false
      },
      {
        "id": "installed-plugin",
        "criterion": 0,
        "resource": "install/orch-dork/**",
        "phase": "publication",
        "surface": "install",
        "generated": false
      }
    ],
    "assignments": [
      {"requirement_id": "api", "owner": {"kind": "lane", "id": "api"}},
      {"requirement_id": "installed-plugin", "owner": {"kind": "lane", "id": "api"}}
    ],
    "integration_owner": {
      "kind": "lane",
      "id": "api",
      "release_conditions": ["all production owners completed and released"]
    }
  }
}
```

For an atomic decision, use zero children, no lanes, `strategy: "none"`, and `coordination_only_after_freeze: false`.

For an orchestrated compatibility plan, every lane's `dependencies` array is
empty. Express any dependency edge under `orch-dork/logical-plan/v1` with the
`finite_dag/v1` profile; `orch-dork/plan/v1` rejects the edge because its trace
qualifier has no dependency scheduler.

The root `model` and `effort` are not global Orch Dork constants. Resolve them from the active orchestrator turn and freeze those exact values into the plan. The qualifier requires the observed root trace to match that frozen pair.

Before either compatibility-plan or logical-plan freeze,
`observe_current_orchestration_route` emits
`orch-dork/current-turn-route/v1`. Codex's per-call MCP `_meta.threadId` binds
the adapter to the calling task. The runtime-observed report binds that exact
Codex session ID, final turn ID, root model/effort, `multi_agent_version`,
governed worker model/effort, selected-record hashes, and a stable route
identity hash. Its dispositions are `SPAWN_COMPATIBLE`, `RESTART_REQUIRED`,
`ROUTE_CHANGED`, `REFUSED`, and `ROUTING_UNKNOWN`. Only the first permits
freeze or spawn. A second observation immediately before spawn must match the
freeze report's `identity_sha256`. Admission, the logical-wave runner, and the
compatibility spawn-wave validator require that digest as
`expected_route_identity_sha256`, re-observe it themselves, and accept no
admission, waves, or members after drift. Installed
MCP calls require per-call `threadId`; only the explicit direct-launcher mode
may use `CODEX_SESSION_ID`/`CODEX_THREAD_ID`.

Root admission and the surface follow ADR 0012 (Issue 203): a root is
admitted when it is a registered orchestrator or has an onboarded profile,
and every live governed task runs on the V1 collaboration surface. An
unadmitted root is `routing:root_model_not_onboarded`; a task on another
surface is `routing:root_surface_not_v1:<reason>`, naming the reason the
model's onboarded profile records (`catalog_row_not_v1` or
`dry_run_failed`), `drift_since_onboarding` when the profile reached V1, or
`not_onboarded`. Native Sol/V2 or Astra/V2 with a routed worker remains
`orchestrated:native_root_routed_worker_encrypted` and requires a fresh task.
No environment rung admits a root: the `ORCH_DORK_ROOT_MODELS` and
`ORCH_DORK_ROOT_SURFACES` ladders of Issue 173 are retired and an exported
value is ignored, so the observer and `validate_current_turn_route` agree in
every process without an exported policy. The registry's closed
root-model/surface matrix (Issue 185, ADR 0010) judges only historical
replay: the `_PINNED` root seams of `orch_dork_worker_default` pin the matrix
in force when a replay's evidence was recorded (`routing:root_model_unsupported`,
`routing:root_surface_unsupported`), and a malformed pin raises
`root_surfaces:invalid` rather than admitting a root. No surface rule
substitutes for the observed turn context, and environment and catalog
surface claims cannot override that observation. The legacy plan schema is
unchanged, so archived plan hashes do not move; a registry-routed plan (one
whose nodes name profiles by registry or onboarded identifier) additionally carries
`routing_policy_sha256`, the digest of its sealed routing policy, which
`bind_routing_policy` freezes and validation requires
(`plan:routing_policy_unbound`, `plan:routing_policy_mismatch`). The
plan-validation report carries
`current_turn_route`, `route_identity_sha256`, `root_route_evidence_tier`,
`root_route_verified`, `worker_route_evidence_tier`, and
`worker_route_verified`.

Current-turn observation establishes only the root route. Plan freeze marks
the requested worker route `submitted` and unverified; current-turn admission
and spawn gates mark it `unobserved` and unverified. A v1 or v2 wave-routing
report remains submitted evidence even when structurally `PASS`. Only a v3
report built from complete independent session-runtime observations may set a
worker or root route to `runtime-observed` and its corresponding `*_verified`
field true. Never infer worker routing from an observed root route.

### Live route authorization handoff schema

`evaluate_live_route_handoff` consumes the closed
`orch-dork/live-route-authorization-program/v1` program. `prepare` requires
exactly `scope_sha256` and `authorization_statement`; it validates a fresh
`SPAWN_COMPATIBLE` current-turn route and returns a sealed
`orch-dork/live-route-authorization/v1` report with disposition
`READY_FOR_HUMAN_AUTHORIZATION`. The report retains the complete sanitized
preflight route and only the SHA-256 of the statement. It makes zero provider,
model, hosted, credential, or network calls.

`authorize` requires exactly the unchanged preparation report and the exact
authorization statement. It independently observes the calling task's current
route and accepts only a distinct later turn whose task/session, root
model/effort/kind, collaboration surface, and governed worker
model/effort/kind equal the prepared route contract. Both embedded routes must
be fresh, valid `SPAWN_COMPATIBLE` observations. A successful report has
disposition `READY_FOR_ONE_ATTEMPT`, binds both turn IDs, the preparation and
scope digests, the statement digest, and the authorization identity, and emits
the current turn's `dispatch_route_identity_sha256`.

The caller must immediately supply `dispatch_route_identity_sha256` to the
ordinary `observe_current_orchestration_route(expected_identity_sha256=...)`
gate before the first live effect. That exact current-turn identity remains the
admission and wave identity. The authorization handoff permits no same-turn
reuse, arbitrary turn substitution, route change, retry, fallback, live call,
or relaxation of any other gate; malformed, stale, tampered, mismatched, or
non-later evidence returns `REFUSED` with `dispatch_permitted: false`.

Subagents remain pinned to the governed worker model and effort. The forward
`implementer.governed-worker/v1` default is exact `openrouter/qwen-qwen3.8-27b` at `xhigh` with
no inherited history; OpenRouter upstream provider selection is automatic and
unpinned. Local Qwen is not probed or used as fallback while offline. The
governed values live in `scripts/orch_dork_worker_default.py` and are read by
the policy validator, receipt builder, both observers, and efficiency governor,
so changing that one file moves every active validator together.
`ORCH_DORK_WORKER_MODEL` and `ORCH_DORK_WORKER_EFFORT` may deliberately bind a
single provider-free historical replay before plan freeze; they are never a
silent post-freeze fallback. WorkerPort 0.1.8 additionally admits a forward
`medium` effort selected explicitly before freeze. For a qualification owner,
pass `worker_effort="medium"` to the installed
`build_qualification_thread_start_params`; its invocation-local MCP environment
makes the subsequent route observer report that choice. Preserve the exact
request and require observed medium before worker registration or dispatch.
The runtime capability catalogue must advertise that effort. Runtime, route,
authority, native argv and every initial/follow-up observation remain bound to
one exact effort. No global configuration change or ambient default selects it. A frozen plan remains authoritative for its own
evidence, which keeps completed local-Qwen receipts replayable after this
forward route migration. Sol integration and adjudication routes are unchanged.

The v1 wire schema retains `children`, `child_thread_id`, and `child.spawned` for compatibility. User-facing text should say “subagents.”

Owned resources are semantic ownership labels, not necessarily filesystem paths. They must be non-empty and pairwise disjoint. Use a dedicated shared-seam lane rather than giving two workers the same resource.

Every validated plan also carries
`orch-dork/acceptance-resource-closure/v1`. Each acceptance criterion has one
or more normalized requirements. Every requirement names one resource, one of
the `implementation`, `integration`, `publication`, or `final_verification`
phases, a `path`, `semantic`, `generated`, `install`, or `publication`
surface, and exactly one root or lane owner. Read-only requirements remain
explicit but do not create mutable ownership. Concrete paths, globs,
ancestor/descendant relationships, semantic keys, generated and install
surfaces, protected overlap, and symlink escape are checked before freeze.

Mutable integration, publication, and final-verification requirements must
match the declared `integration_owner`. A root owner is permitted only when
the plan explicitly uses root integration and the root is not coordination-
only after freeze. Otherwise a named integrator lane and non-empty release
conditions are mandatory. A closure failure sets `freeze_permitted` and
`spawn_permitted` false and permits no retry, shrink, worker reuse, or root
implementation.

The four binding hashes are derived from acceptance criteria, normalized
writable requirements, integration/publication requirements, and final
verification. Carry that closure binding and its digest in the ticket's fresh
classification-policy/v2 evidence. Any material change alters the plan hash
and classification evidence, so a previous ticket admission is invalid rather
than silently absorbing new integration work.

## Admission and spawn-wave schemas

Before freezing a candidate plan, list the native worker inventory and call
`validate_orchestration_admission`. `capacity` is the instantaneous number of
lane slots, excludes the active root, and may not exceed 32. A host-signed v2
active-only inventory counts pending/running lanes and any terminal lane that
lacks the exact signed lane/run/route/descendant/cleanup release receipt.
Only a terminal row with that proof releases capacity while its identity stays
visible and nonreusable. The v1 form is always advisory and treats submitted
terminal state as unproven release, regardless of structural `PASS`.

```json
{
  "schema": "orch-dork/collaboration-inventory/v1",
  "root_thread_id": "root-id",
  "capacity": 3,
  "retirement_supported": false,
  "workers": [
    {"worker_id": "old-id", "status": "completed", "attempt_id": "old-run"}
  ]
}
```

The v2 form adds a closed `slot_accounting` object. Raw v2 remains advisory.
`adapt_native_capacity_observation` promotes authority only when the native
observation payload is carried inside a verified
`orch-dork/signed-observer-receipt/v1`; a bare
`native-capacity-observation/v1` SHA-256 self-seal remains submitted evidence.
For `active_only`,
`occupied_statuses` is exactly `["pending_init", "running"]`; an unproven
terminal is added back to occupied inventory and makes
`terminal_records_consume_slots` true. Evidence tier is
`runtime_observed`, capacity kind is `active_agents_excluding_root`, and the
root/surface/source digest plus five-minute validity interval are required.
Capacity above 32 is refused. No cumulative identity or terminal-record count
occupies capacity, so later finite, budget-admitted waves may exceed 64 total
lanes without exceeding 32 at one instant. The separate shared-route admission
seam seals every successful reservation into one root-owned compare-and-swap
authority state and hash-chained identity ledger bound to lane, run, and route.
The trusted store adapter supplies a continuity-verified snapshot on every
decision; a request cannot supply its own head, entry count, active count, or
authority claim. The adapter verifies each successor semantically against its
predecessor: generation, existing root/run/task-budget bindings, plan-history
prefixes, and identity history cannot change; identities only append; and an
active removal requires its exact sealed terminal- and cleanup-evidence receipt.
The durable stream carries a bounded semantic delta containing only newly
appended run/revision/identity facts, active-set changes, and applicable release
receipts—not the complete historical authority snapshot. Replay reconstructs
the exact successor digest and verifies every release at its persisted,
lane-specific original observer-verification instant. A restart clock therefore
cannot expire already accepted evidence, and historical identity growth cannot
become an event-payload-derived cumulative lane ceiling.
Each delta is independently limited to 32 new runs, revision rows, identities,
or releases and 128 KiB of canonical authority content. A larger finite update
must be split across successive root CAS transitions; this per-event safety
bound is not a cumulative run limit. Topology and decomposition-label inputs
retain their closed field/list rules, and topology programs have a 16 MiB
canonical byte bound, but neither surface imposes a fixed natural-lane-count
ceiling.
The cleanup claim and each host-route authority claim are Ed25519 observer
envelopes verified against host-owned trust and replay state; digest shape or a
caller-supplied authority label is never sufficient. Route authority hashes
bind the exact inventory payload, with the verified native-capacity source
receipt bound separately. Truncation fails closed,
historical identities cannot be reused after terminal-row compaction, and the
run's root, explicit task-node budget, and ordered plan revisions are frozen in
that authority state. A root/Sol revision with an exact predecessor hash may
append the next plan digest while retaining the original `task_node_budget`;
changing that budget or skipping a revision fails closed. Per-run history
enforces the explicit task-node budget, not a fixed product-wide lane ceiling.
Control Tower, native Luna, and portable Qwen reservations must commit to the
same physical authority store for their
governed scope, so route-local inventories cannot create parallel 32-lane pools.
The legacy `validate_admission`/`validate_spawn_wave` path is structural only
unless its embedding root injects the same continuity-verified authority reader
and semantic CAS committer. It batches all dependency-ready native reservations
that fit current capacity into one atomic successor before spawn and queues the
rest; a racing stale commit refuses without a partial wave. The read-only MCP
projection has no such host mutation authority,
reports `spawn_authority_permitted: false`, and cannot be used to bypass the
Control Tower or host adapter.
The normalized inventory and admission report expose
`capacity_authoritative`, `capacity_claim_permitted`, `capacity_scope`, and
`capacity_evidence_tier`, `capacity_signed_receipt_sha256`, signing key ID, and
trust generation; admission additionally exposes `admission_scope`.
Host-signed authoritative evidence is labelled
`runtime-observed-inventory` while still returning
`worker_reuse_permitted: false`.

The signed envelope is an exact closed record containing `receipt_kind`,
`key_id`, `algorithm: ed25519`, `host_id`, `issued_at`, `valid_until`, a replay
`nonce`, the payload and payload digest, and the signature. The trust store is
`orch-dork/observer-trust-store/v1`, loaded only from the host path named by
`ORCH_DORK_OBSERVER_TRUST_STORE`; the private seed is never an evaluator input.
`ORCH_DORK_OBSERVER_REPLAY_DB` names the host-owned nonce registry. Rechecking
the same envelope is idempotent, while a different signed envelope reusing the
same host/kind nonce is denied. Missing trust/replay state is `UNAVAILABLE`,
never a fallback to the payload's claimed observer or key.

After the initial spawn calls, call `validate_orchestration_spawn_wave` with
the admission report and exactly one result per lane:

```json
{
  "lane_id": "api",
  "worker_id": "fresh-id",
  "status": "created",
  "fresh": true,
  "parent_thread_id": "root-id"
}
```

The MCP descriptor declares `results.items` as that exact closed object:
`lane_id`, `worker_id`, `status`, `fresh`, and `parent_thread_id` are all
required; identity fields are non-empty strings, `fresh` is a boolean, and
`status` is one of `created`, `failed`, `ambiguous`, `unknown`, `timed_out`, or
`cancelled`. `adapt_native_spawn_result` copies one explicit native
collaboration receipt into this shape. It applies no defaults, never parses a
JSON string, and never infers freshness or synthesizes parent identity. Server
dispatch passes the resulting array unchanged to the validator.

The wave is atomic for orchestration membership. Any missing, failed,
ambiguous, duplicate, stale, or reused result produces
`attempt_state: aborted_partial_wave`, empty membership, and no permission to
retry or replace.

## Trace schema

```json
{
  "schema": "orch-dork/trace/v1",
  "plan_sha256": "canonical plan hash returned by the validator",
  "counters": {
    "retries": 0,
    "fallbacks": 0,
    "replacements": 0,
    "nested_children": 0
  },
  "events": [
    {
      "seq": 1,
      "type": "root.started",
      "root_thread_id": "root-id",
      "model": "gpt-5.6-sol",
      "effort": "xhigh"
    }
  ]
}
```

Events use strictly increasing positive integer `seq` values. Supported types and required fields:

| Type | Required fields |
| --- | --- |
| `root.started` | `root_thread_id`, `model`, `effort` |
| `root.tool` | `name`, `category` where category is `coordination` or `implementation` |
| `child.spawned` | `lane_id`, `child_thread_id`, `parent_thread_id`, `depth`, `model`, `effort`, `context_policy` |
| `lane.verified` | `lane_id`, `child_thread_id`, `passed` |
| `lane.completed` | `lane_id`, `child_thread_id`, `status` |
| `integrator.started` | `child_thread_id` |
| `lane.released` | `lane_id`, `owner_thread_id`, `integrator_thread_id` |
| `integrator.validated` | `child_thread_id`, `passed` |
| `integrator.completed` | `child_thread_id`, `status` |
| `run.completed` | `root_thread_id` |

Use `status: "completed"` for successful terminal events. Record failures as their real status; the qualifier will fail closed.

## Required orchestrated ordering

1. One root starts.
2. Every planned child is spawned directly from that root before the first lane completes.
3. Every lane verifies successfully before its initial completion.
4. The first completed lane owner becomes integrator.
5. The integrator starts before the last initial lane completes.
6. Every other lane is released exactly once, after its owner completes, to that integrator.
7. The integrator validates after all releases and initial completions.
8. The integrator completes after validation.
9. The submitted trace declares the root completion last. This declaration is
   checked for ordering but is not evidence that the active root has persisted
   a terminal record.

Any root implementation tool, extra or nested child, model or effort substitution, inherited context, missing release, failed verification, retry, fallback, or contradictory identity is a failure.

## Evidence boundary

The policy service checks normalized submitted events and returns a canonical
SHA-256 for both plan and trace. Its one narrow live read is
`observe_current_orchestration_route`, which selects only current-task
`session_meta` and `turn_context` facts for pre-freeze routing; it does not
reconstruct terminal or trace evidence. Therefore:

- `PASS` and `conformant: true` mean the submitted trace satisfies the
  structural policy.
- `qualified: false` and `claim_permitted: false` remain fixed for submitted
  traces, including traces containing `run.completed`.
- `evidence_tier: submitted` means source provenance is not independently established.
- `terminal_evidence.status: declared_not_observed` requires a later external
  post-terminal observer before any qualified completion claim.

### Runtime custody evidence

`validate_orchestration_custody` accepts the frozen plan, the current
`orch-dork/spawn-wave/v1`, and an `orch-dork/custody-events/v1` bundle. The
bundle contains only ordered lifecycle/release records and sanitized
`resource.access` events with worker, lane, normalized resource, read/write
operation, phase, and hash-bound source pointer. Shared filesystem visibility
is never authority. The public submitted seam checks event conformance only.
Even a clean bundle returns `evidence_tier: submitted`, `coverage: unknown`,
`custody_preserved: null`, and `claim_permitted: false`, because omitted access
cannot be detected from caller-authored events.

Governed completion instead uses a closed
`orch-dork/custody-observer-receipt/v1` payload inside a host-signed observer
envelope. The payload must identify an independent
observer, bind its `attempt_id` to the audited attempt and its `session_id` to
that observation's root thread, bind the complete event and access counts plus
bundle digest, declare `coverage: complete`, carry a timestamp and source
digest, and retain its compatibility `receipt_sha256` self-seal. Only a
structurally clean bundle plus a valid host signature, pinned trust key, and
replay disposition may return `evidence_tier: runtime-observed`,
`custody_preserved: true`, `claim_permitted: true`, and
`receipt_binding: host-signed`. A bare self-seal, caller-supplied trust key,
missing host state, forged signature, partial coverage, or mismatched receipt
fails closed. Never claim private reasoning or chain-of-thought; only actions,
messages, results, and causal order are observable.

`orch_dork_evidence_core` is the single canonical sealed-evidence module for
these boundaries. It owns compact UTF-8 canonical JSON (`allow_nan: false`),
SHA-256 seal/check operations, exact-field diagnostics, UTC parsing,
freshness ordering, and the capacity-authority projection reused by admission
and worker lifecycle. Domain modules keep their schemas and semantic checks;
they do not reimplement those mechanics.

## Governed run-state telemetry schemas

Issue 95 (frozen plan f8b99dc3) lands the v3 durable-integration surface as
deterministic, standard-library-only policy data. Every field set below is
closed: unlisted top-level keys fail closed, and list and string bounds are
enforced before any projection. Reason codes are `prefix:code` and stable;
a validation error is the sorted union of the codes found.

**Authority.** The canonical RunEngine event stream (hash-chained rows of
kinds started, applied, completed, terminated; verified by
orch_dork_run_engine.verify_event_chain; digested by stream_digest) is the
sole authority for run state and terminal outcomes. The lane event stream
documented below is a compatibility projection of a lifecycle view, never
an authority: its ingestion is the explicitly non-authoritative lifecycle
compatibility reducer, and the only authorized bridge from the canonical
stream to the telemetry world is the one-way wrapper
orch-dork/canonical-lifecycle-projection/v1 (see One-way projections),
whose run state carries no terminal claim of its own. Assessments and
projections mark run_state_authoritative false and bind their source
digest to that authority. Note on this section: the v3 kernel recovery
run (plan 54a6dbc) inspected kernel resources once before release; that
inspection is a custody exception (since dispositioned superseded by
commit 9840955 under Issue 96), not a qualifying pass, and no
claim in this reference rests on pre-release kernel reads.

### Lane event stream (`orch-dork/lane-events/v1`)

One append-only stream per run whose top-level keys are exactly `schema`,
`run_id`, and `events`. Each event carries the integer `seq` counting
from 1 with no gap, the event `type`, and an optional integer `ts` in
seconds bounded to [0, 1e15] and monotonically non-decreasing. At most 256
events, and the stream is the closed set below.

| Type | Required fields |
| --- | --- |
| `lane.started` | `lane_id` |
| `lane.completed` | `lane_id`, `outcome` |
| `integrator.started` | (none) |
| `integrator.completed` | `outcome` |
| `run.terminal` | `outcome` |

A lane id starts exactly once and completes once; `integrator.started`
occurs at most once before `integrator.completed`; lane outcomes are
`completed`, `failed`, `blocked`, `cancelled` and the run outcome is
`success`, `failure`, `blocked`, `cancelled`. `run.terminal` must be
the final event and no lane may remain unfinished at terminal. Structural
failures are stable reason codes: `lane_events:seq_gap`,
`lane_events:open_event_type`, `lane_events:extra_field`,
`lane_events:lane_duplicate_start`, `lane_events:lane_not_started`,
`lane_events:lane_already_terminal`, `lane_events:timestamp_regression`,
`lane_events:open_outcome`, `lane_events:terminal_missing`, and
`lane_events:lane_unfinished_at_terminal`.

### Lane event state (`orch-dork/lane-event-state/v1`)

Ingestion is the explicitly non-authoritative lifecycle compatibility
reducer: the lane stream is a compatibility projection of a lifecycle
view and never carries run-state authority (the canonical RunEngine
stream is the sole authority for run state). Ingestion is deterministic
and order-independent: events are sorted on their integer `seq` before
validation (matching the kernel), so harmless physical reordering of one
valid stream always reduces to the identical state and `stream_sha256`;
seq gaps and duplicate seqs still fail closed.
Closed fields: `schema`, `run_id`,
`lanes` (a map of `start_ts`, `end_ts`, `outcome` per lane, `null`
where absent), `integrator` (`start_ts`, `end_ts`, `outcome`; all
`null` when the integrator was never started), `terminal` (`seq`,
`outcome`, `ts`), `event_count`, and `stream_sha256`, the SHA-256 of
 the canonical form of the seq-sorted lane event list (schema and
 run_id are excluded, so physical event order never changes the digest).

### Lane result (`orch-dork/lane-result/v1`)

The bounded structured output one lane hands back. Closed top-level field
set: `schema`, `lane_id`, `producer_id`, `status`, `claims`,
`evidence`, `tests`, `artifacts`, `conflicts`, `unknowns`,
`usage`. `status` is `complete`, `blocked`, `failed`, or
  `partial`. The list fields `claims`, `evidence`, `tests`, and
  `artifacts` are required lists: any non-list (mapping, string, or null)
  fails closed with the stable reason `lane_result:{field}_not_list`. Every
  claim, evidence, test, and artifact record has a closed
field set; unbounded or transcript-shaped payloads are rejected by
construction.

| Nested record | Closed fields |
| --- | --- |
| Claim | `claim_id`, `label`, `verdict` (`PASS`/`FAIL`/`UNKNOWN`), `required` (boolean), `evidence_refs` |
| Evidence | `evidence_id`, `kind`, `origin` (`local`/`imported`), `authority` (`canonical`/`derived`/`imported`), `pointer`; optional `sha256` (exactly 64 hex) |
| Test | `test_id`, `result` (`PASS`/`FAIL`/`ERROR`/`SKIP`) |
| Artifact | `path` |
| Usage | `model`, `tokens_in`, `tokens_out`, `tool_calls` (integers in [0, 1e12]) |

Evidence kinds are the closed set `test_result`, `artifact`,
`observation`, `receipt`, `custody`, `verification`,
`projection`, `otel-export-record`. Combining `origin: imported` with
`authority: canonical` fails closed as
`lane_result:evidence_authority_mismatch`. Bound constants: at most 32
claims, 32 evidence items, 32 tests, and 16 artifacts; at most 8
`evidence_refs` per claim and 16 items in `conflicts` and `unknowns`;
strings are 2048 bytes per value and 1024 bytes for conflict and unknown
entries; the canonical JSON form of the whole result is 256 KiB or less;
`evidence_refs` must resolve within the result. `status: complete`
further requires at least one PASS claim whose every referenced evidence
entry carries `canonical` authority; a result supported only by imported
or derived evidence fails closed as `lane_result:complete_unsupported`.
The lane result digest is SHA-256 over the canonical form and therefore
key-order independent: the same content hashes equal regardless of mapping
key order.

### Governance profiles (`orch-dork/governance-profile/v1`)

Exactly three closed records with the fields `schema`, `name`,
`authority`, `description`, `writable_custody_required`,
`tests_required`, `required_evidence_kinds`, `required_axes`, and
`adjudication_required`:

| Name | Authority | Writable custody | Tests | Required evidence kinds | Required axes | Adjudication |
| --- | --- | --- | --- | --- | --- | --- |
| `scan` | `read_only` | no | no | none | none | no |
| `mutation` | `write_scoped` | yes | yes | `custody` | `custody`, `verification` | no |
| `release` | `release` | yes | yes | `custody`, `test_result`, `verification` | `outcome`, `evidence`, `custody`, `verification` | yes |

Profiles are deterministic typed policy data, not prose: a caller or
controller selects one record and reasons about its fields; the set itself
is closed and adding a fourth profile is a new version, not a widening.
Only canonical-authority evidence entries count against
`required_evidence_kinds`; imported or derived entries count for nothing.
`tests_required` demands at least one test entry with no `FAIL` or
`ERROR` result.

Profile-required custody and verification axes are derived from in-stream
facts and enforced fail-closed: the custody axis holds only when a
canonical-authority custody evidence entry exists, and the verification
axis holds only when at least one test entry is `PASS` and no entry is
`FAIL` or `ERROR`. A required axis that does not hold is named in
`missing_axes` and the assessment closes with the stable reason
`required_axes_missing`, independently of any adjudication record
(release adds the independent four-axis adjudication on top). The axes
adjudicated here are the release adjudication axes
(`RELEASE_ADJUDICATION_AXES`: outcome, evidence, custody, verification);
the kernel run result dimensions (`RUN_RESULT_DIMENSIONS`: execution,
deliverable, conformance, evidence) form a distinct closed set and are
never substituted for them.
An adjudication record opens exactly those four axes: any extra axis is
named in the stable reason `unexpected_adjudication_axis: <extra axes,
sorted>` and makes the report ineligible; any missing axis still closes
the assessment with the stable reason `adjudication_axes_incomplete`.

### Governance assessment (`orch-dork/governance-assessment/v1`)

Closed fields: `schema`, `profile`, `eligible`, `reasons` (sorted
vocabulary, see below), `missing_evidence_kinds`, `missing_axes`, and
`basis` with `lane_result_sha256` binding the report to the digest of
the exact LaneResult it assessed. Closed reason vocabulary:
`invalid_lane_result`, `tests_missing`, `tests_failed`,
`required_axes_missing`,
`required_evidence_missing`, `adjudication_required_absent`,
`adjudication_not_object`, `adjudication_missing_field`,
`adjudication_schema_mismatch`, `adjudication_identifier`,
`adjudicator_not_independent`, `adjudication_axes_not_object`,
`adjudication_axes_open`, and `adjudication_axes_incomplete`. Unknown
profile names fail closed (not a report) as `governance:unknown_profile`;
an invalid LaneResult yields exactly the single reason
`invalid_lane_result`.

### Adjudication (`orch-dork/adjudication/v1`)

Closed fields: `schema`, `adjudicator_id`, `producer_id`, and
`axes`, a flat object keyed by exactly the four release adjudication axes —
`outcome`, `evidence`, `custody`, `verification` — each valued
`PASS`, `FAIL`, or `UNKNOWN`. Independence is a hard rule: the
`adjudicator_id` must differ from the assessed LaneResult's
`producer_id` or the profile fails closed as
`adjudicator_not_independent`. Release eligibility requires all four axes
to read `PASS` in this one record; any missing or non-PASS axis names
itself in `missing_axes`.

### One-way projections

Both projection records are outbound only: they never update the canonical
stream, they are stamped `authority: projection` and
`run_state_authoritative: false`, and they carry a source digest binding
them to the exact canonical input, so re-projection is byte-identical and
reordering of mapping keys or events changes nothing. The authorized
canonical entry point is the one-way bridge
`orch-dork/canonical-lifecycle-projection/v1` produced by
`canonical_lifecycle_projection`: it accepts only real, kernel-verified
`RunEngine` events, validates the whole chain through the kernel public
verifier `verify_event_chain`, emits the wrapper — closed fields `schema`,
`run_id`, `authority` (always `projection`), `run_state_authoritative`
(always `false`), `source_sha256` (the public `stream_digest` over the
verified rows), `kernel_stream` (the carried verified rows), and `stream`
(a nested `orch-dork/lane-events/v1` lifecycle view) — and both projections below
consume that wrapper (legacy raw lane-events streams remain accepted only
for compatibility). The wrapper provenance is recomputable, never
trusted: every wrapper consumer (the dogfood and the
OpenTelemetry import paths) recomputes `stream_digest` over the
carried `kernel_stream` with the released engine and fails closed
with the stable reason `canonical_lifecycle:provenance_unverified`
when the recomputed digest does not match the `source_sha256`
carried by the wrapper, or when the `kernel_stream` is missing
or malformed. The wrapper remains one-way: authority `projection`
and `run_state_authoritative` `false` always carry, and the
carried digest is trusted only after that recomputation.

`orch-dork/dogfood-summary-projection/v1` is compact: `schema`,
`authority`, `run_state_authoritative`, `run_id`, the terminal
`outcome`, the integrator outcome or `null`, sorted `{id, outcome}`
lane records, `counts.lanes`, `counts.completed`,
`counts.blocked_or_failed`, and `source_sha256` — the SHA-256 of the
seq-sorted lane event list of the canonical input, or the recomputed
kernel stream digest when a canonical lifecycle projection wrapper is
the input.

`orch-dork/otel-export-record/v1` is OpenTelemetry-shaped and imports no
SDK: `schema`, `authority`, `run_state_authoritative`,
`source_sha256` (the ingest stream digest, or the carried kernel stream
digest when a canonical lifecycle projection wrapper is the input), a
`resource`
(`orch-dork.run-id`, `orch-dork.schema`), a `scope`
(`orch-dork.telemetry`, version `1`), and `spans`. All spans share one
deterministic 32-hex `traceId`; 16-hex `spanId` values (and
`parentSpanId` for the children) derive from the run id and span name;
`kind` is `INTERNAL`. The closed span set is `orch-dork.run` plus one
`lanes/<lane_id>` span per lane plus `orch-dork.integrator`.
`startTimeUnixNano` and `endTimeUnixNano` are the event `ts` seconds; the
run span start uses only the first event timestamp, and when it is absent
the start is 0 with the `absent` marker even if later events carry
timestamps. Otherwise
scaled by 1e9, with 0 wherever a timestamp was absent, marked by
`orch-dork.time.origin: absent` (otherwise `event_ts`). The deterministic
status mapping is `success`/`completed` to `OK`, `failed`/`blocked`
to `ERROR`, and `cancelled` to `UNSET`.

### Imported evidence re-entry

`imported_evidence_entry` (shape `imported-<kind>-<16-hex-digest-prefix>`,
with `-` converted to `_` in the kind) is the only form by which a
projection may re-enter a LaneResult: it stamps `origin: imported` and
`authority: imported` with a bounded provenance pointer, and it
recomputes no canonical authority. All projection surfaces remain one-way:
imported telemetry is never authoritative run state.


## Flexible work intake and confirmed ticket status schemas

Issue 198 adds provider-free preparation and ticket status tools to the governed
chat journey. Codex interprets supplied text and drafts the work; the host
validates that draft against project enrollment. The MCP source identity is
`params._meta.threadId`, never a task identifier supplied in the arguments.
Preparation creates no run, model call or GitHub access.

The input schema names below label the closed MCP `inputSchema` contracts;
they are not additional `schema` fields in tool arguments. All three tools
reject unlisted argument fields. Model, effort, lane and enrolled-check
validation uses the existing governed-run request contract.

| Input schema | Tool and fields |
| --- | --- |
| `orch-dork/work-summary-input/v1` | `prepare_work_summary`: required `project_root`, `input_text`, `goal`, `model`, `effort`; optional `lanes` or `tickets` (mutually exclusive), `ticket_file`, `worker_model`, `worker_effort`, `cost_budget_usd`. |
| `orch-dork/ticket-status-proposal-input/v1` | `propose_ticket_status_update`: exactly `run_id` and `edits`, each edit exactly `{ticket_id, before, after}`. |
| `orch-dork/ticket-status-confirm-input/v1` | `confirm_ticket_status_update`: exactly `confirm_proposal_sha256`, the returned proposal's 64-character lowercase SHA-256. |

`input_text` is nonempty UTF-8, at most 262,144 bytes, and is opaque provenance.
A ticket draft contains 1–128 rows in document order, each exactly `id`,
`status`, `depends_on`, `writes`, `goal`, `checks`. Identifiers are unique,
non-control strings of 1–128 characters; status is `ready`, `blocked` or
`complete`; dependencies name known rows without duplicates or self edges.
Write paths are canonical repository-relative paths, excluding Git and
Orch Dork control paths, symlinks and hardlink aliases. Each row has at most
128 paths. The host selects ready rows whose dependencies are complete and
whose nonempty write ownership is disjoint from prior selections, up to the
existing run lane limit. Other rows are returned with a skip reason. Empty
ownership does not create a read-only lane or grant write authority; completed
dependency rows may have empty ownership. With no eligible selection, preparation refuses.
Original identifiers remain visible in the summary; native lane identifiers
are normalized when necessary. A singleton stays in the root with zero workers.
All selected tickets must name valid enrolled checks, including a singleton.

The optional `ticket_file` must be a bounded regular UTF-8 file inside the
enrolled project, outside selected lane write ownership, with no symbolic or
hardlink alias. Its relative path and exact byte digest are frozen at intake;
the goal tells the run to leave it unchanged.

| Artifact schema | Meaning and successful response |
| --- | --- |
| `orch-dork/work-intake/v1` | Private sealed intake: project and requesting-task identity, `input_sha256`, `summary`, `summary_sha256`, `selected_tickets`, optional `target` (`path`, `sha256`) or null, `start_arguments`, and `intake_sha256`. |
| `orch-dork/work-summary-report/v1` | `PREPARED`: `summary`, `summary_sha256`, `intake_sha256`, `selected_tickets`, `skipped_tickets`, returned `start_arguments` containing the intake digest, and an instruction to show the summary before start. |
| `orch-dork/ticket-status-proposal/v1` | `APPROVAL_REQUIRED`: `proposal_sha256`, local `file`, exact `edits`, unified `diff`, and the user confirmation question. No ticket mutation. |
| `orch-dork/ticket-status-update/v1` | `APPLIED`: `proposal_sha256`, local `file`, `updated_sha256`, and `mutation_performed: true`. |

Public reports also carry `provider_free: true` and a `report_sha256` seal.
Preparation and proposal reports have `mutation_performed: false`; this refers
to ticket-file mutation, not their private receipt writes. Ordinary refusals
use the corresponding report schema, `status: REFUSED`,
`reason: work_intake:request_invalid`, a diagnostic `message`, and
`mutation_performed: false`.

The admitted plan and run bind `summary_sha256`, never raw input. The intake
seal also covers raw-input provenance. `start_governed_run` with an intake
digest must match the stored task, project, resolved summary and exact returned
start arguments, excluding the digest and any explicit plan approval digest.
A mismatch refuses before capacity is claimed or a model is dispatched. The
run keeps the intake as a private sidecar.

Proposal requires that task's sealed terminal record and a recomputed host
Verified verdict, matching the intake's project and admitted summary. A revised
summary, failed or incomplete run, model claim, another task, or changed ticket
file cannot propose updates. Each edit names a selected ticket exactly once,
replaces one unique nonempty literal string (before/after at most 4,096 UTF-8
bytes), and keeps the whole file within the intake byte limit. The private
proposal seal covers the record and intake digests, task/project, target,
edits, updated text and updated digest. Its `proposal_sha256` identifies that
stored proposal; the public report's `report_sha256` seals the response.

Only explicit user confirmation of that exact displayed proposal permits
confirmation; standing run authority is insufficient. Confirmation rechecks
Verified, record/intake identity, absence of an active project run and the
unchanged file, then claims a create-only consumption marker. It pins the
parent directory, compares file identity again, writes and fsyncs a temporary
file, and replaces the target once. Stale, consumed or task-mismatched
confirmations refuse. A failure after replacement returns `REFUSED` with
`reason: work_intake:write_unconfirmed` and `mutation_performed: true`;
confirmation remains consumed and the diagnostic requires inspection of the
file before another proposal. Such a refusal never claims that no effect
occurred. None of these tools fetches or writes a remote issue.


Issue 211 binds controller source/evidence custody at activation. The canonical
activation records each named root's canonical path and directory device/inode;
its source root must match active enrollment. Subsequent controller requests and
current-root hook exemptions compare the same map before stage evaluators or
review continuations read files. Foreign, removed, added or replaced named roots
refuse; the host may supply its sealed source and plugin defaults. This is root
custody, not an orchestration-time source-commit or checkout-legitimacy check.
