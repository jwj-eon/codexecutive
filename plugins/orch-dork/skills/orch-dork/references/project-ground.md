# Project-ground enrollment and enforcement

## Contents

1. [Status and purpose](#status-and-purpose)
2. [Terms](#terms)
3. [Non-negotiable invariants](#non-negotiable-invariants)
4. [Required architecture](#required-architecture)
5. [Lifecycle](#lifecycle)
6. [Failure modes and responses](#failure-modes-and-responses)
7. [Project-native adapter interface](#project-native-adapter-interface)
8. [Model Coordinate mapping](#model-coordinate-mapping)
9. [Qualification matrix](#qualification-matrix)
10. [Current implementation boundary](#current-implementation-boundary)

## Status and purpose

This reference is the canonical design target for making Orch Dork portable
across projects without treating model instructions or repository data as
mechanical enforcement. It defines the project-ground trust model, lifecycle,
failure behavior, recovery rules, and qualification surface. `SPEC.md` owns
the normative product requirements; this file explains their architecture and
operational consequences.

Project ground is mandatory for governed mutation and whenever an external
enrollment record says the project requires it. An ordinary advisory run in an
unenrolled project may operate within the parent task's existing sandbox,
approval policy, and writable scope. That run has submitted evidence only and
must not claim project-ground enforcement, controller authority, or governed
completion. Once enrollment marks ground required, missing or unhealthy ground
remains `READ_ONLY`; advisory mode cannot bypass that external requirement.

The design does **not** make a full `.orch-dork/project-adapter.json` file the
project's enforcement engine. A repository-local JSON file cannot execute
checks, block writes, detect its own deletion, or safely restore itself. The
existing `orch-dork/project-adapter/v1` evaluator remains a declarative
evidence seam until the tickets linked from `TICKETS.md` implement the deeper
project-ground module described here.

The current Codex hook surface provides useful lifecycle events, including
`SessionStart`, `PreToolUse`, `PostToolUse`, `Stop`, and subagent events.
`PreToolUse` can deny supported local tool calls. Hooks still require trust,
may be disabled unless managed, do not cover hosted tools, do not re-intercept
`write_stdin` for an already admitted process, and may be bypassed by
specialized tool paths. Treat them as an important guardrail, never as the only
enforcement layer. See the official [Codex hooks
documentation](https://learn.chatgpt.com/docs/hooks).

## Terms

**Project ground** is the complete project-specific operating contract needed
to decide whether a task may read, mutate, verify, delegate, publish, or act on
an external system.

**Enrollment record** is a durable trust anchor outside the repository. It
states that an exact project identity requires Orch Dork and pins the active
binding generation. Repository-local deletion cannot erase this fact.

**Binding manifest** is a small repository-owned declarative record. It names
the project, project-ground protocol, executable adapter entry point, exact
adapter digest, and required status. It is discovery and identity data, not
enforcement logic.

**Project adapter** is project-owned executable code that implements the
project-ground interface. It may wrap existing project-native Python, Node, or
other deterministic controls. It runs with no broader authority than the
calling task and may narrow but never broaden the root authority envelope.

**Active snapshot** is the immutable, content-addressed adapter byte set bound
to one admitted ticket or frozen wave. Active work executes the snapshot, not
the mutable repository copy.

**Mutation gateway** is the smallest supported tool, hook, sandbox, or
controller seam through which a protected mutation must pass.

**Maintenance operation** is a separate provider-free enrollment, migration,
repair, or removal attempt. It is never silently folded into product work.

## Non-negotiable invariants

1. `AGENTS.md` is guidance, not an enforcement or recovery mechanism. Codex
   builds its instruction chain at task start; a running task does not obtain a
   live configuration channel from later instruction edits. See the official
   [AGENTS.md documentation](https://learn.chatgpt.com/docs/agent-configuration/agents-md).
2. No repository-local artifact can prove that it should exist after every
   local copy of that artifact has been deleted. Required-state detection
   therefore needs an enrollment record outside the repository.
3. JSON may identify and pin an adapter but never substitutes for executable
   project-native checks.
4. The invariant is an exact compatible generation, not an automatically
   selected latest version.
5. A task binds one project-ground generation before its first mutation.
   Changing the binding, adapter, plugin, authority, writable scope, lease, or
   acceptance criteria expires that admission.
6. Active work never self-repairs its own policy. Missing, changed, stale,
   ambiguous, or unavailable ground makes the task read-only and opens a
   separate maintenance operation.
7. Enrollment, adapter evaluation, hooks, sandbox policy, mutation gateways,
   leases, admissions, and completion evidence are distinct layers. Passing
   one layer never fabricates another.
8. The project adapter accepts authority as input and can only preserve or
   narrow it. Repository data never mints credentials, grants, production
   authority, or hosted authority.
9. Policy files, enrollment state, binding manifests, active snapshots,
   leases, and evidence seals are protected control resources. Ordinary
   implementation ownership does not include them.
10. Missing evidence is unknown, contradiction is failure, and a failed check
    never becomes success through a retry, fallback, replacement, or silent
    downgrade to advisory behavior.

## Required architecture

```text
AGENTS.md
  human and model guidance only

external enrollment registry
  project identity -> required binding generation
                  |
                  v
repository binding manifest
  protocol + adapter entry point + exact digest
                  |
                  v
content-addressed active snapshot
  immutable project adapter bytes
                  |
                  v
authorize(operation, live_context)
  closed ALLOW or DENY result + evidence
                  |
        +---------+----------+
        |                    |
        v                    v
pre-tool hook          project-native gateway
local guardrail        protected semantic action
        |                    |
        +---------+----------+
                  v
sandbox + active controller + durable capsule
  writable scope, lifecycle, ownership, completion
```

The project-ground module should expose one small interface:

```text
authorize(operation, live_context) -> decision + reason codes + evidence
```

Callers should not assemble enrollment, hashing, migration, recovery,
concurrency, or verification logic themselves. Those behaviors belong behind
the interface so the same implementation serves a coding adapter, a
non-coding adapter, a local test adapter, and project-native production
adapters.

### External enrollment registry

Store the registry in plugin-owned writable data or an equivalently durable
local control location, never solely under the enrolled repository. Bind each
record to an exact project identity, host or environment identity where
required, canonical initial root, binding generation, manifest digest,
adapter digest, protocol compatibility, status, and last-known-good artifact
locators. Use compare-and-swap versioning and retain append-only lifecycle
evidence.

A copied repository, moved root, new clone, worktree, nested repository, or
different saved Codex project is not silently equivalent. Reconcile it through
an explicit enrollment operation.

### Repository binding manifest

Use a small closed manifest such as `.orch-dork/binding.json`. It should name
only stable discovery and identity fields, for example:

```json
{
  "schema": "orch-dork/project-binding/v1",
  "project_id": "model-coordinate",
  "protocol": "orch-dork/project-ground/v1",
  "adapter_command": ["python3", "scripts/orch_dork_adapter.py"],
  "adapter_sha256": "<exact digest>",
  "required": true
}
```

Invoke command fields as argument arrays without a shell. Reject unknown
fields, sensitive keys, path escape, symlinked control files, unsupported
protocols, unknown ownership markers, and ambiguous roots.

### Content-addressed active snapshot

Read the adapter bytes once during admission, verify their exact digest, and
place the verified bytes in immutable plugin-owned content-addressed storage.
Execute that snapshot for the active attempt. Rechecking and then executing the
mutable repository path leaves a time-of-check/time-of-use race and is not
sufficient.

### Hooks, sandbox, and gateways

Use a trusted plugin-bundled or managed `SessionStart` hook to verify enrolled
project health before mutation. Use `PreToolUse` to deny supported local tool
calls when enrollment, admission, lease, generation, scope, or adapter checks
fail. Use `PostToolUse` only for observation and drift detection because it
cannot undo completed side effects. Use `Stop` and `SubagentStop` to request
continued verification, not as substitutes for independent terminal
qualification.

Back hooks with the narrowest practical filesystem sandbox and project-native
mutation gateways. Treat long-running shells, `write_stdin`, child processes,
hosted tools, computer-use paths, specialized tools, and non-Codex external
processes as separate coverage risks. A hook-only claim is never hard
enforcement.

### Durable state

Bind project-ground identity and generation into the ticket admission,
acceptance-resource closure, execution lease, active-controller stream,
coordinator capsule, readiness receipt, and final evidence. Use one writer and
monotonic compare-and-swap generations. A resumed or compacted task validates
the durable capsule and current project ground before continuing.

## Lifecycle

### Enroll

1. Resolve the authoritative project identity and initial root without
   repairing a wrong task by changing directory.
2. Inspect existing `.orch-dork`, adapter, instruction, hook, and project-native
   control files read-only.
3. Refuse symlinks, path escape, unknown ownership, conflicting nested roots,
   unsupported newer formats, or ambiguous existing state.
4. Derive only observable project facts. Ask for or leave blocked any authority,
   protected-resource, external-system, or recovery decision that cannot be
   inferred safely.
5. Stage the manifest, adapter snapshot, enrollment record, and evidence away
   from their active locations.
6. Validate the project-ground interface through local provider-free fixtures.
7. Atomically activate one generation. A crash before activation leaves the
   prior generation unchanged.

### Start or resume

1. Resolve project identity from the task's authoritative initial routing and
   current workspace.
2. Read the external enrollment record before trusting repository state.
3. Require the manifest, adapter, installed plugin, protocol, host, root,
   authority, lease, and admission identities to match.
4. Reject duplicate or split-brain writers through the execution lease.
5. Enter read-only mode on any missing, stale, unknown, or contradictory fact.

### Authorize a mutation

1. Bind the proposed tool and its exact arguments to the current task, turn,
   ticket, lease, adapter snapshot, workspace baseline, and writable scope.
2. Run the immutable adapter snapshot through the closed project-ground
   interface.
3. Deny unsupported tool paths and protected semantic actions unless a stronger
   gateway owns them.
4. Record one structural decision and evidence pointer without parsing prompts
   or private reasoning into authority.
5. Recheck generation and lease immediately before the controlled mutation.

### Verify and complete

The controller, not a model-authored claim, runs or independently binds the
declared focused and final verification commands in the exact repository,
interpreter, environment, and workspace tree. Bind results to command argv,
cwd, environment identity, output digest, and final tree digest. Any later
mutation invalidates verification. Terminal qualification remains subject to
the independent observer and governed completion contract.

### Upgrade or migrate

Require a maintenance operation with no active mutation owner. Compare the
installed plugin protocol with the pinned adapter compatibility range. Keep a
compatible pinned version; do not select latest automatically. For a required
migration, stage transformed artifacts and registry state, run old-to-new and
failure fixtures, preserve the previous content-addressed generation, and
activate through one compare-and-swap. Unknown or newer unsupported state
stops without overwrite.

### Recover

Never repair policy during active product work. Between tasks, a maintenance
operation may restore exact last-known-good bytes only when the external
registry, content-addressed artifact, project identity, and expected digest
agree and no conflicting user change exists. Revalidate the restored adapter
and issue fresh ticket admission. A stale, corrupt, missing, or semantically
changed recovery source requires an explicit migration or user decision.

Permit at most one bounded prerequisite repair and one rerun for a named
defect. Persist the failed attempt and stop rather than entering a recovery
loop.

### Remove

Unenrollment is an explicit maintenance operation. Require no active lease or
attempt, preserve audit evidence and project files by default, remove the
external required-state anchor last, and report which state remains
recoverable. Repository deletion alone never unenrolls a project.

## Failure modes and responses

| Failure | Required response |
| --- | --- |
| Existing control directory has unknown ownership | Preserve it and refuse enrollment |
| Manifest or adapter is a symlink or escapes the root | Refuse before staging or execution |
| Enrollment crashes before activation | Leave the prior generation active |
| Enrollment registry and repository manifest disagree | Enter read-only mode and name both generations |
| Enrollment registry is missing, corrupt, unreadable, permission-denied, or loses a compare-and-swap | Enter read-only mode; preserve repository state and the prior known generation |
| Repository is moved, copied, cloned, or opened as another worktree | Require explicit identity reconciliation |
| Nested repositories claim the same path | Refuse ambiguous ownership |
| Installed plugin and source plugin differ | Refuse publication or governed work until parity is restored |
| Adapter protocol is older but compatible | Continue the pinned generation or migrate explicitly |
| Adapter protocol is incompatible or newer unknown | Block mutation without overwrite |
| Plugin is rolled back below the pinned security generation | Refuse activation |
| Active snapshot storage is missing, corrupt, unreadable, permission-denied, or rolled back | Refuse execution and preserve the attempt as blocked |
| Adapter passes a hash check and is then replaced | Execute only the immutable verified snapshot |
| Manifest or adapter changes during active work | Expire admission and block the next mutation |
| Manifest or adapter is deleted during active work | Preserve the attempt as blocked; never self-repair it |
| Repository-local control files vanish between tasks | External enrollment keeps the project read-only until repair |
| Hook is absent, disabled, untrusted, timed out, or crashed | Fail closed for writes and keep diagnosis read-only |
| Multiple hooks conflict | Load all applicable hooks; any mechanical denial remains a denial |
| A tool path is not covered by hooks | Require sandbox or project-native gateway coverage |
| `write_stdin` continues an already admitted process | Treat the process as one bounded admitted operation and monitor its group |
| A long-running or child process writes later | Bind process-group ownership and cleanup; do not infer completion from parent exit |
| An external editor or process changes the tree | Detect baseline drift before each critical gate and completion |
| Two tasks claim write ownership | Admit only the compare-and-swap lease winner |
| Old admission or evidence is replayed | Reject task, ticket, generation, scope, lease, or nonce mismatch |
| Compaction or restart loses conversational context | Resume only from the sealed capsule and current ground |
| Adapter command uses a shell string or sensitive field | Reject the definition |
| Adapter code is untrusted | Require exact trust and run it under minimal privileges |
| Adapter attempts to broaden sandbox, approval, or grants | Refuse the decision |
| Verification is reported but not independently observed | Keep completion unqualified |
| Code changes after final verification | Invalidate the verification tree hash |
| Recovery source is stale, corrupt, or ambiguous | Stop without restore |
| Automatic recovery would overwrite an intentional change | Require explicit maintenance disposition |
| Hook defect blocks all work | Permit read-only diagnosis and an audited maintenance repair, never write fail-open |
| Checks are too slow and users are tempted to disable them | Cache immutable results; keep per-mutation checks small and observable |

## Project-native adapter interface

The external interface should remain one closed provider-free operation even if
the implementation uses internal subcommands:

```text
authorize(operation, live_context) -> {
  schema,
  status: ALLOW | DENY,
  project_identity,
  binding_generation,
  adapter_sha256,
  authority_preserved,
  writable_scope_preserved,
  reason_codes,
  evidence
}
```

`operation` distinguishes enrollment validation, session start, local tool
authorization, focused verification, final verification, controlled semantic
mutation, upgrade, repair, and removal. `live_context` carries only exact
runtime facts and opaque evidence pointers. Do not include credentials,
prompts, copied conversation history, private chain-of-thought, or inferred
authority.

Provide at least two adapters at qualification time: a disposable in-memory or
temporary-project adapter and a real project-native adapter. Test both through
the same external interface.

## Model Coordinate mapping

Model Coordinate already has project-native Python that performs real checks:

- `scripts/validate_session_lease_preflight.py` binds the saved project,
  authoritative initial root, host, permission profile, checkpoint, current
  lease, read-only successor state, and zero credential/reservation/hosted
  activity.
- `scripts/transfer_model_coordinate_lease.py` is the controlled transfer
  gateway. It reruns preflight, invokes Orch Dork's compare-and-swap, and
  verifies durable post-transfer ownership and checkpoint state.

The Model Coordinate project adapter wraps these modules rather than
translating their behavior into JSON. Its binding command carries digest-bound
control paths; the generic runner pins the wrapper entry point and immutable
snapshot, while the wrapper reads each control module once into memory before
execution. Native PASS/REFUSED reports and reason codes remain intact. Hook
and sandbox policy now deny direct low-level lease transfer and direct
lease-file writes through the Issue 42 protected-resource gateway. The wrapper remains
project-owned while the generic plugin owns enrollment, immutable execution,
lifecycle binding, and closed results.

## Orch Dork source-repository mapping

The Orch Dork source checkout owns
`scripts/orch_dork_self_project_adapter.py`, a bounded provider-free adapter
for the same closed operation interface. Its input is one strict JSON object;
unknown fields, sensitive key names, oversized or non-JSON input, and malformed
operation identity are denied. Its output contains only the accepted operation
digest, kind, and provider-free fact.

Enrollment is deliberately not performed by an active source-editing task.
Use `evaluate_project_enrollment` for a read-only preview, then apply the exact
manifest, adapter digest, external registry record, and binding generation in
a separate maintenance task with `active_writer: false`. The next product task
must load and verify that exact generation before mutation. Claiming that the
current writer is inactive in order to self-enroll is a contract violation.

## Qualification matrix

Provider-free acceptance must prove at least:

- clean enrollment, idempotent re-enrollment, and explicit removal;
- collision with unknown files, symlink escape, partial staging, and atomic
  activation failure;
- missing, corrupt, unreadable, permission-denied, and compare-and-swap-losing
  enrollment-registry state without repository overwrite;
- wrong root, saved project, host, clone, worktree, and nested-repository
  identity;
- exact, compatible-old, incompatible-old, unsupported-newer, rolled-back, and
  source/install-mismatched generations;
- adapter deletion and mutation before start, after admission, before a write,
  during execution, and before completion;
- missing, corrupt, unreadable, permission-denied, and rolled-back active
  snapshot storage;
- absent, untrusted, disabled, timed-out, crashed, and conflicting hooks;
- supported local tool denial plus documented uncovered tool, hosted,
  `write_stdin`, long-running-process, and external-process paths;
- one-writer lease contention and stale admission, generation, scope, nonce,
  capsule, verification, and completion evidence;
- malicious command strings, sensitive fields, path escape, authority
  broadening, credential output, and direct protected-resource mutation;
- failed upgrade preserving the prior generation, exact last-known-good repair,
  ambiguous-recovery refusal, and no active-task self-repair;
- independently executed focused/final verification bound to the final tree;
- Model Coordinate rejection of saved-project, root, host, permission-profile,
  checkpoint, lease snapshot, already-owner, credential-access, grant-
  reservation, hosted-call, transfer-request, and compare-and-swap mismatch,
  plus direct lease-file and low-level-transfer denial;
- bounded performance, concise diagnostics, and read-only failure behavior;
- one disposable adapter and the real Model Coordinate adapter through the
  same interface.

## Current implementation boundary

Issue 40 supplies the provider-free enrollment layer. Its read-only policy
tool validates one exact external record and repository manifest; its separate
module/CLI apply seam can stage and compare-and-swap enrollment or explicit
removal in disposable/local maintenance fixtures. The layer binds exact
project/root/host/saved-project/workspace/worktree identity, adapter bytes,
generation, collision state, last-known-good locators, and append-only events.
It never auto-enrolls, repairs active work, executes an adapter, installs a
hook, alters a sandbox, or infers authority.

Issue 205 confines executable adapter authorization to trusted host callers.
The model-facing MCP catalogue excludes `authorize_project_ground`, and its
retired dispatch name receives the standard invalid-tool error before reads,
snapshot creation or launch. A caller-supplied digest or lifecycle hash cannot
grant adapter execution authority. The bounded host library interface remains
supported, including its immutable snapshots and provider-free evidence.

Issue 41 now supplies the generic `authorize(operation, live_context)` seam,
disposable immutable snapshot runner, and the integrated Model Coordinate
wrapper in the source checkout. Its policy descriptor is read/evaluation-only;
the provider-free qualification matrix covers snapshot/process failures,
authority/lifecycle binding, mutable wrapper/control drift, and the native
session-lease mismatch matrix. It does not enroll a project, install a hook,
alter a sandbox, reserve authority, or make a hosted/model call.

Issue 42 now supplies the provider-free mechanical layer in source:
`hooks/hooks.json`, `hooks/project_ground_hook.py`, and the closed
`evaluate_project_ground_enforcement` policy surface. A gateway-sealed state
record and session-health seal bind every supported local mutation to the
ticket, lease owner, enrollment generation, adapter snapshot, authority and
writable scope, workspace baseline, readiness, controller, capsule, and exact
tool input. Protected control resources require a named exact gateway; later
mutations persist completion invalidation. Post-tool and stop hooks remain
observation/continuation controls, never rollback or terminal qualification.

Issue 160 adds the optional hard native binding outside that legacy program.
The host-owned controller atomically writes a sealed `native_controller`
member beside the program in `project-ground/current.json`. `WAITING`,
`BLOCKED`, and `TERMINAL` deny every supported mutation; `ACTIVE` permits only
the exact root session, tool name, and canonical tool-input hash for one
single-use action. The synchronous hook atomically consumes that exact grant
from the controller's canonical SQLite database before returning allow, so a
duplicate request, rewritten grant snapshot, changed capacity head, or
rolled-back binding cannot restore it. Grant and hook-projection snapshots are
checked against sealed append-only transition histories, and the outer
RunEngine chain plus owner row must verify first. PostToolUse requires the
identical official tool-use ID and revalidates the create-only closed/self-
sealed PreTool report; controller observation revalidates it again, then
persists a closed/self-sealed matched action ID, normalized actual outcome,
raw-result digest, and sanitized report, which the controller must re-read before it advances or
enters cleanup-only state. Tampered binding, changed input, child session,
stale cursor, missing or contradictory PostTool evidence, or an unmatched
durable intent fails closed. Legacy records without this member keep their
advisory Issue 42 behavior and cannot claim hard native governance.
Legacy behavior applies only when canonical SQLite proves that no controller
owner exists. Once activated, the hook rejects a missing projection and checks
its root/session/model, action, status, event tip, store, grant history,
projection history, capacity cursor, and read-only policy against canonical
authority on every event. Nonterminal native state also
forces pending completion, independently blocking premature Stop.

Issue 43 now supplies pinned compatibility, transactional migration, exact
last-known-good recovery, read-only diagnostics, immutable evaluation caching
with generation/lease/scope rechecks, latency accounting, and the closed
provider-free replay. The external active record is written last through one
compare-and-swap; transform, validation, hook, publication, install, binding,
or activation failure restores the prior repository binding and leaves the
prior content-addressed generation active. Recovery is between tasks only and
requires exact locator, digest, identity, unchanged destination expectation,
no conflicting user change, and fresh admission.

Issue 209 bounds maintenance content reads to owned regular files reached
through no-follow directory descriptors under the program's project and
external registry roots. Each file is limited to 262,144 bytes before its
first content read; one evaluation or transaction has a cumulative 1 MiB
read budget. Hashes stream in chunks, and changed files refuse. An explicit
trusted-host `staging_roots` argument may admit a separate staging directory;
the closed model-callable program cannot add that authority. These roots
describe read-only diagnostic inputs, not authority to govern a task.

Read-only evaluation and cache generation checks run in one owned process
group with a five-second execution bound and separately bounded cleanup.
The MCP dispatch lifetime cancels that process group; stateful host handlers
keep their existing process-local custody. Public timing includes process
startup and cleanup, and unknown timing stays null. Explicitly admitted
maintenance writes remain in their original host process with bounded reads,
the existing ten-second transaction deadline, CAS and rollback behavior.
The preview reports its consumed bytes over the private process envelope and
debits the host transaction's same read budget. A backup-read refusal stops
before replacement; rollback starts only for writes actually attempted after
their backups succeeded. Cache hits refresh all current timing fields.
Recovery rechecks the exact source digest and destination expectation before
replacement. Rollback retains the same transaction lock; unsuccessful
restoration reports uncertain preservation and a mutation instead of claiming
success. Lock acquisition polls its deadline, all diagnostic facts participate
in cache freshness, and apply timing includes report construction and hashing.
Apply preserves lexical file paths through no-follow validation, including
post-preview replacements. It seals the final timing verdict under the same
lock: any deadline or budget refusal after writes restores the backups before
unlocking. Delivery of that sealed result does not re-veto a committed
transaction.

Issues 40–43 themselves enrolled or migrated no real project and trusted no
hook. Plugin hooks remain non-managed until reviewed, and a disabled or skipped
hook cannot police itself. Issue 160's controller does not infer trust or
retroactively govern work that preceded activation; the fresh task must
present a host-signed, freshness- and replay-checked observation of the
reviewed hook definition and registration, and noninteractive automation may
use only Codex's externally attested exact-invocation bypass. Hosted,
specialized, `write_stdin`, child-process, computer-use, and external-process
paths remain ineligible unless the declared sandbox or project-native gateway
independently covers them. The controller reserves shared capacity only during
the staged host transition and never invokes a native/model/hosted action.

Issue 193 scopes the hooks and adds governed runs from an ordinary task
(Owner decision D2, 2026-10-03). Outside the qualification host the hooks
enforce only for a task a governed state binds and pass every other task
through unchanged, writing nothing for it. A task is bound when the
project-ground state names its thread as the lease thread or the native
controller's root session, when it already left governed evidence (a
session-health record or durable events), so deleting or rewriting the state
never releases it, or when the governed-run watcher wrote a sealed
`orch-dork/governed-run-binding/v1` for its thread before the first
turn. Codex 0.160.0 fires SessionStart at the first turn, and every hook
event in a task, a worker's own tool calls included, carries the task's
thread id as its session id. A watcher-bound task has zero workers: its own
tool calls run under Codex's sandbox and are recorded create-only as
`orch-dork/governed-run-hook-event/v1`, every collaboration call and
worker action is refused, input to a running process, background children
and calls naming Orch Dork's records are refused, and a missing, malformed,
ended or stale binding fails closed. Stop is never blocked, because the
watcher computes the verdict from the enrolled project's checks it runs
itself after the turn and joins the hooks' records to the owner rail by
tool-use id; any action one side saw and the other did not ends the run
Refused.

Issue 194 adds guided enrollment and standing authority. `enroll_project`
reads the project's own declarations for its checks: a pytest configuration,
a package's test script run by the package manager its lockfile names (and
its lint and typecheck scripts), a Cargo or Go module, or a Makefile test
target. More than one candidate, none, or a command missing from PATH is a
named question; the user states the command and it is recorded as stated.
The proposal also reads the requesting task's model from the turn context
Codex recorded, lists the models Codex reports with a second model suggested
from a different family, and reports where governed runs reach V1 with the
confirmed opt-in that moves the user's own Codex there. `confirm_enrollment`
applies the answers: when the project has no active project-ground
enrollment it writes `.orch-dork/adapter.py` (the generic project-ground
adapter, pinned by digest) and lets this layer write `.orch-dork/binding.json`
and the external record under its own compare-and-swap lock, reusing an
existing active enrollment and overwriting nothing. One sealed
`orch-dork/governed-enrollment/v1` record, outside the project, carries the
checks with their pinned files, the chat and second models, the V1 location
and opt-in answer, and the `orch-dork/governed-standing-authority/v1`:
workers (four by default, at most eight), per-run and daily cost limits, the
allowed Workflow Profiles, the role lineup (Cheap: the chat model plans and
reviews and the second model writes the code; Balanced: the chat model writes
and the second model reviews; Local: two local models), per-run approval and
keep-on-my-machine. Commands and paths change only through this seam on the
user's machine; a governed run cannot edit them. Whichever of the two models
has not passed onboarding is probed by one detached job (`read_onboarding`),
and governed runs stay refused with the profiles' reasons until two
different models pass.

Every run is admitted before it starts (ADR 0002): the request's frozen
`orch-dork/governed-run-plan/v1` (summary digest, Workflow Profile, workers,
the model for each role, effort, and budget) is compared with the standing
authority. Within every limit the run starts with a notice and the plan as a
Mermaid diagram; beyond any limit it asks, naming each one, and starts only
when the same request returns that exact plan digest as the approval. The
question is recorded as an `orch-dork/governed-run-ask/v1`, and an approval
from the task it was put to answers it once: it starts the plan that day,
within the hour, while no limit the question did not name is exceeded, and
the run consumes it. Billing is not observable, so a run's budget is the
per-run limit unless it asks for more, and the daily limit counts every
budget admitted that day in full; once it is reached, further runs ask. A
START decision is written create-only as the run's
`orch-dork/governed-run-admission-claim/v1`, and the watcher re-derives the
plan and refuses a run whose claim does not bind it. A stop request
(`stop_governed_run`) is written beside the run; the watcher interrupts the
turn or ends the running check and records Stopped by you with the usual
cleanup. A turn that does not confirm its end within the grace period after
the interrupt is recorded as unconfirmed (`governed_run:stop_unconfirmed`):
the run's binding still ends, so the hooks refuse the task's further tool
calls.

Issue 195 adds parallel lanes (Owner decision 2026-10-03).
`start_governed_run` may name up to eight `lanes`, each with an id, a goal and
one to four checks: an enrolled check, optionally narrowed by `selectors` to
the files holding the lane's acceptance tests (pytest arguments, or a package
script's arguments after `--`); every file a selector names must exist in the
project and is pinned like a check's own files. A run with lanes is
`execute_verify_repair/v1` for one lane and `parallel_join/v1` for more, its
`model` is the lineup's planner and its `worker_model` the implementer. The
governed task coordinates and does no lane work: the binding (now
`orch-dork/governed-run-binding/v2`, with a round and its spawn permissions)
holds one permission per lane, the exact message, model and effort of that
lane's worker (the message compared word for word, each run of whitespace read
as one space). The hook allows a spawn only when it matches an unused
permission, which its records call a spawn grant, claims it create-only
(`orch-dork/governed-run-grant-claim/v1`) and binds the worker the spawn
started (`orch-dork/governed-run-grant-outcome/v1`); waits and closes may name
only those workers (the repair round may also close a first-round worker left
open), a worker no spawn result has bound is refused, other messages and the
task's own shell and patch calls are refused, and a worker gets the
zero-worker task's closed set of tools. After the turn the watcher joins every
root and worker action to Codex's own record of each thread
(`orch-dork/governed-run-lane-cross-check/v1`), then runs each lane's checks
and the project's checks on the joined tree. A failed check gets exactly one
repair round, one worker spawned with a message the watcher computes from the
failed checks under a binding holding only its permission, before every check
runs again. A repository with a live or starting run, or a plan whose workers
would take the machine past eight, is refused at once, and a run with more
lanes than Codex's `agents.max_threads` lets one task keep open is refused by
the watcher before any task starts; a spawn Codex itself refuses starts no
worker, the checks decide, and the record names it. The record
(`orch-dork/governed-run-record/v3`) keeps each lane's worker, its checks and
any overclaim, both rounds, and the `orch-dork/governed-run-cost-summary/v1`:
usage by role from Codex's token counts, the limits, and a frontier-only
savings estimate labeled as a token estimate, with billing unknown.


Issue 196 adds steering while a run is active. In the requesting chat call
`steer_governed_run` with `run_id` and the user's exact `text`; it is forwarded
once with `turn/steer` on the retained owner connection. Typing directly in the
governed task is recorded too. Each steer retains its source task, source
turn, exact text and Codex user-message identity; every verdict with a recorded
steer carries `steered_by_you`. `read_governed_run` includes the live steering
record and any revision offer. A lane root may forward a steer once to each
bound worker, with that exact message and `interrupt=true`; the v3 binding
holds those continuation permissions, and the hook claims them once and binds
their outcomes before the owner rail cross-checks them. Other continuations,
extra spawns, and reuse of a closed worker remain refused.

A steer leaves the admitted summary and permissions in force. When an action
outside those permissions is refused after a steer, the watcher preserves the
refusal and offers one next revision for that parent. Use `revise_governed_run`
with its `offer_sha256` and `accept`: a decline keeps the original plan. A
later root or bound-worker refusal can reopen that same immutable N+1 choice,
without erasing the original refusal or the previous answer. An
acceptance supplies the revised `goal` and `lanes` (empty for zero workers).
It rechecks onboarding, standing authority, daily budget, machine capacity and
Codex's worker cap, freezes a sealed predecessor-bound revision, and activates
it on the same governed task only after the old turns are confirmed ended.
Beyond standing limits it returns `APPROVAL_REQUIRED`; only after the user
approves that question repeat with its exact `approve_plan_sha256`. The model
and effort remain fixed, old grants are never reused, and all rounds retain
their evidence. A run forwards at most sixteen steers and accepts three plan revisions
including the original; its one repair allowance is shared across revisions.
Refused attempts retain their exact text and known source with an unresolved
source turn explicitly unknown. Direct messages past the forwarding bound
remain in the record, end the run as Interrupted, and never disable Stop.
Each admitted revision reserves its whole budget because billing is unknown.
If the original turn finishes with an unanswered offer, the watcher holds a
bounded `AWAITING_REVISION` phase without a model turn, so the offer remains
answerable. Declining runs the original plan's checks; accepting starts the
admitted revision. Stop, owner loss or the answer deadline ends the wait.
Live and terminal projections include each control result and any approval
question, even when the requesting call returned before it was consumed.

`Stop` from either chat ends the run, including during checks and repair.
Losing the owner connection ends it as Interrupted — not verified. Codex keeps
turns alive after a client disconnect, so the watcher explicitly interrupts
owned turns and archives workers not already proven closed. It may open one
cleanup-only connection to the same daemon, restricted to read, interrupt and
archive; it never resumes the attempt or starts a replacement task. The root
stays visible. Cleanup that cannot be confirmed stays unknown in the sealed
cleanup report and cannot produce Verified. The v4 run record keeps steers,
revision answers, frozen revisions and cleanup evidence. These controls have
the same hook enforcement scope described above; they do not classify the
meaning of arbitrary shell commands or expand that scope.

Issue 246 pins the project's test tree for each run (Owner decision
2026-10-15). When a run starts, before the governed task exists, the watcher
writes `orch-dork/governed-run-test-tree/v1` to the run directory: the
digest of every file in a `test`, `tests`, `__tests__`,
`spec` or `specs` folder or under a pytest `testpaths` entry,
and of every file named like a test (`test_*.py`, `*_test.py`,
`conftest.py`, `*_test.go`, `*_spec.rb`, and `*.test.*`
or `*.spec.*` JavaScript and TypeScript files); every `pytest.ini`,
and the section that configures pytest of every `pyproject.toml`,
`setup.cfg` and `tox.ini`; and the jest and vitest configuration at
the root, present or absent. The walk skips hidden, dependency, cache and
build folders and follows no symbolic link; a linked test file is pinned by
its target. Before each round's checks, including the repair round and after a
revision, a pinned file or section that changed, appeared or disappeared, or a
new `conftest.py`, `pytest.ini` or other file configuring pytest,
refuses the run with `governed_run:check_changed` and joins
`changed_check_files`. A new test file is allowed. A tree of more than
10,000 test files or 256 MiB, or a project walk past 200,000 entries, refuses
the run before any task with `governed_run:test_tree_too_large`.
Enrollment fixes these rules and pins the configuration that decides which
files are tests; the bytes are pinned per run, so the user's own test edits
between runs refuse nothing. A refused run leaves its edits in the working
tree, and its record names the changed tests.

Issue 247 lets a lane own paths (Owner decision 2026-10-15). A lane given to
`start_governed_run`, `revise_governed_run` or
`prepare_work_summary` may name `writes`: one to 128 canonical
project-relative paths, each owning itself and everything under it, never
through `..`, `.git`, `.orch-dork` or a symbolic link, and
disjoint from every other lane's. Work intake passes each selected ticket's
`writes`. When any lane owns paths, the work summary records each lane's
`writes`, and each lane worker's message names its own paths and the
paths other lanes own. The binding (now
`orch-dork/governed-run-binding/v4`) carries `lane_writes`, each
first-round lane permission's paths; the repair round owns none, and v3 and v2
bindings read as owning nothing. The hook finds a worker's lane through the
spawn outcome that bound it and refuses with
`governed_run:path_owned_by_other_lane` an `apply_patch` whose
`Add File`, `Update File`, `Delete File` or `Move to`
header resolves, against the call's folder and any linked folders, inside
another lane's paths. A shell call is read best-effort: a command part that
names another lane's path and writes it by a redirection, a writing or copying
command, `sed -i` or `perl -i`, a Git command that rewrites files,
an inline interpreter script or a heredoc is refused. A write through a script
file, a variable or a changed folder is not seen. Reading another lane's files
is allowed, and a path no lane owns stays writable by every worker.
