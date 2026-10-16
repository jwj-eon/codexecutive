# Orch Dork conditional execution procedures

## Contents

- [Governed-run owner](#governed-run-owner)
- [Host-owned governed native controller](#host-owned-governed-native-controller)
- [BlindLabeler export and import](#blindlabeler-export-and-import)
- [Execution readiness](#execution-readiness)
- [Logical waves and Sol replans](#logical-waves-and-sol-replans)
- [Advisory scan workflow](#advisory-scan-workflow)
- [Adaptive finite-DAG revisions](#adaptive-finite-dag-revisions)
- [Typed propagation, joins, and adjudication](#typed-propagation-joins-and-adjudication)
- [Worker-to-root escalation](#worker-to-root-escalation)
- [Active controller](#active-controller)
- [Limits and budgets](#limits-and-budgets)
- [Profiles and efficiency](#profiles-and-efficiency)
- [Cancellation and recovery](#cancellation-and-recovery)
- [Worker lifecycle and capacity](#worker-lifecycle-and-capacity)
- [Root rollover](#root-rollover)
- [Model-portable worker seam](#model-portable-worker-seam)
- [Optional ecosystem adapters](#optional-ecosystem-adapters)
- [Projection-aware installed-runtime parity](#projection-aware-installed-runtime-parity)
- [Host-owned observer authority](#host-owned-observer-authority)
- [Current Local task owner](#current-local-task-owner)
- [Evaluator reachability via the launcher fallback](#evaluator-reachability-via-the-launcher-fallback)
- [V3 run-state telemetry and integration](#v3-run-state-telemetry-and-integration)
- [Read custody, lane workspaces, and exceptions](#read-custody-lane-workspaces-and-exceptions)

This reference expands conditional lifecycle paths linked from `SKILL.md`.
The exact wire shapes remain in [policy.md](policy.md). It does not create a
second execution policy.

## Governed-run owner

For a supported governed attempt, use
`evaluate_governed_orchestration_run` with
`orch-dork/governed-attempt-program/v1`; the earlier governed-run/v1 program is
replay-only. Persist each returned receipt before its action and recompute its
seal before the next stage.

1. Build `pre_spawn` before any native creation. Supply fresh advisory ticket
   classification plus the raw AdmissionKernel program, exact logical plan,
   empty-observation wave v3, complete TaskSpecs and independently observed
   route preflights, native budget reservation, per-attempt Sol/total/tool
   limits, readiness, project ground, capsule, installed/fresh generation,
   and a sealed Markdown inventory when the project requires research.
2. `pre_spawn` returns `SHARED_CAPACITY_ADMISSION_REQUIRED`, never spawn
   authority. Invoke `capacity_admission` only through the host-injected shared
   authority adapter. It reserves only the current dependency-ready wave,
   requires a digest-bound commit plus continuity-verified readback, and never
   exceeds the lower of the run concurrency budget and 32. The read-only MCP
   projection has no adapter and cannot cross this boundary.
3. Call native creation only from the resulting `SPAWN_AUTHORIZED`. Treat the
   initial worker exchange as a zero-tool acknowledgement handshake. Before
   allowing substantive tools, submit all exact creation/session identities, sealed
   session-runtime route observations, and TaskSpec acks to `worker_start`;
   the observed terminal JSON must hash to the ack, and any early tool or
   wrong model/effort/history permanently fails that attempt.
4. Feed runtime-observed incremental packets, budget records, Sol ingress,
   total tokens, tool-call count, and named per-lane tools through `progress`.
   On `STOP_REQUIRED`, stop the workers and preserve the receipt. Do not send a
   follow-up, resume, or move failed work to root.
5. On completed, failed, or cancelled worker termination, submit one exact
   host-signed cleanup release per reserved lane to `capacity_settlement`.
   The stage atomically commits canonical terminal releases and verifies a
   fresh authority readback. A completed wave advances to the next
   dependency-ready capacity admission or terminal qualification; failure or
   cancellation advances only to recovery. `errored` and `interrupted` are
   normalized to `failed` and `cancelled`; `released` is representation only.
6. A recovery is a new attempt: bind a successor revision to the prior plan
   hash and run the complete `pre_spawn` again. Unchanged attempt identity or
   stale hard admission is refusal evidence.
7. After every node and dependency is terminal and shared capacity settlement
   is verified, call `terminal` with the full
   v3 wave, strict handoffs, verification receipts, claim ledgers, independent
   bounded attempt manifest, trace, capsule, and session-derived dogfood spine.
   For a multi-run task, select an immutable physical-line segment and bind its
   exact ticket and plan; append the requested blind/non-blind provenance-typed
   label separately. A human uses the worksheet path. A model uses only the
   sealed `BlindLabeler` packet export/import path and its separate model chain;
   neither source may impersonate the other.

Do not splice reports or use root narration as a stage. Caller-authored
timestamps do not establish creation or delivery order; native task creation
also refuses future or created-after-observation facts. Any missing, failed,
timed-out, cancelled, unbound, unknown-budget, over-budget, wrong-route,
undeclared-tool, dependency-blocked, or invalid-terminal fact stops with zero
retry, replacement, fallback, or advisory upgrade.

Validation is provider-free. The MCP projection is read-only; the host-only
capacity admission and settlement operations require the injected persisted
authority adapter. The contract is a physical gate only when an external
dispatcher, or qualified project-ground hooks plus sandbox and gateways,
actually withholds native calls until the receipt authorizes them.

## Host-owned governed native controller

`orch_dork_governed_native_controller.py` is the installed host bridge for
that withholding rule. Its sole write interface is
`GovernedNativeController.advance(program)`, exported through the explicitly
named `advance_governed_native_controller` MCP tool with closed `activate`,
`stage`, `observe`, and `inspect` operations. Use that tool after activation
preparation; `run_active_orchestration_controller` is a separate generic
efficiency controller and rejects the governed-native schema as wrong-surface.
The MCP tool and CLI invoke the same interface over a SQLite RunEngine stream,
filesystem Artifact Ledger, canonical Control Tower shared-capacity adapter,
and atomic project-ground hook-state adapter. They make zero native, model,
provider, hosted, credential, or task-creation calls.

Codex derives a legacy plugin's durable data directory as
`$CODEX_HOME/plugins/data/<plugin-name>-<marketplace-name>`. For this installed
marketplace the exact path is
`$CODEX_HOME/plugins/data/orch-dork-orch-dork-local`; do not place controller
state in the replaceable plugin cache. Invoke the installed module with exact
absolute roots and one JSON program on stdin:

```bash
export ORCH_DORK_OBSERVER_TRUST_STORE=/absolute/host-owned/observer-trust.json
export ORCH_DORK_NATIVE_WITNESS_ROOT=/absolute/host-local/native-controller-witnesses
python3 -B "$ORCH_DORK_INSTALLED_ROOT/skills/orch-dork/scripts/orch_dork_governed_native_controller.py" \
  --state-root "$CODEX_HOME/plugins/data/orch-dork-orch-dork-local/governed-native" \
  --plugin-data "$CODEX_HOME/plugins/data/orch-dork-orch-dork-local" \
  --hook-definition "$ORCH_DORK_INSTALLED_ROOT/hooks/project_ground_hook.py" \
  --source-root fixture=/absolute/enrolled-project
```

`--state-root` is only a compatibility assertion and, when supplied, must be
that exact `PLUGIN_DATA/governed-native` directory. The controller stream,
shared-capacity ledger, sole-controller owner row, single-use grant projection
plus sealed transition history, and append-only hook-projection history share
`governed-native/controller.sqlite3`; an attempt-local or caller-selected
database is rejected rather than becoming a shadow authority.
An independent host-local witness root defaults to
`$XDG_STATE_HOME/orch-dork/native-controller-witnesses` (or the platform's
standard user-state fallback) and may be pinned with the absolute
`ORCH_DORK_NATIVE_WITNESS_ROOT` path shown above. It is not plugin data and must
not be copied, restored, or installed with the replaceable runtime. One
read-only create-once manifest binds the physical database path; read-only
per-run witnesses bind the complete controller-marker inventory; and paired
grant-transition intent/commit witnesses bind only sequence and digest
coordinates. They contain no occupancy, lane set, dispatch permission, or
semantic authority and therefore are not a second capacity ledger. Missing,
changed, writable, extra, or database-newer/database-older witness facts fail
closed.
The hook opens that authority for every event, even when the JSON projection is
missing. It verifies the outer RunEngine chain, owner schema/store identity,
grant history, and projection history before deriving activation identity,
current event tip, lifecycle, canonical read-only policy, and the last
projected binding. A removed, rolled-back, resealed, or identity-shifted
projection—or a rewritten grant snapshot—denies rather than reverting to
advisory behavior. An irreversible authority marker distinguishes a truly new
store from deleted projection history, a deleted owner cannot be recreated
while controller residue exists, and the complete grant inventory must equal
the action hashes sealed in controller stage results.

Activation is provider-free and requires an independently active enrollment,
the exact installed manifest version, ticket admission, root/session, plan,
TaskSpec set, authority scope, reviewed hook bytes, and either observed
persisted trust or the exact one-invocation automation bypass. Trust arrives as
a host-signed, freshness- and replay-checked `hook-trust-observation` receipt
stored content-addressed under `PLUGIN_DATA/governed-native/hook-trust`; an
inline caller assertion is never accepted. Activation writes
`project-ground/current.json` atomically with status `WAITING`; supported
mutations remain denied, caller-supplied completion is required to be pending,
and only the closed true-read-only tool set is accepted. The bypass is an invocation property supplied by
Codex and attested by that external receipt after vetting, not trust minted by
the controller or prompt.

When a fresh ticket-admission record is still advisory about mutation, do not
copy its `implementation_permitted: false` placeholder directly into the
post-plan activation state and do not toggle that field by hand. Call the
read-only `prepare_governed_native_activation` MCP seam with exactly
`orch-dork/governed-native-activation-preparation-program/v1`: the candidate
activation payload plus the self-sealed project-adapter report. The preparer
requires a PASS `pre_implementation` / `ADAPTER_READY` report bound to the
exact ticket, admission, and root; copies only the permitting fact and adapter
definition/report digests; refreshes the project-ground self-seal; and returns
`READY_FOR_ACTIVATION` only after the recomposed SessionStart ground evaluates
`HEALTHY`. A malformed, mismatched, nonpermitting, unavailable, or unhealthy
input returns `REFUSED` with no payload. This grants no authority: submit the
returned payload unchanged as the `activate` program to
`advance_governed_native_controller`, never to the generic active-controller
tool, and later pass the independent hard `pre_spawn` admission as usual.

A fresh task whose plugin hook is not yet trusted may do only read-only setup
before activation and no native action. After its session ID is bound, activate
the controller and resume that same still-fresh task with the exact vetted hook
definition enabled (or the one-invocation bypass); SessionStart then seals the
root health record before the first governed action.

The action transport must also be fixed before that fresh task starts. For a
Code Mode Sol/V1 root, set the Codex project or session configuration to
`features.code_mode.direct_only_tool_namespaces = ["multi_agent_v1"]`. The
shipped source-project `.codex/config.toml` is the canonical form. This makes
the V1 namespace top-level and removes it from Code Mode's nested executor
catalogue, so Codex's ordinary function-tool dispatcher runs synchronous
PreToolUse and PostToolUse around the exact call.

Before activation, inspect the current task's real tool surfaces. Require
`multi_agent_v1__spawn_agent`, `multi_agent_v1__send_input`, and
`multi_agent_v1__close_agent` as top-level direct collaboration tools. Inspect
`ALL_TOOLS` and require those same exact identities to be absent from the
nested Code Mode tool surface. Any missing direct tool, present nested mutation, unavailable
catalogue, or contradictory observation is
`DIRECT_ACTION_SURFACE_REFUSED`: preserve the observation and stop before
controller activation, capacity reservation, grant publication, or native
action. `functions.exec` is a custom wrapper and is never an equivalent
governed action path; a nested call beneath it cannot satisfy the hard-hook
receipt contract.

Those names are controller protocol identities, not a claim about the hook
event's serialized spelling. Current Codex special-cases the V1 spawn tool as
`spawn_agent`, while its generic function-hook flattener concatenates namespace
and function name without a separator, yielding `multi_agent_v1send_input` and
`multi_agent_v1close_agent`. Project-ground matching canonicalizes only these
documented exact spellings and their protocol forms. Prefix/suffix lookalikes,
different namespace versions, or single-underscore variants remain distinct
and are denied.

For each later transition:

1. Submit the exact staged governed-attempt program at the current controller
   cursor. Derive the first successor only with the exact installed
   `build_capacity_admission_program(pre_spawn_program, pre_spawn_report)`;
   never retype its schema, identity, predecessor receipt, operation, or empty
   payload. The constructor requires the passing pre-spawn program/report pair,
   validates their binding, and copies the installed `PROGRAM_SCHEMA`. The
   caller imports it from the exact installed
   `skills/orch-dork/scripts/orch_dork_governed_attempt.py`, never from the
   development checkout or a prior cache. The
   controller independently pins that schema before writing a stage intent, so
   a malformed caller input is a cursor-preserving `STAGE_REFUSED`, not an
   evaluator transition. Provider-free stages return no tool action. Capacity
   admission and settlement use the same persisted Control Tower authority as
   every route.
2. When the stage's `next_action` is `spawn`, `continue`, or `stop`, submit one
   closed intent containing only action ID, kind, root actor, and recognized
   adapter. The controller derives lanes, TaskSpecs, route, native operation,
   and an ordered batch of exact direct local-function inputs from sealed
   receipts; the caller cannot supply tool code or lane membership. It publishes
   only one `spawn_agent`, `send_input`, or `close_agent` call at a time, never a
   freeform executor. Spawn publication independently checks the complete batch
   lane set against the current canonical reservation and authority head, then
   binds each per-lane grant to that exact capacity-stream cursor. Any
   reservation or release before PreToolUse makes the published spawn
   permanently stale.
   The production evaluator, action adapter, observer, and trust/replay adapters
   are hard-bound; constructor injection is not a public option. It persists an intent/result pair and
   returns one single-use action. It does not invoke it.
3. The root invokes only that action. `PreToolUse` matches root session, action
   grant, tool, and canonical input hash, then atomically consumes the grant in
   the canonical SQLite authority before returning allow. The grant also binds
   the official `tool_use_id` and exact durable PreTool report. A duplicate, child,
   changed byte, rolled-back hook binding, or non-current controller tip is
   denied. `PostToolUse` reopens and validates that same create-only durable
   PreTool record, and the controller validates it again before advancing.
   Only then does PostToolUse write a create-only, closed, self-sealed event
   containing the matched action ID, normalized per-lane outcome, raw-result
   digest, and report hash. The complete durable identity is re-derived from
   the activated project ground; digest-shaped substitutions are not evidence.
4. Submit a closed native-action receipt plus that exact PostToolUse report.
   Every outcome requires the result-bound durable hook event. A completed
   per-lane call may atomically publish the next exact call in the same batch;
   only the final call produces the aggregate lane binding consumed by the
   governed-attempt stage. A partial spawn failure deterministically publishes
   exact `close_agent` compensation calls for already-created lanes before
   entering cleanup-only state. Failed, cancelled, or timed-out batches retain
   cleanup; unknown or contradictory evidence terminalizes while retaining
   capacity. None grants retry, fallback, replacement, or action widening.
   The accepted observation retains both durable records and their seals in
   the controller stream. Every later stage must reopen the complete retained
   set before it can authorize a successor. A completed spawn additionally
   carries a closed lane-to-worker bijection, and `worker_start` must present
   exactly those host-returned worker IDs.
5. After identity-bound cleanup releases every lane, submit terminal evidence.
   The CLI's closed observer verifies a host-signed content-addressed
   `attempt-observation` receipt. Only `TERMINALLY_QUALIFIED` materializes
   completion state that lets Stop/SubagentStop finish; every nonterminal sync
   forcibly projects pending/unbound completion.

Every mutation first lands a durable intent. A restart with a complete result
reconstructs the byte-identical sole action and rematerializes hook state. A
crash after the controller result but before grant finalization recovers only
an exact `PROVISIONAL` row bound to the preceding intent cursor. A missing
grant is corruption/outcome-unknown and is never re-minted. A
grant-transition witness intent written just before SQLite commit may be
re-entered only by the byte-identical transition; a changed action/event/tool
identity conflicts, while a committed witness absent from SQLite proves
rollback. SQLite committed without its matching external commit witness stops
without healing the missing file. A restart whose final durable fact is an
unmatched controller intent is
`OUTCOME_UNKNOWN`: it denies mutation permanently rather than guessing whether
dispatch occurred. The root is the only native task-creation actor. Workers
have no controller operation, no action grant, and no spawn authority.
The plugin-data singleton may rotate to a different controller only after the
prior stream and hook binding are both terminal, no intent/action/cleanup is
pending, canonical occupancy is zero, and no grant remains `AUTHORIZED`,
`DISPATCHED`, or `OUTCOME_UNKNOWN`. One distinct
`TERMINAL_OUTCOME_UNKNOWN` state settles ownership authority without settling
the native outcome. It is reachable only for the sole claimed
`OUTCOME_UNKNOWN` spawn after the same owner's exact sealed
`partial_native_failure_terminalization` result and an independently verified
empty capacity read at a later canonical cursor. The state-only transition
retains its tool-use claim and pre-action evidence, leaves all outcome/result
fields empty, and creates no action or native authority. The successor's
attempt ID, run ID, and admission hash must all be different. Sequential
independent attempts therefore remain possible without permitting two active
controllers, treating an unknown result as success, or turning cleanup into a
same-attempt retry.

## BlindLabeler export and import

Use the provider-free model-labeler CLI only after the human corpus contains
one effective label-ready spine bound to the exact run. Packet export replays
that spine against the named session bytes and copies only the validated frozen
plan and bounded mechanical evidence. It prints JSON; it neither writes a
verdict nor calls a model:

Mechanical label readiness is necessary but not sufficient for model export.
If the exact frozen plan or other safe judgment evidence cannot be recovered,
the exporter refuses; the run may still remain available to the separate human
worksheet path.

```bash
python3 scripts/orch_dork_dogfood_model_labeler.py packet \
  --corpus "$HOME/.local/state/orch-dork/dogfood-corpus.jsonl" \
  --run-key RUN_KEY \
  --session /path/to/exact-session.jsonl \
  --compact > /path/to/blind-packet.json
```

Derive the exact transport request from that packet. The envelope is a sealed
audit artifact; the two component views let a transport receive the same
deterministic instruction and packet-specific JSON Schema without rebuilding
either one:

```bash
python3 scripts/orch_dork_dogfood_model_labeler.py request \
  --packet /path/to/blind-packet.json --compact \
  > /path/to/model-request.json
python3 scripts/orch_dork_dogfood_model_labeler.py request \
  --packet /path/to/blind-packet.json --component answer-schema --compact \
  > /path/to/model-answer.schema.json
python3 scripts/orch_dork_dogfood_model_labeler.py request \
  --packet /path/to/blind-packet.json --component instruction \
  > /path/to/model-instruction.txt
```

Use a fresh transport invocation that can enforce the emitted JSON Schema.
For example, a separately authorized Codex CLI transport may pass the schema
through `--output-schema` and persist only the final message through
`--output-last-message`; its event stream must still be inspected to record
actual tool use and invocation identity. The request contains no model or
provider selection. The operator supplies those as transport provenance.
Schema enforcement establishes output shape only, never packet-only context,
zero tool use, semantic correctness, blindness, or model quality.

Give that exact packet to any sufficiently capable model in a fresh context
with no tools, inherited conversation, aggregate analysis, prior labels, or
peer verdicts. The model returns only `orch-dork/dogfood-model-answer/v1`: one
`verdict` with all four closed fields and packet-local evidence references, or
one `abstain` with its closed reason. A bounded justification is permitted;
private chain of thought is not requested or retained. The transport separately
records model/version when known, transport, invocation when known, bounded
inference configuration, prompt-template hash, and exact context/exposure
declarations. There is no provider or model-name allowlist.

Import writes only the model chain. The human corpus is read to revalidate the
current spine and duplicate boundary and remains byte-intact:

```bash
python3 scripts/orch_dork_dogfood_model_labeler.py record \
  --corpus "$HOME/.local/state/orch-dork/dogfood-corpus.jsonl" \
  --model-chain "$HOME/.local/state/orch-dork/dogfood-model-verdicts.jsonl" \
  --packet /path/to/blind-packet.json \
  --answer /path/to/model-answer.json \
  --provenance /path/to/model-provenance.json \
  --recorded-at 2026-08-26T00:00:00Z \
  --host HOST
```

Malformed, stale, unsupported, contradictory, duplicate, or partially repaired
answers refuse before append. An abstention is preserved and cannot be retried
as a fresh initial answer. A changed opinion is an explicit additive correction
using both `--corrects-entry-sha256` and `--correction-reason`; the original
line remains intact.

Do not extract an object from surrounding prose. A transport failure or
prose-wrapped final message remains a refused invocation. A later call for the
same still-unlabeled run is a new explicitly authorized invocation with its own
identity and provenance, never an automatic retry or fallback from the failed
one.

Project the two chains without concatenating them:

```bash
python3 scripts/orch_dork_dogfood_model_labeler.py summary \
  --corpus "$HOME/.local/state/orch-dork/dogfood-corpus.jsonl" \
  --model-chain "$HOME/.local/state/orch-dork/dogfood-model-verdicts.jsonl"
```

The summary reports human and model strata separately. Only accepted blind
verdicts count once per run. A non-blind answer remains recorded but cannot
satisfy the floor. Export/import is not authority to invoke a model; obtain any
required model-call authority separately.

## Execution readiness

Before governed credential inspection, grant reservation, or model dispatch,
run the project-native disposable readiness runner and pass its closed program
to `evaluate_execution_readiness`. Bind the exact executor,
controller, adapter, policy and MCP descriptor, finalizer, evidence schema,
environment runner, readiness evaluator, lifecycle policy, interpreter,
repository and working directories, disposable root, OS capabilities, plan,
and authority scope.

An ordinary advisory run uses the parent task's existing sandbox, approval,
and model-dispatch authority. It does not consume this readiness gate and may
not project parent authority into `READY_FOR_AUTHORITY` or a governed claim.

The replay must persist terminal or durable-unknown evidence before
propagating timeout, cancellation, provider exception, missing usage,
finalizer exception, partial evidence, or cleanup failure. It must cover owner
work before release, release send and delivery, sender binding, duplicate
delivery, expiration, late completion, and integrator failure. The release
deadline begins at `release_sent`, never at assignment or legitimate owner
work.

Only `READY_FOR_AUTHORITY` satisfies the prerequisite. It is not an authority
grant and cannot make a spent grant reusable. Unavailable, unknown, stale, or
mismatched facts stop provider-free. Setup failures consume no model attempt
and permit no retry or fallback. A changed implementation, environment, plan,
authority scope, or lifecycle policy expires the receipt.

## Projection-aware installed-runtime parity

Compare a normal development checkout with one installed plugin root through
the public runtime projection rather than passing the raw checkout to the
strict runtime-only validator:

Python callers use
`validate_projected_runtime_package(source_root, installed_root)` from
`orch_dork_runtime_package`; release construction uses the same module's
create-only `project_runtime_source(source_root, projection_root)` helper, so
there is no second release-only projector. Operators use the matching CLI
mode:

```bash
python3 -B <development-checkout>/skills/orch-dork/scripts/orch_dork_runtime_package.py \
  <development-checkout> <installed-plugin-root> --projected-verify
```

Exit zero means the closed
`orch-dork/runtime-package-projection-parity/v1` report is `PASS`; exit two
means `BLOCKED`. The command copies only the normalized runtime allowlist into
an owned temporary projection, delegates exact byte, mode, inventory,
manifest, descriptor, and package-digest parity to the strict runtime-package
authority, and requires independently observed cleanup. Its report contains no
input or temporary path, file content, credential, or private fixture. Expected
development-only files and generated artifacts outside the projection are
ignored, while any installed-runtime contamination or drift fails closed.

## Host-owned observer authority

Provision the local receipt authority once from the installed plugin root,
using a stable host identifier:

```bash
python3 -B skills/orch-dork/scripts/orch_dork_observer_authority.py \
  --host-id jwj-lab --compact
```

The command atomically creates an owner-only Ed25519 seed, pinned public trust
store, and initialized SQLite nonce registry beneath
the owner-home `.local/state/orch-dork/observer-authority` subtree. Its report
contains only the public key identity and filenames; it never prints the seed
or absolute host paths. Repeating the command validates and reuses the exact
authority. It refuses unsafe permissions, symlinks, ownership changes,
malformed replay state, a different host ID, or disagreement between the seed
and trust store.

At server start the portable MCP launcher validates that fixed state and sets
`ORCH_DORK_OBSERVER_TRUST_STORE` and `ORCH_DORK_OBSERVER_REPLAY_DB` only when
the host has not supplied explicit values. Missing or invalid state does not
become trust: signed observation verification remains unavailable or refused.
Restart the plugin host and use a fresh Codex task after provisioning so the
new server process owns the discovered environment.

The same two variables are how a Control Tower that was constructed without an
injected trust store and replay guard verifies the signed lane-release
receipts in the shared capacity ledger. Any process that reads that ledger
after a lane has been released (a recovery driver, a dry run against a copied
controller database, an ad hoc `ControlTower()`) must export both; without
them the ledger read refuses `lane_ledger_observer_authority_unconfigured`
before any receipt is checked, and the read report's `reason_codes` are
exactly `["lane_ledger:authority_read_failed",
"lane_ledger:observer_authority_unconfigured"]`. The rule is the receipt
verifier's own (`observer_receipt.host_authority_configured`): both halves
named, by injection or by the environment. A trust store and replay guard
that are both named but unreadable are configured, so their failure is a
verification failure, reported as the ledger's
`lane_ledger_authority_invalid`.

Provisioning never rotates an existing authority. Rotation is explicit host
maintenance: first stop observer writers and MCP readers, preserve the old
trust and replay state for outstanding receipt audit, move the complete state
directory aside, provision a new generation, and then restart into a fresh
task. Never replace only the seed, trust store, or replay database in place.

## Current Local task owner

A governed fresh-task qualification must bind its actual app-server owner
before the server starts. Launch that bounded Local app server on an owned Unix
socket and export the same absolute path as `ORCH_DORK_APP_SERVER_SOCKET` to
the server. The plugin's `.mcp.json` declares that exact variable in
`env_vars`, so Codex forwards it—and no broader environment policy—to the MCP
child. The path is transport identity, not authority; the socket and its parent
must remain owner-only. This owner observer is a diagnostic surface, not a
qualification prerequisite or release-blocking orchestration gate.

`observe_current_local_task_runtime` may diagnose a task-owner mismatch. The evaluator
uses Codex's official `thread/read`, `thread/loaded/list`, and filtered
`thread/list` methods over only that injected socket. PASS requires that the
server owns and has loaded the exact per-call MCP task and that the fresh task
has no direct descendant record. It returns only a sanitized owner-identity
digest and bounded counts, with zero provider, model, hosted, credential,
network, task-creation, or native calls.

For one-invocation hook trust, call
`observe_current_local_task_hook_trust` through the repository-owned
activation-handoff driver. It additionally binds the exact Unix peer PID to a
bounded `/proc/<pid>/cmdline` read, accepts one bypass flag only before the
`app-server` subcommand, and reports only argv and invocation digests. Prompt
text, an environment claim, a flag after the subcommand, duplicated flags, or
an owner process without a readable exact invocation never authorizes receipt
issuance.

Missing owner injection, unsafe or changed socket identity, a different
owner, `thread not found`, an unloaded task, pagination, or any existing
descendant fails closed. Never query a fixed app-server socket, search for
another socket, restart a server, or replace owner evidence with rollout-file
inference. A standalone `codex exec` task has no queryable app-server owner and
is therefore not the qualification host for this governed path.

## Evaluator reachability via the launcher fallback

The plugin's stdio server is declared in `.mcp.json` (command
`python3`, args `-B scripts/orch_dork_mcp_launcher.py serve`, `cwd` rooted at the
plugin). Current Codex installs materialize that declaration as the
`orch-dork` MCP server; inspect it with `codex mcp get orch-dork`. A task keeps
the tool catalog with which it started, so restart the plugin host or create a
fresh task after installation, cachebuster, or MCP configuration changes.

Check the fresh session tool catalog first. If the registered server is still
absent, or a required evaluator is missing, run the launcher directly from the
plugin's own root directory as a diagnostic and emergency fallback:

```bash
python3 -B scripts/orch_dork_mcp_launcher.py serve
```

Drive it over stdio JSON-RPC: send `initialize`, then the
`notifications/initialized` notification, then the `tools/*.tool` calls; read the
response whose `id` matches from stdout. A `tools/list` probe returns the exact
evaluator inventory before any policy work begins. Wrap every call's
arguments in the documented program envelope (`{"program": {...}}` or
`{"plan": {...}}`); a bare object is rejected as `-32602 Invalid tool or
arguments`, so send the envelope, not the inner object. The clean-machine
acceptance probe in the repo's own suite is a reference implementation of
this launcher check. A successful direct probe establishes server health, not
active-task registration; preserve it together with `codex mcp get` output
when reporting an installer or catalog regression. If the launcher probe fails
or the evaluator inventory mismatches, stop with the evaluator named and the
probe evidence preserved: there is no local re-implementation of a policy
gate, and a missing route is a reachability stop, never a silent policy change.

## Current-turn route and hybrid OCX setup

`observe_current_orchestration_route` is the sole root preflight adapter. MCP
calls require Codex's per-call `_meta.threadId`; missing metadata fails closed
instead of falling back to a process-start task. The direct stdio/shell launcher uses
the equivalent `CODEX_SESSION_ID`/`CODEX_THREAD_ID`. The adapter resolves one
exact rollout under `CODEX_HOME` (or the standard home), retains only
`session_meta` and `turn_context` facts, and treats the final turn context as
authoritative. The sealed identity covers task, turn, root model/effort,
collaboration surface, and governed worker model/effort.
The plan validators reread it at freeze; the coordinator supplies the returned
digest as `expected_identity_sha256` for a second read immediately before
spawn and as `expected_route_identity_sha256` to admission, the logical-wave
runner, and the compatibility spawn-wave validator. Those downstream routes
independently re-observe the identity and accept no admission, waves, or members
when it changed. A catalog row, feature flag, profile name, or
`ORCH_DORK_COLLABORATION_SURFACE` is never runtime evidence.

A live flow that stops to request separate human authorization necessarily
advances to another Codex turn, so it must not carry the preflight turn's exact
route identity into that later turn. Before asking, call the provider-free
`evaluate_live_route_handoff` tool with this closed program:

```json
{
  "schema": "orch-dork/live-route-authorization-program/v1",
  "operation": "prepare",
  "payload": {
    "scope_sha256": "<exact live-attempt scope digest>",
    "authorization_statement": "<exact statement to be approved>"
  }
}
```

Persist its complete `READY_FOR_HUMAN_AUTHORIZATION` report. On a distinct
later turn containing the exact human authorization, call the same tool with
operation `authorize`, the preparation report unchanged, and that exact
statement. The handoff permits only a later turn in the same task with the
same root model, effort, and kind, collaboration surface, and governed worker
model, effort, and kind. Statement mismatch, preparation tampering, same-turn
reuse, task substitution, route change, stale expected identity, or an invalid
route returns `REFUSED` without a live effect.

Success returns `READY_FOR_ONE_ATTEMPT` and the new turn's
`dispatch_route_identity_sha256`. Before installation, registration, task
creation, credential access, network access, or model dispatch, immediately
call `observe_current_orchestration_route` with that digest as
`expected_identity_sha256`; pass the same digest to every ordinary downstream
route gate. This handoff admits only the expected approval-turn transition. It
does not weaken the strict same-turn drift check, replace any independent live
preflight gate, or create continuing authority.

The supported profiles are exactly:

- native `gpt-5.6-sol` or `gpt-6-astra` + V1 + governed routed worker, using the V1 spawn schema
  with `fork_context: false`;
- routed `anthropic/claude-opus-5` + V2 + governed routed worker, using the V2
  spawn schema with `fork_turns: "none"`.

For OpenCodex, a hybrid host keeps catalog mode V2, pins ChatGPT-native catalog
rows to V1, and disables the global V2 feature override so each model row can
select its own surface:

```bash
ocx v2 mode v2
ocx v2 keep-native-v1 on
ocx v2 off
```

Restart Codex only after active tasks are idle, then create a fresh task.
Existing tasks remain pinned. The global V2 feature must be off in this hybrid
configuration: while enabled it overrides the per-model native V1 pin. Routed
Opus still selects V2 from its catalog metadata after the global override is
off. Always confirm the resulting final `turn_context.multi_agent_version`;
configuration state is not proof of the live route.

## Logical waves and Sol replans

Validate a finite `orch-dork/logical-plan/v1` with
`validate_logical_worker_program`. It may contain more useful workers than
current concurrency, but one-worker work stays with Sol. `run_logical_worker_waves`
uses a fresh authoritative inventory before each wave and never places more
workers in a wave than free slots.

Use `orch-dork/wave-program/v3` for every governed substantive delegated run. Its
`route_preflights` contain exactly one independently runtime-observed
`HandoffPreflightCandidateV1` plus its sealed session observation per distinct
subagent `model_profile`. The tool-free candidate contains only its TaskSpec
binding, canary identity/profile, and typed handoff; it never claims its native
route, session ID, usage, tool count, source, or evidence tier. The bounded
session-runtime adapter independently binds either the exact native rollout or
the create-only structural Responses evidence, no-history route, candidate
schema and terminal JSON digest, and exact token/tool snapshot. The controller
derives the compact progress packet and projects `HandoffPreflightV1` only from
those observer facts, then compares the route with the frozen logical plan
before looking at any creation observation.
A historical full `HandoffPreflightV1` remains compatibility input only when
the same independent observation exactly corroborates every claimed field; its
submitted tier alone proves nothing. A missing, duplicate, submitted-only,
mismatched, or malformed canary returns
`PREFLIGHT_REJECTED`, `spawn_permitted: false`, and zero waves or retries.

Zero capacity waits for a capacity event without waking Sol. A partial or
ambiguous creation wave is failed and donates no member to later work. Pending
nodes stay in the immutable plan.

A v3 program binds each exact same-ID `TaskSpecV2` before execution. Live
`evaluate_wave_progress` prefixes carry one or more contiguous
`IncrementalClaimPacketV1` records; packet identity and digest are globally
unique, usage is observed,
monotonic, evidence-indexed, digest-bound, and checked against context, output,
and tool limits as each prefix arrives. A positive completion reserve stops
continuation before a hard limit is exhausted; later packets or a completed
terminal fail. Each wave composes wave-routing v3 from exact native worker and
session membership before custody or terminal evaluation. The terminal carries
exact-or-unknown usage and a status-compatible `HandoffReceiptV1`; terminal
input and output usage are checked
again against the TaskSpec and the logical worker's declared context limit.
Missing usage for a declared limit and exceeded usage are typed failures.
Free-form `terminal_text` is rejected on v3.

Wave-program v2 is the advisory typed logical-wave contract. Its caller-
supplied preflight tier is compatibility evidence, never independent terminal
qualification. Compatibility `plan/v1` advisory runs instead use the admitted
spawn wave and submitted trace. Wave-program v1 is deprecated replay-only and
names v3 as its migration target.

The replay-compatible v1 schema may carry the lane's own final text as
`terminal_text`. When present it is structurally screened before its declared
status is believed. A lane whose text is degenerate -- high-count exact line
or sentence repetition, one n-gram dominating the content, or unbalanced
markup at implausible density -- is quarantined: its status becomes
`failed_degenerate_output`, the wave reports `FAILED_DEGENERATE_OUTPUT` and
lists the lane in `quarantined_worker_ids`, and the typed verdict with its
evidence rides on the reconciliation row as `output_screen`. V1 does not
satisfy the typed substantive-spawn contract.

This exists because an absorbed degenerate answer is permanent: it enters the
root's conversation history and every later root turn re-sends it. Quarantine
reports and stops. It never retries, replaces, or substitutes the lane; the
replan seam below is how a root recovers, and Sol decides.

At a declared Sol decision point, `evaluate_sol_replan` binds the current
plan, immutable node history, persisted Sol identity, and proposed revision.
Only that Sol may revise. The revision links its predecessor and records
retained, added, removed, and dependency-changed nodes plus basis and
authority. Failed nodes remain immutable; only transitive dependants block.
No retry, replacement, fallback, resume, or worker-created delegation may be
inferred.

## Advisory scan workflow

Use the advisory scan state machine for read-only inspection that has at least
two independently verifiable lanes but does not need a governed terminal claim.
It is a convenience composition over the existing logical-plan, typed-handoff,
attempt-observer, session-runtime, and host-signing primitives; it is not a new
dispatch authority.

1. Build one closed `orch-dork/advisory-scan-program/v2` with `operation:
   prepare`. Make lane read scopes explicit and disjoint where possible, list
   exclusions, name one bounded deliverable and verification set per lane, and
   cap handoffs at 1,200 estimated tokens. An exact zero-tool lane declares
   `allowed_tools: []`; the positive TaskSpec accounting ceiling remains at
   least one even when observed tool use must be zero. Call
   `evaluate_advisory_scan` and
   persist the returned preparation receipt, logical-plan digest, and
   TaskSpec-digest map. V1 remains deterministic replay compatibility only.
2. Evaluate fresh current-turn routing, split, capacity, lifecycle, admission,
   ownership, and workspace gates exactly as for any advisory logical plan.
   The preparation report has made no model call and grants no creation
   authority. Perform native creation only under the parent and sandbox
   authority already in force. Do not retry, replace, or reuse an ambiguous
   creation.
3. Wait for terminality through the native lifecycle surface. Preserve one
   typed handoff per lane and perform root/Sol semantic verification. Do not ask
   a participant to reconstruct terminal evidence.
4. Construct one existing `orch-dork/attempt-observation/v1` manifest with the
   exact root and child source paths, complete file hashes, selectors, parent
   edges, expected routes, and attempt ID. Call
   `observe_native_advisory_scan`. It reads only those declared sources and
   returns a path-free projection. Use host signing only when the fixed
   provisioned authority exists; never send a seed or caller-selected key.
5. Reuse the unchanged advisory program with `operation: finalize`. Supply the
   exact preparation receipt, native creation membership, typed terminal
   handoffs, observed usage when available or a typed unknown with its session
   pointer, valid incremental packets when any were emitted, custody coverage
   or typed unknown, exact root verification membership, and one
   `native_observation` binding. `status: observed` carries the complete sealed
   report from step 4. `status: unknown` is limited to
   `native_session_records_unavailable` or `native_observer_unavailable` with a
   source pointer. Omission, an arbitrary reason, a failed observer report, a
   broken seal, or a scan/root/lane/worker/route/terminal contradiction fails.

Report `COMPLETED_ADVISORY` when execution drained and every handoff verified,
even if independent usage, packet, or custody evidence remains unavailable.
Display those unknowns beside the completion instead of relabeling execution as
failed. Conversely, preserve an actual failed lane, invalid handoff, membership
error, or incomplete verification as `FAILED`. In all cases the state machine
is `ADVISORY_ONLY` and cannot authorize a qualified runtime claim.

Do not translate this report into wave v2/v3. A caller that needs governed
qualification uses the governed-run owner and strict wave-v3 path from the
start; it may not retrofit advisory unknowns after execution.

For a governed two-or-more-axis read-only review, use
`evaluate_advisory_scan` in `prepare` mode only as the closed pre-execution
constructor, then feed its exact logical plan and TaskSpecs into the governed
owner before any creation. The caller must not hand-build the review TaskSpecs
or logical plan. This constructor supplies valid empty input references,
deliverables contained by lane ownership, `provider_free` plan authority, and
the declared root effort. Do not execute or finalize the advisory lifecycle,
and do not convert a later advisory completion into governed evidence.

The native observer is a one-way evidence bridge. Codex owns physical worker
creation, waiting, interruption, and closure; the v2 finalizer only binds those
facts to Orch Dork's logical result. A typed unknown preserves truth when the
evidence source is genuinely unavailable, but recurring unknowns are an
operational defect to investigate rather than a substitute for observation.

## Adaptive finite-DAG revisions

Use `adaptive_finite_dag/v1` only as a sequence of validated revisions of one
finite logical plan. Start from a valid `finite_dag/v1` revision and an exact
history/consumption snapshot. Keep every worker's spawn authority false.

When a worker discovers a justified split, it stops and returns the existing
typed `orch-dork/decomposition-proposal/v1`, used here as
`PlanPatchRequestV1`. Do not let the worker spawn children or mutate the active
plan. Present Sol only the compact patch, bounded evidence pointers, budget
reservation, and active-plan hash. The current root/Sol may approve or reject;
the controller alone validates and binds N+1.

Submit a patch only while the named parent is pending or running and after all
of its original predecessors are recorded complete. A completed or failed
parent cannot patch. The binder preserves every original predecessor edge on
every child in addition to child-local edges, requires the semantic join to
depend on every proposed child, and turns a running parent into a pending
acceptance carrier behind the join. It also binds the parent's semantic
resource/deliverable and the refreshed authority set directly, then seals both
for exact retained-content checks; do not mutate either after binding.

Treat the approved child `model_profile` as executable routing input: it
names one registered node profile by its exact identifier (for example
`reviewer.root-labor/v1`, `implementer.governed-worker/v1` or
`escalation.strong-worker/v1`); a root-labor profile becomes a Sol executor
and every other profile becomes a subagent executor for canonical governor
resolution. The three expand-step alias values resolve only through the
registry's historical replay adapter. Treat child `effort_profile` and `tools` only as validated proposal
evidence in v1. The logical-worker binding does not contain those fields;
enforce them only once an explicit downstream `TaskSpecV2` binds them.

Call `evaluate_adaptive_finite_dag` with the exact active plan, proposal and
approval (or explicit nulls), configured per-run limits, observed consumption,
contiguous revision history, controller termination, and root verification.
The controller checks scope containment, proposal/base hashes, DAG validity,
retained content, authority, node/depth/revision/retry limits, and projected
token reservations. A failed check leaves N effective. A successful bind
increments effective depth and active revisions; proposed tokens remain
projected reservations until runtime evidence records actual consumption.
An absent, malformed, rejected, or non-current-root approval is unapproved, not
tampered. Tampered requires an otherwise current approved root/Sol record whose
proposal digest changed; stale proposal or base-plan lineage remains stale.

The hard controller maxima are depth 2, two retries per node, and three active
revisions. Configure positive node, Sol-ingress-token, and total-token limits
for every run; fixture values are not defaults. The controller never performs
a retry or spawn. Any separately authorized retry remains an observed counter
subject to the cap, while the current logical-plan execution contract still
declares no implicit retry, replacement, fallback, or worker-created nesting.
Token reservations are enforced only against the global Sol-ingress and total
limits. The wall-clock reservation is separately checked against the proposal
evidence's remaining minutes. V1 carries no parent remaining-token field and
therefore does not mechanically reallocate or conserve tokens between a parent
and its children. Add explicit parent/child token-ledger fields in a future
contract before depending on that guarantee.

Do not accept completion from a worker or from an exhausted queue alone. The
controller must record terminal success, every non-optional effective node
must be complete, and root/Sol must pass final verification. Otherwise final
acceptance remains pending or rejected. No revision may recursively invoke a
second adaptive controller; this is one root-owned finite sequence, not a
swarm.

## Typed propagation, joins, and adjudication

Freeze every node as a `TaskSpecV2`, including explicit `allowed_tools`, scope,
budgets, dependencies, acceptance checks, and whether it may request
decomposition. Workers return `HandoffReceiptV1` records that summarize claims,
checks, conflicts, unknowns, requested decisions, and content-addressed
`ArtifactRefV1` pointers. Never copy a transcript, terminal history, prompts,
tool history, raw output, session body, or private reasoning into a task or
handoff. Every evidence pointer used by a handoff claim, check, conflict, or
raw-trace reference must also be present in its top-level artifact index.

Workers emit `IncrementalClaimPacketV1` records during execution rather than
buffering all useful evidence until their terminal response. Each packet is
bounded to 2,400 canonical bytes and 600 estimated tokens, is sequence- and
TaskSpec-bound, indexes all claim/check evidence, and contains observed
cumulative input, output, total-token, and tool-call usage. The controller
requires contiguous sequence numbers and non-regressing cumulative usage.

The current handoff validator enforces one uniform cap for all task kinds:
4,800 canonical bytes, 1,200 estimated tokens, and a 2,048-byte result summary.
Future differentiated targets -- ordinary 600–1,200, join 1,500–2,500,
PlanPatch-to-Sol 300–600, and final Sol packet 4,000–8,000 tokens -- are not
implemented limits and must not be reported as enforcement.

Before evidence propagates to a dependant, a different verifier in a clean
context validates the exact task, artifacts, acceptance checks, and (for an
`execute` task) diff through `VerificationReceiptV1`. The receipt's
`subject_handoff_sha256` must identify that exact valid, same-TaskSpec,
`complete` handoff, and its verification artifact index must cover every
handoff artifact. Record accepted claims in `ClaimLedgerV1`. A failed or
inconclusive verification blocks propagation;
re-running it is a separately governed attempt, not an invisible retry.

A `join` consumes only its declared verified inputs. Deduplicate identical
digest-bound claims, but preserve differences in claims, evidence quality,
unknowns, and interface compatibility. Never collapse disagreement by
majority vote. Route a consequential conflict to a declared `adjudicate` task
or to root/Sol with the competing evidence pointers. Adjudication cannot widen
scope, tools, model authority, or budgets, and its result propagates only after
its own clean-context verification.

Before any substantive worker action, validate and persist the exact
TaskSpec-delivery acknowledgement for the lane, native worker, and session.
Do not infer delivery from task creation, a worker message, or later success.
If the native payload is absent or cross-wired, stop mutation, publish a
content-addressed TaskSpec store, validate the selected row against the exact
write scope, and record the incident separately; recovery does not rewrite the
failed delivery event as success.

For evidence-producing work, carry the exact execution receipt through every
derived claim. Classify a failure's origin separately from whether it says
anything about candidate quality. Report advice novelty and actual claim use
as separate sets, including honest zero use. Use Evidence Reveal only for
explicit selectors against a sealed fresh manifest and byte cap.

For campaigns, reserve series draw and token authority before the draw and
never refund failed or cancelled work. Verify sensitive evaluator criteria
with effective falsifying witnesses and hostile constant/oracle/abstention
probes. Adjudicate bounded batches mechanically so each input has exactly one
disposition and every high-risk, unknown, or incompatible item is surfaced to
Sol. Never count multiple workers from the same independence group as quorum
or make causal arm claims across serving epochs.

## Worker-to-root escalation

Freeze a structural escape hatch into every lane brief. The worker uses the
completion disposition `ROOT_ESCALATION_REQUIRED` and stops further mutation
when new evidence shows that the lane is not independently ownable: it needs a
shared mutable core, changes a public wire contract or architecture, changes
acceptance, crosses frozen ownership or authority, or discovers a dependency
that invalidates the graph. The report names the lane and plan, reason code,
bounded evidence pointers, completed checks and artifacts, resources already
modified, last safe state, and proposed root decision. It includes no private
reasoning, prompt copy, or guessed authority.

Time is a detection backstop, not a classification basis. A brief may cap
orientation turns, wall time, or context consumption and require the worker to
run the same structural check at that boundary; merely taking longer than
expected never makes a lane root-owned.

Escalation terminates that lane attempt. Do not send a follow-up that widens its
brief, let root edit inside the frozen orchestrated attempt, or call the worker
again as a retry. Root binds the new evidence into fresh ticket admission. An
`ATOMIC_ADMITTED` decision makes the remaining work root-owned; an
`ORCHESTRATION_PLAN_REQUIRED` decision requires a new closure and graph; refusal
stops. The old attempt and its incurred usage remain observable history.

## Active controller

`run_active_orchestration_controller` consumes the immutable logical plan,
closed runtime event stream, exact authority, adapter disposition, previous
packet cursor, and exact-or-unknown telemetry. It mechanically owns
admission, scheduling, membership, custody, release, duplicate prevention,
and terminal handoff.

Observable events advance the controller without model polling. It wakes Sol
only for declared semantic decisions through one versioned delta packet with
bounded options and stable evidence pointers. An unavailable controller or
failing adapter blocks governed use; it never falls back to advisory behavior.

## Limits and budgets

Before optional work, call `evaluate_orchestration_limits` with versioned hard
ceilings, soft targets, completion reserve, cost weights, append-only ledger,
and candidate reservation. Keep uncached input, cached input, output, and
reasoning as separate raw dimensions. Every raw dimension needs a hard
ceiling; weights are only a derived view.

Hard authority or safety exhaustion and unknown telemetry block the candidate
without erasing completed work. A soft overrun applies only declared
remediation. Non-completion work may not consume the reserve for integration,
verification, external observation, cleanup, or final Sol review.

Before downstream admission, `evaluate_orchestration_budget` reconciles exact
or unknown runtime consumption for hosted calls, tokens, cost, wall time,
turns, children, depth, and concurrency. Submitted or unknown counters remain
unknown, never zero. Rejected local replays are recorded separately from
hosted generations.

## Profiles and efficiency

`evaluate_orchestration_profile` binds one exact versioned collaboration
profile, immutable transition history, provider-free qualification, hosted
canary authority, canary receipt, and regressions. Provider-free success never
authorizes a hosted canary. A clean independently bound sealed-runtime canary
may activate only its exact profile. A verified correctness or lifecycle
regression suspends only that profile; recovery requires verified repair and
fresh provider-free and hosted qualification.

`evaluate_orchestration_efficiency` consumes a predeclared finite matched
contract and sealed evidence. Freeze fixtures, routes, models, efforts, plan,
checks, raw usage, cost weights, timing, failure policy, and terminal rules
before collection. Accepted quality, attributable raw token dimensions,
weighted cost, critical-path latency, and lifecycle reliability are primary.
Sol share is secondary and has no threshold.

Complete evidence closes as `EFFICIENCY_PROVEN` or
`EFFICIENCY_NOT_PROVEN`; bounded incomplete, unknown, incompatible, or
contradictory evidence closes `INCONCLUSIVE`. Cost or latency misses never
disable a correct active safety gate.

## Cancellation and recovery

On cancellation or timeout, call `evaluate_orchestration_recovery` with the
append-only trigger and process-group events, runtime checks for owned
processes, temporary credentials, locks, tunnels, configuration, cleanup
markers, usage, and task identities. Termination is never cleanup. Unknown
cleanup requires recovery.

Any later recovery uses a new plan identity linked to the failed plan and its
own explicit policy and authority. Never retry, replace, fall back, or describe
spent usage as rolled back. Historical Issue 17 and Issue 28 outcomes remain
read-only.

For a bounded dependency graph, `qualify_orchestration_graph` checks declared
nodes, typed edges, joins, bounds, authority, and closed observation. Each
join partitions exact accepted and excluded inputs with reasons. Quorum and
integrator selection are deterministic. Undeclared nodes, edges, releases,
retries, replacements, fallbacks, or bound overruns fail.

## Worker lifecycle and capacity

Before freeze and spawn, call `evaluate_worker_lifecycle` with retirement
capability and two fresh authoritative inventories. Capability is exactly
`supported`, `unsupported`, or `unknown`; unknown takes the unsupported
branch. Changed, partial, ambiguous, or stale inventory prevents freeze.

Under retained-until-shutdown accounting, a completed worker occupies its
slot until an exact terminal-worker record proves no owned live process or
pending delivery, one release request has one observed success, and a later
inventory proves shutdown or absence while all other capacity remains stable.
A delayed, failed, ambiguous, or stale release proves no capacity and permits
no second release call.

When retirement is unsupported or unknown, declare `one_wave_only` before
freeze and fit the wave within reservable slots. If another wave is needed,
schedule an Issue 29 rollover before it. Never infer capacity from terminal
records, reuse an older worker, shrink the plan, or move its work into root.

## Root rollover

At a safe ticket or wave boundary, call `evaluate_root_rollover` only for an
authoritative capacity, context-pressure, repeated-large-input, or explicit
Sol trigger. Seal the checkpoint before the single successor creation call.
An ambiguous creation is `OUTCOME_UNKNOWN`; reconcile by the same marker,
host, project, and time and never create again in that turn.

The successor starts read-only with no inherited conversation. It verifies
routing, checkpoint, worktree, authority, and capacity. It cannot mutate until
an independent observer freezes the terminal predecessor and the approved
project wrapper performs the lease compare-and-swap. Continuity, recovered
capacity, and context reduction are separate results; one rollover never
triggers another automatically.

## Model-portable worker seam

`evaluate_orchestration_worker_port` validates a closed provider-free
`orch-dork/worker-port-program/v1`. The public contract is
`WorkerTransport.invoke(WorkerCall) -> WorkerResult`. Integration may translate
only documented `edit` and `test` capabilities into legacy adapter labels.

The evaluator may inspect manifests, capability profiles, declarative routes,
disposable-worktree records, candidate diffs, evidence, paired qualification,
and activation. It must not contact a provider, run a command, create a
worktree, apply a patch, or promote a route. Provider-free success never
authorizes a model call or live activation. Exact checkpoint, served runtime,
paired program, and authority remain separate; Luna stays the default until a
later activation program independently passes.

## Provider-free Control Tower profiles and scheduler lifecycle

Use `evaluate_orchestration_control_tower` only with the closed Control Tower
program v1 envelope. First call `prepare` with one bounded TaskBrief. If it
returns `PLANNING_REQUIRED`, a later provider-free call may resubmit the same
TaskBrief plus one sealed planning submission containing that exact unexpired
requirement and a valid typed proposal. The direct tracer accepts only the
canonical one-node proposal. General finite-DAG planning uses the registered
`finite_dag/v1` workflow envelope described below.
A ready result is still zero execution authority: submit that exact sealed preparation
to `advance` with `kind: start`. The returned dispatch intent contains the
canonical WorkerCall and model manifest and explicitly reports zero observed
executions.

After the separately owned fake or future admitted adapter executes, call
`advance` with the exact prior cursor, full sealed intent, and observed
WorkerResult. The Control Tower validates call, manifest, runtime, artifact,
TaskSpec, and HandoffReceipt bindings before landing the executor fact. Submit
the emitted verification intent and an independently valid VerificationReceipt
the same way. `direct/v1` and the historical parallel tracer accept the legacy
passing receipt; Issue 147 profiles require the emitted review contract plus
one sealed `orch-dork/review-disposition/v1`. Only admissible PASS evidence can
land reviewer evidence and canonical completion. `inspect` accepts a bounded cursor query and returns reduced state,
artifact refs, and payload-free event projections.

Cancellation is two-step. Submit a current-cursor cancel request, stop all
future dispatch, then return the exact cleanup intent with complete or typed-
unknown cleanup evidence. Cleanup lands before canonical termination. Never
retry a stale or malformed call, reconstruct a missing intent, reuse a failed
response, or infer execution from an emitted intent.

For `parallel_join/v1`, submit `task_brief` and the exact sealed
`workflow_submission` together. Treat any preparation with a non-passing
Topology Closure as terminal pre-dispatch refusal; do not repair its cut,
substitute shared visibility, or issue an executor intent. A ready start emits
only dependency-ready producer intents. Preserve each returned ArtifactRef and
HandoffReceipt exactly. When a producer unlocks an acknowledged serial relay,
advance with the newly emitted dependent intent; never dispatch the dependent
from the plan alone.

The integration intent is the sole join release. It appears only after all
producer facts are in the same RunEngine stream and contains the exact input
ArtifactRefs, handoffs, required producer IDs, Topology Closure digest, and
bounded ingress accounting over both artifact bodies and the canonical
ref/handoff envelope. Return one closed join result that repeats all
inputs, partitions them into consumed and unused refs, names conflicts, repeats
the exact owned criteria, and provides a sealed evidence digest. Any missing
producer, unreadable artifact, conflicting claim, undeclared criterion, or
over-limit ingress refuses without state advancement. A valid join publishes
one immutable joined artifact and emits the ordinary independent verification
intent; only that verification can complete the run.

For `execute_verify_repair/v1`, submit the sealed workflow parameters with
`max_repairs` from zero through two and failure policy `fail` or `escalate`.
Start emits only the original executor intent. Return verification evidence in
the exact emitted layer order. PASS completes immediately. REPAIR must repeat
the immutable acceptance and scope digests, exact failed checks, permitted
source ArtifactRefs, next repair sequence, and bounded instruction. Execute
only the newly emitted Repair intent. Its call, idempotency key, TaskSpec,
context digest, and provenance are new, and its result always returns to a new
verification intent. Never resubmit an admitted repair, reuse the failed bytes,
or create a third repair. ESCALATE is terminal non-success and emits no intent.

For `best_of_n/v1`, submit two through eight unique candidate independence
groups, a distinct comparator group, winner or winner-or-synthesis policy, and
the sealed direct-baseline evidence digest. Start may emit all budget-matched
candidate intents. Return each independently; completion order does not enter
the comparator input. Once all candidate facts land, execute only the
`comparison` intent. Its payload contains opaque `option-NNN` labels and
ArtifactRefs, not candidate IDs, WorkerResults, handoffs, or completion order.
Return one sealed comparison result. Winner or allowed synthesis emits final
verification; tie or escalation terminates failure without repair, retry,
fallback, or replacement.

For a general `finite_dag/v1`, first obtain the immutable planning requirement.
Then submit one sealed finite-DAG workflow envelope containing that exact
requirement-bound planning submission, a closed parallel-form Topology Closure
submission, and the matching integration node. The proposal must be canonical,
finite, acyclic, revision one, inside the TaskBrief node/budget/authority
envelope, and use zero spawn, retry, fallback, and replacement permissions.
Start returns roots only. Submit each WorkerResult against the current cursor;
the Control Tower emits a dependent intent only after every declared dependency
has an applied fact. The integration and final review then use the same intents,
Artifact Ledger, and RunEngine conjunction as `parallel_join/v1`.

The Issue 147 review payload always carries five ordered layers:
orchestration invariants, deterministic checks, execution-grounded checks,
independent review, and human approval. Use only PASS, REPAIR, or ESCALATE. A
later PASS cannot erase an earlier failure. If `required_human_approvals` is
non-empty, the human layer must carry independent PASS evidence; a model or
integrator cannot manufacture it. Requested external effects, non-empty
integrator tools/write scope, or side-effect capability refuse before run state.

Issues 144–145 and 147 are provider-free and do not authorize a real Qwen, hosted,
credentialed, repository-effect, release, installation, or activation
operation. They permit zero retry, fallback, replacement, or hidden repair.

Issue 146 adds scheduled direct execution without changing that boundary. The
embedding controller must explicitly construct the Control Tower with one
closed capacity vector. Its fields are `logical_runs`, `live_sessions`,
`gpu_memory_mib`, `process_slots`, `integration_slots`, `tokens`,
`context_tokens`, `hosted_calls`, and `wall_time_ms`; each is a separate hard
ceiling and `hosted_calls` must be zero in this provider-free generation. The
default evaluator has no inferred scheduler inventory and therefore refuses
scheduler operations until the embedding controller supplies one. Reserve
`tokens` as context plus output plus handoff; do not treat the separately
reported context ceiling as a substitute for that total.

To queue a ready `direct/v1` preparation, submit `advance` with schema
`orch-dork/control-enqueue/v1`, `kind: enqueue`, and the exact
preparation. A successful result is `QUEUED`, lands the normal RunEngine
`started` fact, and returns no intent. Read scheduling state with `inspect`
schema `orch-dork/control-scheduler-inspection-query/v1` and bounded
`max_runs`. This read is a sealed, non-authoritative projection and cannot
advance any run.

Submit the exact returned `scheduler_cursor` to `advance` with schema
`orch-dork/control-schedule/v1`, `kind: schedule`, and
`max_dispatches` from one through 32. The scheduler capacity vector likewise
refuses `live_sessions` above 32. These are instantaneous reservation/execution
bounds, not cumulative run limits: completed, failed, or cancelled runs leave
the active inventory after authoritative terminal and applicable cleanup
evidence, so later waves may create more than 64 total lanes while never
reserving more than 32 at once.

Every Control Tower dispatch path—immediate or queued `direct/v1`,
`parallel_join/v1`, `best_of_n/v1`, and `finite_dag/v1`—also commits its exact
run/node/intent reservation to the one hash-chained global lane-ledger
RunEngine stream before returning an intent. The stream also persists the
root-owned shared authority state used by native Luna and portable Qwen
admission; requests cannot provide their own occupancy or ledger anchor. A
ledger CAS computes availability from all paths and routes together. Queued
direct scheduling reserves there first, commits the scheduler record second,
and, if that second CAS conflicts, retains the unemitted exact lane reservation
for adoption by a fresh scheduling call. It neither dispatches nor consumes a
second identity. Stale or racing controllers therefore fail closed instead of
creating path-local capacity or poisoning queued work. A worker result releases
its reservation only after the exact WorkerResult validates and a typed
zero-descendant cleanup observation is carried in an Ed25519 envelope verified
against host-owned trust and replay state, then bound into the sealed
lane/run/route/terminal/descendant/terminal-evidence/cleanup-evidence receipt.
Cancellation or run terminality requires the same applicable cleanup evidence.
The ledger never grants spawn authority or turns 32 into a launch target.
Legacy native admission follows the same rule: an embedding root must inject
the shared authority reader and CAS committer, bind an explicit run ID, and
atomically commit one capacity-bounded dependency-ready wave before any spawn
call while leaving the remaining ready nodes queued. Its read-only MCP
validator intentionally cannot grant spawn authority. The v1 compatibility
replay validates archived receipts structurally without reading or mutating
shared authority and always reports replay-only, never spawn authority; any
`fresh_native_acceptance` input is refused with migration to the governed-
attempt API. Fresh execution uses that governed-attempt API plus the injected
shared authority adapter. A concurrent stale commit leaves no partial
reservation or replacement.
Each lane-ledger event persists a bounded authority delta, never another copy of
the complete cumulative identity history. On replay, the controller derives the
exact successor state from that delta and verifies release signatures at the
lane-specific observer-verification instant persisted when the evidence was
accepted. Long-lived sequential waves therefore add bounded events without
event-size or restart-freshness becoming a hidden whole-run lane ceiling.
An individual delta contains no more than 32 new run/revision/identity/release
facts and 128 KiB of canonical authority content. Split larger finite work over
successive root-controlled transitions; do not reinterpret that event bound, or
the separate 16 MiB canonical topology-program byte bound, as lifetime
capacity. Decomposition labels have no fixed natural-lane-count ceiling.

One winning scheduler CAS appends sealed reservations to the dedicated
scheduler RunEngine stream and returns the exact dispatch intents selected
under every capacity dimension. A stale or racing controller receives a typed
refusal. A `NOOP` reports no feasible ready run; it does not widen capacity or
manufacture work. Execute each returned intent only through its separately
admitted adapter, then submit its observed result against the queued run's
current cursor. The result is rejected unless both the global lane ledger and
scheduler stream contain the exact matching reservation.

The returned WorkerResult must report exact token usage and exact elapsed
time. Input and output remain inside their separate TaskSpec and capability
limits, total usage remains inside their sum, elapsed time remains inside the
bound timeout, and candidate bytes remain inside the declared four-byte token
projection. Unknown or excessive values produce the business refusal
`advance:worker_budget_exceeded` before artifact publication. An accepted
applied fact preserves canonical usage, timing, and runtime summaries plus the
exact WorkerResult digest for restart-time audit.

For durable single-host operation, inject `SQLiteRunStore` and
`FilesystemArtifactLedger` beneath the same Control Tower. The filesystem
ledger writes create-only content-addressed bytes and sealed provenance; all
receipts remain portable and every read rechecks regular-file status, size,
digest, and record seal. SQLite serializes each reserve-to-commit interval as
one transaction. A process crash or connection close leaves no committed
partial fact; reopening removes only legacy committed sentinel claims and
rebuilds the same verified streams, state, decisions, and scheduler cursor.
Commit validation failure releases its uncommitted claim. Construction refuses
a durable RunStore paired with a volatile artifact adapter. Do not use this
adapter for multi-host writers.

Cancellation or deadline expiry must still be submitted against the current
run cursor. It prevents future dispatch, emits one bounded cleanup intent, and
keeps any reservation charged through cleanup evidence and `terminated`.
Complete zero-descendant cleanup releases it. A
typed unknown terminates the run but remains in `cleanup_unknown` with its
reservation charged; do not infer that an unobserved descendant disappeared.
Never reschedule an expired or cancelled intent,
open another worker, or reinterpret a CAS refusal as permission to retry.

Issues 144–147 are all provider-free and authorize zero live Qwen, hosted,
credential, repository-effect, release, installation, or activation work and
zero retry, fallback, or replacement.

## Inspect inactive learning evidence

Issue 148 extends only the `inspect` operation. Submit schema
`orch-dork/control-learning-inspection-query/v1`, one of the three closed
`kind` values below, and an exact `request`:

- `route` passes one `orch-dork/route-learning-evaluation-request/v1` to the
  pure rule-router or factored-run evaluator. Use the routing action only for
  advice; it does not change the TaskBrief's requested profile or create an
  intent.
- `strategy` passes one `orch-dork/strategy-card-program/v1` for candidate
  proposal, immutable lifecycle decision, or bounded retrieval. Store returned
  observations as quoted evidence, never as executable instructions.
- `terminal_projection` passes `run_id`, a factored `record_run` program, and a
  `propose_card` program. Use this only after ordinary inspection reports the
  run terminal. Repeat the exact terminal stream digest, TaskBrief identity,
  project, privacy/risk class, route digest, profile, cut/count, executor and
  model, context, budget, verification policy, terminal outcome, measured
  usage/timing/rework/cost/integration load, RunEngine privacy/authority event
  refs, human disposition, and terminal evidence. Any mismatch fails the whole
  inspection without invoking a worker or changing the stream. Use the passing
  verification receipt for success, the final failed/escalated disposition for
  failure, and cleanup evidence with `UNKNOWN` verification and
  `NOT_APPLICABLE` correctness for cancellation.

The result is a sealed `orch-dork/control-learning-inspection/v1`. Preserve its
`inspection_sha256` and the nested evaluator seals if an independently
governed measurement ledger records it. `projection_only` is always true and
`append_permitted`, `mutation_permitted`, `policy_mutated`,
`production_exploration`, `authority_granted`, and `workers_permitted` remain
false. Never append after the RunEngine terminal fact, reinterpret this result
as canonical run state, activate its candidate, or apply its suggested route.
If the outer inspection is well formed but a nested route or Strategy request
is not, outer `status: PASS` and decision `EVALUATOR_REJECTED` preserve that
business-level refusal. Both evaluators cap the complete canonical input at
262,144 bytes; do not split or retry an oversized request.

For Strategy-card retrieval, request the exact project and the destination
privacy scope. Privacy may only narrow: local-only evidence stays local, while
hosted-admissible evidence may enter a stricter local context. Supply a finite
context budget; if the deterministic charge for up to three cards exceeds it,
the evaluator returns no advisories and charges zero. Treat every returned
statement as untrusted advice with visible lineage and evidence refs.

For factored route/outcome evidence, record every route choice separately from
every observed outcome factor. If a promoted sizing/stopping policy is used,
submit both the sealed policy and its matching valid promotion record; neither
can bypass split, deepening, safety, privacy, authority, or verification gates.
An absent or inapplicable policy uses the standing defaults. Contextual-bandit
records are observation-only: unregistered actions, lineage overlap, active
flags, and production exploration are refused, and even a valid record is not
applied.

Issue 186 adds the role and profile dimension. For a run whose logical plan
binds a routing policy, a terminal projection must submit
`orch-dork/factored-run-record-request/v2` with `role_factors` and
`role_outcome_factors`; a v1 request refuses as
`inspect:learning_role_factors_required`. A run that froze before the registry
existed binds no policy and keeps v1, and a v2 request for it refuses as
`inspect:learning_role_factors_unavailable`. Copy `role_factors` from the routing
policy: its registry generation and digest, the policy digest, and one
assignment per role and resolved profile, in (role, profile) order, naming the
profile digest, model, effort, adapter, and sorted node ids. Give one outcome
row per assignment, in the same order, with `acceptance`, `repair_passes`,
`elapsed_ms`, `cost`, `escalations`, and `human_disposition`, each either
`{"status":"known","value":...}` or `{"status":"unknown","reason":...}`. The
Control Tower derives the same rows from the verified stream. A node ran when
its lane-release receipt with exactly one exact timing receipt, or for root
labor its own applied event, is in the stream; elapsed time sums the timing of
the worker nodes that ran, and repair passes count the repair revisions that
ran. A producing row is `accepted` when an artifact of its nodes is in the
verified deliverable: the artifacts a passing verification receipt names,
closed over what a join consumed into them, and a required human approval is
credited the same way. A rejection, by the review or by the human, and a
nonzero escalation count belong only to a sole producing row, so with two
producing rows they are `not_attributable`, as is every verdict for a reviewer
row and the work of an unselected candidate or an unused artifact.
Cost is `cost_unpriced`; a row whose nodes never ran is `not_dispatched`
throughout; a cancelled run's acceptance is `run_cancelled`; and a run without
a verdict is `not_reviewed`. Any difference refuses as
`inspect:learning_role_factors_mismatch` or `inspect:learning_role_outcome_mismatch`,
malformed role evidence refuses as `inspect:learning_role_evidence_invalid`, and a
policy the active registry no longer seals to the plan's digest refuses as
`inspect:learning_routing_policy_stale`. The v2 record keeps the v1 route factors
and run-level outcome record unchanged, adds the role factors to the route
record, and adds one sealed `orch-dork/factored-role-outcome-record/v1`. Never
write a missing value as zero or success. An `execute_verify_repair/v1` route
counts one execution plus each declared repair, so its lane count is 1 to 3;
the evaluator formerly refused any count above 1, which left every run that
declared a repair unrecordable.

Issue 148 remains provider-free and permits zero live Qwen, hosted,
credentialed, repository-effect, release, installation, activation, retry,
fallback, or replacement work. Issue 149 is the separate CPU-only topology
laboratory boundary; no Issue 148 result starts it automatically.

## Inspect inactive topology and promotion evidence

Issue 149 also extends only the Control Tower `inspect` operation. Submit one
closed `orch-dork/control-optimization-inspection-query/v1` with `kind:
topology` or `kind: promotion` and the corresponding complete nested program.
Treat outer `EVALUATED` as a sealed projection of nested provider-free work and
outer `EVALUATOR_REJECTED` as the preserved nested business refusal. Neither
decision is canonical run state or execution authority.

For topology work:

1. Use `seal_registry` to freeze one closed registry containing every permitted value for the ten
   genome axes, the finite enumeration order, objective directions, resource
   ceilings, and the budget-matched `direct/v1` baseline. Do not infer values
   from installed models, live capacity, environment defaults, or a search
   adapter.
2. Use `evaluate_candidate` for a bounded explanation, or supply the same exact
   feasibility and FR54 Topology Closure evidence to `enumerate`. Invalid or
   missing evidence is pruned before any metric comparison. Preserve the
   candidate identity and stable prune reasons; do not convert a prune into a
   zero score.
3. Prefer exhaustive streaming enumeration while the declared product is
   tractable. Set the CPU process count independently of the genome. A
   multi-process run must reproduce the one-process candidate identities,
   decisions, order, direct baseline, and Pareto archive byte-for-byte. Keep
   only bounded counters, prune summaries, and the nondominated archive in
   memory rather than materializing the full population.
4. Inspect every objective separately. Correctness/coverage,
   privacy/authority/safety, critical path, tokens/cost, Sol ingress,
   integration/repair cost, and evidence completeness never collapse into one
   reward. Child count and process count are not objectives.
5. `select_frontier` re-enumerates the sealed registry and requires the supplied
   archive to reproduce exactly before it accepts a selection. It may name only feasible nondominated candidate
   digests from that exact archive. Preserve it as inactive selection evidence.
   Do not dispatch Qwen, reserve tokens, unload or restart the resident server,
   create a worker, or treat the selection as a model-quality result.

For promotion work, first seal each complete Champion or Challenger
configuration, then seal one four-part corpus and one result per fixture and
configuration. `seal_configuration`, `seal_corpus`, and `seal_result` are
pure record constructors. `evaluate_offline` revalidates every input, exact
coverage, configuration binding, human-review evidence, validity interval,
and train/holdout lineage before applying the fixed safety, correctness,
usefulness, and efficiency order. Persist the returned record only in a
separately governed evidence store. A retained Challenger remains offline;
shadow, canary, activation, automatic suspension, bandit exploration, and
model-weight training are outside this ticket and inactive.

Issue 186 adds role-default Challengers. A v2 configuration
(`orch-dork/configuration-draft/v2`) also binds `registry_generation`,
`routing_policy_sha256`, and an optional `role_default`. `decide_role_default`
takes the offline evaluation request plus `role`, `champion_routing_policy`, and
`challenger_routing_policy`. Both configurations must be v2 records naming that
role's default; each policy must be the sealed policy its configuration binds,
in the same registry generation, routing the role through exactly that default,
with the configuration's identities running the route's model; and the
Challenger may differ from the Champion only in that default, its routing, and
its model and runtime identities. The action derives the offline evaluation
again from the same sealed inputs and seals one
`orch-dork/role-default-promotion/v1` for the offline stage, `OFFLINE_RETAINED` or
`NOT_RETAINED`, which permits no shadow observation, canary, or activation. The
registry's `role_default_change` replays that decision and names every reason a
change refuses: no Challenger record or sealed decision
(`role_default:challenger_record_missing`,
`role_default:promotion_decision_missing`), a target profile without a release
qualification (`role_default:challenger_profile_unqualified`), a replay,
retention, role, default, or generation mismatch, and, because no decision
records FR60's shadow observation, canary, or forward activation yet,
`role_default:promotion_path_incomplete`. No role default changes until those
stages exist.

Issue 149 performs zero live Qwen, hosted, credential, repository-effect,
release, installation, activation, retry, fallback, or replacement work. CPU
pool processes are local deterministic computation, not Orch Dork subagents.
An oversized, malformed, stale, drifted, pruned, dominated, or inconsistent
input is one terminal evaluator result; do not split, retry, repair, replace,
or fall back around it.

### Continuous frontier qualification

`orch_dork_frontier_qualification` is the provider-free admission layer for
the additive Control Tower v2 frontier campaign. It does not own campaign
state or authority. It loads the checked-in
`runtime/frontier-regression-corpus-v1.json` vault, reproduces the frozen
structural archive, and compiles one selected twenty-fixture corpus into the
existing `orch-dork/frontier-corpus-draft/v2` contract. Every campaign still
enters through Control Tower `prepare`, changes state only through `advance`,
and reads state only through `inspect`; RunEngine remains the run and campaign
stream authority.

The vault contains thirty focused historical manifests: five frozen feature
slices, five review-found defects, five adversarial fixtures including the
exact Issue 111 r5 dependency cut, and three lineage-disjoint five-fixture
holdout groups. The compiler selects all fifteen non-holdouts plus exactly one
holdout group, one fixture from each partition per rung. It seals snapshots,
public tasks, public checks, controller-only checks, lineages, privacy, tool
policy, and artifacts before preparation. Champion and Challenger task and
snapshot digests are identical. Model task projections omit partition,
history, lineage, hidden checks, and expected results. Rotate holdouts only
with `next_holdout_group` after a sealed terminal campaign; a holdout result
never changes the structural archive, selector, system prompt, rubric, weight,
or expected result.

Materialize each model workspace with `materialize_snapshot` under a new
disposable directory. Its receipt permits writes only beneath that snapshot,
sets network and credential access false, excludes Git history and the parent
vault, and allows only repository reads, `apply_patch`, the explicit
build/test commands, and status commands. Never mount the catalogue or hidden
checks into that workspace. Any existing destination, symlink, traversal,
outside-temp target, or digest mismatch refuses before a model session.

Build Sol review input only with `sanitize_sol_packet`. It accepts only the
fixture's allow-listed relative artifact paths for anonymous options A and B,
rejects symlinks, traversal, absolute paths, secret-shaped values, hidden-check
contracts, private option maps, disallowed artifacts, and oversize input, and
never truncates. The conservative byte count is an upper bound on input tokens
and must not exceed 8,000. Sol receives the fixed four-dimension zero-to-four
rubric with one generation, no tools, 12,000 total tokens, and 2,000 output
tokens. Sol is the proxy for human usefulness review; no human review,
human-authored evidence, fallback reviewer, or repair call exists in this
campaign.

Before a release or live registration, call `qualify_installed_runtime` with
the exact plugin root and OpenCodex root. It binds the complete runtime-package
allowlist, runs content-only, reasoning-rich, malformed, over-budget, and
identity-drift records through the installed Qwen/Sol observers, and executes
the shipped OpenCodex parser/adapter probe through the contained process
boundary. A passing report has zero credential reads, network calls, model
calls, and hosted calls. Any missing root, changed closure, parser mismatch,
tool-observer mismatch, process uncertainty, or cleanup uncertainty stops
before registration.

The active OpenCodex 2.35 contract is
`orch-dork/live-zero-tool-request/v2`. It omits the obsolete
`include_reasoning` request field and accepts either one strict assistant
message or one exact opaque `ocxr1` hidden-reasoning envelope immediately
followed by that message. The envelope must have an empty summary, no visible
reasoning content, one bounded canonical `txt` payload, and no tool item; its
bytes never enter terminal output, a receipt, runtime observation, campaign
record, or public qualification report. Missing envelope fields, visible text,
reordering, duplication, malformed encoding, over-budget usage, tools, model
drift, or any extra output fails closed. V1 remains available only to validate
immutable historical requests and still rejects every reasoning item.

Frontier credential admission uses only
`orch_dork_frontier_admission.run_live_loopback_credential_lifecycle`; do not
recreate key management in a temporary campaign runner. The closed draft binds
campaign, purpose, exact runtime identity, `http://127.0.0.1:10100`, a maximum
10-second request timeout, a maximum 60-second lifecycle, and the response
budget. Supply management authority only as an absolute owner-only mode-0400 or
mode-0600 token file. The lifecycle reads it into the current process, creates
one data-plane key through authenticated `POST /api/keys`, sends one fixed
invalid-JSON admission request, deletes the key, then independently censuses
`GET /api/keys`. It returns only bounded statuses and digests. Ambiguity,
unexpected output, possible provider dispatch, cleanup uncertainty, or drift
stops without retry, fallback, repair, replacement, or another key.

Before the first real credential lifecycle, call
`qualify_installed_credential_admission` with the exact installed plugin and
OpenCodex package roots. It hashes the complete plugin runtime allowlist and
installed OpenCodex package, runs the synthetic success, bad-auth, malformed,
duplicate, timeout, deletion-failure, census-failure, and secret-leak matrix,
then exercises OpenCodex's real management and data-plane auth observers with
synthetic credentials inside the contained process boundary. A passing report
must show the Issue 152 response binding, seven loopback requests, complete
synthetic cleanup, and zero real credential reads, provider calls, model calls,
hosted calls, retries, fallbacks, repairs, or replacements. Qualification does
not authorize a real lifecycle or campaign; live preflight and separate exact
post-report authority remain mandatory.

`run_provider_free_campaign` is the release qualification. Supply the sealed
catalogue, `build_qualification_archive()` result, an in-memory or SQLite
RunStore, a new campaign identifier, and one holdout group. The routine drives
all five rungs through the public v2 seam with deterministic synthetic Qwen and
Sol observations and returns a sanitized report plus an in-memory recording.
`replay_provider_free_campaign` accepts that exact recording and dispatches no
external work. In-memory, SQLite with restart around every transition, and
replay qualification identities and recording digests must match byte-for-byte.
Do not persist the synthetic recording in Git. For a live campaign, keep exact
outputs, option maps, transport bodies, ledgers, and private artifacts only in
the owner-local frontier-qualification store; commit only sanitized seals and
aggregate evidence.

Provider-free qualification and installation grant no live authority. A live
frontier campaign requires a fresh task, exact installed-runtime preflight,
and one atomic `frontier-qualification/v1` registration. Once live dispatch
starts, do not change source, fixtures, checks, prompts, rubric, weights,
runtime, installation, or authority to obtain a different outcome.

## Optional ecosystem adapters

The adaptive core remains Python-standard-library-only and provider-free. The
following decisions create later pilot boundaries, not dependencies in this
version:

- **Sweep harness — native optional adapter.** `run_sweep_campaign` consumes
  only a sealed `campaign/v1`, the caller's exact append-only ledger path, and
  an injected replicate adapter. Each request names the ordinary governed
  entry point and program schema; the adapter returns a sealed request-bound
  provider-free receipt. The harness calls once per cell with no retry or
  fallback, records failed bindings as incomplete, and reports only through
  `summarize_sweep_campaign`. Policy, campaign-contract, and trace core modules
  never import the harness. A future live adapter requires its own explicit
  grant and must not reinterpret this provider-free receipt as live evidence.
- **First live sweep — bounded ledger controller.**
  `orch_dork_live_sweep` owns no provider, worker, command, retry, fallback, or
  replacement seam. This local-Qwen path is historical-only while that runtime
  is offline and must not dispatch a new lane. The historical 1,500,000-token v1 grant remains durably
  `ABORTED`. The v2 successor re-reads and binds that exact predecessor before
  sealing its replay plan and accepts only 36 cells, 3,000,000 additional
  attributable local-Qwen tokens, and 14,400,000 ms from the first reserved
  dispatch, with zero Qwen preparation/review sessions or hosted calls. It
  historically reserved 27,000 tokens per lane session (54,000 per two-lane cell, 108,000
  per four-lane cell, 972,000 per family, and 2,916,000 total), creates one
  append-only shard per task family, and permanently charges a
  configuration/seed cell before its native creation calls. The historical operator had to
  run each cell through ordinary
  admission, plan, spawn-wave, custody, trace, and terminal gates and supply
  independently observed logical `qwen-local/qwen-smart` session evidence.
  For the structural Responses transport, that logical route is projected only
  from the fixed returned `qwen-smart` response-wire identity; never compare
  the raw response model with the namespaced request selector. A family shard
  cannot spend another family's allocation. Root joins shards in sealed
  campaign order only after all cells settle or the fixed deadline arrives.
  Ordinarily settlement is a scored completion. Under separately authorized
  v4 policy, a complete exact-route/usage/zero-tool lane set whose terminal
  content alone is missing, unclosed, or conflicting may instead append one
  unscored evidence-failure settlement. For a missing terminal body the
  operator may take one second sealed observation of the same session at
  least the fixed 5,000 ms grace floor later: identical store bytes settle
  the stronger stable-absence cause (`terminal:json_missing_stable`) through
  the v2 evidence-failure draft carrying the sealed two-sample derivation,
  changed bytes keep single-read `terminal:json_missing` semantics, and a
  terminal that appeared re-enters the ordinary scored path with the second
  observation. The re-read never scores, retries, or repairs anything.
  The operator counts those sealed causes
  across family shards and enforces its authorized repetition threshold; it
  never retries, repairs, or replaces the cell. Any untrusted membership,
  route, usage, tool, source, or observation seal stops immediately. An
  all-settled grid may join before the unused wall ceiling. The join records
  completed cells exactly, emits no canonical/replay record for evidence-
  failure cells, leaves every
  shortfall missing, archives three family summaries, and emits aggregate-cell
  replay records without copying route, custody, timing, or token facts into
  the replay-decidable projection. Joined live training records are accepted
  by the learned-policy manifest only when the campaign is complete.
  V1 attribution began with any local-Qwen session undertaken for campaign
  preparation, not only a successfully reserved measurement cell; its two
  pre-start review sessions therefore exhausted that grant. V2 attribution is
  separately scoped to successor campaign execution and permits no Qwen
  preparation, review, qualification, or preflight session. Any failure stops
  without retry or replacement, preserves the partial append-only ledger, and
  requires new explicit authority. A later explicit Owner direction may close
  the remaining window early through `terminate_live_campaign`. That
  provider-free transition verifies the exact canonical and shard bytes,
  preserves the original deadline and raw contradicted completion, appends one
  canonical quarantine/finalization record, and closes
  `INCOMPLETE_EVIDENCE_FAILURE` with no score/outcome, replay record, canonical
  replicate, family summary, extrapolation, or later dispatch. It makes zero
  Qwen/model/hosted calls and consumes no additional token or reservation. A
  mismatch or append failure stops without retry or rewrite.
- **Structural zero-tool measurement transport — one-shot local adapter.**
  After a live-sweep cell is reserved and the exact fresh authority remains
  valid, build its request with `build_live_zero_tool_request`. Revalidate the
  closed envelope immediately before `invoke_loopback_once`; pass the exact
  campaign/grant/reservation binding from the external gate, a dedicated
  credential, a literal loopback `/v1/responses` endpoint, and a new absolute
  response path. The adapter sends exactly one non-streaming request and
  stores the exact bounded response bytes create-only before observation. Use
  the returned typed lane result for ordinary completion input and the
  sanitized runtime projection for independent route/usage/tool evidence.
  The generated schema must remain xgrammar-compatible and omit
  `uniqueItems`; rely on the independent terminal observer for sorted
  uniqueness, disjointness, and assignment membership.
  On non-200, preserve the owner-only response file and the invocation report
  v2 `transport_failure` object. Use its exact status/category to choose a later
  corrective ticket, but keep attempted usage `UNKNOWN`; do not publish or
  parse the raw body into campaign evidence. Its `attempted_requests` is one
  and its `model_calls` is `null`, not a claim that generation did or did not
  run. Drain and terminally stop the tranche. Never repair output, retry,
  redirect, fall back, replace the lane,
  substitute endpoint/key, or issue a second continuation. Request
  construction and response observation are provider-free, but
  `invoke_loopback_once` is a live model-call boundary and must never be
  exercised from implementation tests or without the fresh exact grant. Native
  Codex creation that advertises `exec` remains unsuitable for a zero-tool
  measurement even when its brief requests no tools.
- **Observer-bound route preflight — structural zero-tool adapter.** For a
  strict wave-v3 Qwen canary, first qualify a deterministic representative as
  required by the pre-authorization gate below. After the exact live authority
  exists, seal its accounting-only TaskSpec with
  `build_route_preflight_task_spec`; this constructor owns `input_refs: []`,
  `allowed_tools: []`, `budgets.tool_calls: 1`, and `budgets.retries: 0`, so
  callers must not hand-build those fields or invent content-addressed inputs
  for a self-contained route canary. Build the exact
  `route-preflight-zero-tool-request/v1` with
  `build_route_preflight_zero_tool_request`. Bind that TaskSpec, five-field
  `HandoffPreflightCandidateV1`, attempt digest, live-preflight digest, and
  create-only evidence scope. Run `qualify_zero_tool_transport` again against
  that exact request and installed plugin/OpenCodex closure, revalidate, and
  call `invoke_route_preflight_loopback_once` once with the dedicated
  credential and literal loopback endpoint. Feed only its returned candidate
  and independently sealed `session-runtime-observation/v1` to the unchanged
  wave-v3 projection. A PASS starts exactly two substantive native Qwen lanes;
  any transport, output, usage, route, schema, tool, or projection failure
  terminally stops that generation without retry, replacement, fallback, or a
  native canary. Request construction, validation, synthetic qualification,
  and response observation remain provider-free; implementation tests must
  never exercise the live invocation boundary.
  Loading the canonical candidate validator widens the exact transport runtime
  closure to include `orch_dork_adaptive_contracts.py` and
  `orch_dork_ownership.py`. That digest change intentionally invalidates every
  earlier authority scope: do not reuse an old grant on either host. Rebuild
  and requalify the scope against the new installed generation before any live
  request.
- **Qualification caller rehearsal — projected provider-free gate.** As part
  of the release tier and before CI, release, or a fresh qualification, run
  `python3 -B -m unittest tests.test_orch_dork_qualification_rehearsal`.
  The test creates a runtime-only projection and invokes the shipped
  `orch_dork_qualification_rehearsal.py` driver from that projection. The
  driver accepts one tracked replay case rather than hand-built intermediate
  dictionaries, calls advisory preparation, route TaskSpec construction,
  candidate sealing and validation, route-request construction, governed
  activation preparation, synthetic transport qualification, and structural
  report validation in order, and passes each complete sealed report into its
  next repository-owned consumer. It returns only a sealed
  `READY_FOR_ONE_ATTEMPT` rehearsal report with `dispatch_permitted: false`,
  all live-boundary counters zero, and `stopped_at:
  before_network_model_native`. It never calls a loopback endpoint, model, or
  native controller action. The runtime corpus at
  `skills/orch-dork/runtime/qualification-rehearsal-replays-v1.json` retains
  every terminal pre-live caller failure; Cycle 10 pins the legacy string
  `input_refs`, and Cycle 11 pins the nonexistent `candidate_sha256` report
  lookup. Cycle 12 pins the unavailable `TextEncoder` and `crypto` globals
  used while ephemeral JavaScript tried to assemble and seal approval
  preflight. Cycle 13 pins the 4,096-byte PTY truncation, closed non-TTY stdin,
  and unavailable `btoa` global encountered while ephemeral JavaScript tried
  to transport the already-sealed report to Python validators. Add each later
  terminal pre-live caller failure as another closed replay before the next
  changed generation. Cycle 14 pins the direct read of mixed-sensitivity
  OpenCodex runtime metadata while agent code tried to discover the canary
  endpoint; callers must use only the fixed sanitized readiness surface below.
  Cycle 15 pins the nonexistent root `README.md` imported from a test-only
  research fixture during post-canary governed-input assembly. Its successor
  regression also runs the real closure binder so no acceptance criterion can
  remain unmapped. Cycle 16 pins the ephemeral outer-program field translation
  and literal ticket-admission v1 schema that the production v2 evaluator
  refused. Callers must never assemble that wrapper themselves. Cycle 18 pins
  the raw `project-binding/v1` manifest supplied where activation requires a
  complete `project-enrollment-program/v1`; both activation refusal codes stay
  sealed in the replay corpus. Cycle 19 pins the caller self-seal supplied as
  `hook_trust_receipt_sha256` where activation requires the filename digest of
  a host-signed, content-addressed hook-trust receipt.
  Cycle 20 pins the split activation/stage caller that lost the evidence root
  and freshness window. Cycle 21 pins the owner process whose five discovered
  plugin hooks were all disabled, leaving a returned native worker without
  durable PreToolUse/PostToolUse custody.

  **Historical owner-legitimacy contract:** The v6-v12 instructions below are
  retained to explain those terminal generations. ADR 0007 supersedes them as
  current caller guidance: checkout capture, hook inventory, argv ancestry,
  external-executor projection, and owner-gate reconciliation are not on the
  orchestration critical path. Current qualification keeps the retained
  connection, explicit model/effort, real hook behavior, task/turn attribution,
  governed outcomes, and owned cleanup.

  Before creating the next fresh task,
  call the installed `orch_dork_qualification_host.py` constructor with the
  exact Codex executable, workspace, nonexistent owner socket, observer trust
  store, and replay database. The constructor writes its whole report
  create-only at mode 0600 beside the owner socket and seals that exact path in
  `ORCH_DORK_QUALIFICATION_HOST_PREPARATION`. Launch its sealed `argv` and
  complete four-variable environment overlay unchanged, then pass the whole
  preparation report to
  `verify_qualification_host_pre_turn`. Require the returned strict owner hook
  inventory to contain exactly the five current-generation plugin definitions
  enabled at the expected matchers and source path, and require its live peer
  argv digest to equal the preparation report's sealed launch argv digest.
  The same report seals
  `orch-dork/qualification-first-turn-transport/v9`. Before persistence,
  `thread/start` and `thread/read` can independently project the current time as `createdAt`.
  Installed `reconcile_qualification_idle_task` v3 validates both integer
  timestamps inside the sealed checkout capture window, capped at the current
  observation; equality is not task identity. It preserves both observations
  and the exact solo task, owner, model, workspace, and empty-history checks.
  Replay v29 pins the v14 second-boundary refusal before any owner turn.
  The authorized external caller must use installed
  `create_qualification_controller_root` before a registration command uses
  that working directory. This create-only local write creates missing
  parents and the leaf at mode 0700, refuses existing destinations or unsafe
  parents, and does not change existing permissions. Its frozen destination
  must already be authorized. Replay v30 preserves the v15 missing-parent
  refusal; provider-free rehearsal must mirror the nested host layout through
  pre-registration cwd creation, private Codex registration, and bootstrap.
  Call installed
  `run_qualification_owner_session` with the owned connection factory and
  prepare, authorize, execute, and terminal callbacks. The driver retains the
  exact WebSocket that performs the sole `thread/start` through approval,
  live execution, and terminal recording. The authorization callback waits
  on that connection and validates the user input; execution still enforces
  the frozen scope. A new reader does not subscribe to the task: Codex unloads
  an inactive task after 30 minutes without subscribers. The driver refuses
  detach, resume, replacement tasks, a lost connection, and a missing or busy
  owner immediately before execution. Terminal recording runs before close
  even on failure; there is no reconnect or retry. Reconcile an idle paginated
  task with `thread/loaded/list` and
  `thread/read`; its compact `thread/start` projection may carry
  `gitInfo: null`, and its declared JSONL is not required to materialize until
  that turn starts. Call installed `capture_qualification_checkout`
  immediately before the sole creation, then pass its whole sealed report and
  the whole start/list/read responses to installed
  `reconcile_qualification_idle_task`; never dereference optional task-start
  Git metadata or reconstruct these checks in caller code. Call installed
  `build_qualification_thread_start_params` with the whole preparation and
  checkout reports, then submit its returned mapping unchanged. Never add
  `allowProviderModelFallback`, `historyMode`, or `projectId`: all three are
  absent from Codex 0.153.2's standard `ThreadStartParams` schema and require
  the experimental client capability. The server-default compact response may
  still report paginated history and `projectId: null`. Keep the report's
  random `task_project_id` local to the task intent and later preflight; bind
  the actual task through the sealed five-minute window, exact sole loaded-task
  inventory, and matching whole start/read responses.
  Never close and reconnect or call
  `thread/resume` before the
  first turn. Doing so changes the real hook source away from `startup`, and
  the clean-terminal successor exception correctly refuses with
  `native_controller:root_session_mismatch` before model execution.
  Same-connection startup is necessary but cannot itself override an
  unrelated active canonical controller. The hook therefore reads the private
  report and binds it to the live owner socket plus an exact owner-UID
  app-server process ancestor with the sealed argv and workspace. It performs
  no app-server RPC on the `SessionStart` critical path. Only that root,
  provider-free, event-bound context may admit fresh startup, bounded read-only
  shell, and the exact owner, route, and authorization-handoff gates. When the
  unrelated active controller belongs to an older installed hook generation,
  the context filters only `native_controller:hook_definition_mismatch` and
  records that compatibility decision; hook registration, canonical authority,
  store, state, action, and every other drift remain blocking. It admits no
  native action and cannot settle, rotate, or mutate the protected controller.
  This overlay is
  invocation-local, writes no persistent config or trust hash, and must run
  before task or turn creation. The activation handoff observes and binds the
  same inventory again; bypass argv without enabled hooks is never sufficient.
  Issue 171 owner launch v8 pins the nullable-`gitInfo` caller failure after
  exactly one task creation and before any turn, hook, model, WorkerPort, or
  live-route effect. Replay v23 binds its exact task-start response, transcript,
  terminal receipt, owner failure, installed generation, and clean teardown;
  the next owner must consume the installed create-only, host-bound,
  project-ID-linked two-phase contract before any first-turn authority.
  Issue 171 owner launch v9 pins the caller's explicit capability-gated
  `historyMode: paginated` request. The sole `thread/start` was rejected with
  `-32600` before task creation, and no turn, hook, model, WorkerPort, route, or
  mutation effect occurred. Replay v24 binds its exact transcript, terminal
  receipt, owner failure, pre-call checkout, request intent, installed
  generation, and clean teardown. The next owner must use the installed closed
  request builder unchanged; server-default history projection is observation,
  not caller-supplied authority.
  Issue 171 owner launch v10 pins the second experimental-field refusal. The
  installed builder correctly omitted `historyMode` but still supplied
  `projectId` (and the standard schema also excludes
  `allowProviderModelFallback`); the server rejected the sole request with
  `-32600` before task creation. Replay v25 binds the exact terminal evidence
  plus the generated standard/experimental schema projections. The v6 contract
  uses only the six standard, previously task-creation-proven fields and moves
  the local intent binding to the exact sole-loaded-task reconciliation.
  Issue 171 owner launch v11 passed task creation, idle reconciliation, all
  five enabled-hook checks, and the actual owner gate. Its external client
  then rejected the sealed PASS because it expected `task_id` inside the
  public runtime report, which intentionally omits that field. Replay v26
  preserves this terminal without permitting resume or retry. The v7 host
  contract requires `reconcile_qualification_owner_gate` with the whole
  public report and whole authoritative `thread/read` response, the same
  connection's task/turn identities, and the verified pre-turn owner identity.
  It requires exactly one completed owner-gate MCP call with the identical
  structured report and rejects other actions or missing attributed evidence.
  It grants no dispatch authority and must pass before route/handoff work.
  Issue 171 v13 retained that owner through authorization but its external
  pricing guard mistook positive `discount` metadata for a non-token fee.
  Replay v28 preserves the terminal and separately labels the later public
  response that reproduces the predicate. For an authorized WorkerPort price
  read, preserve the bounded public response before validation, including on
  refusal, then pass those original bytes to installed `bound_published_worker_pricing` from
  `orch_dork_qualification_pricing.py`. This pure guard removes positive
  discounts from its conservative token-price bound and still refuses real
  non-token fees, markups, unknown rates, and the frozen budget ceiling. A
  published-rate bound is separate from actual provider billing and grants no
  authority to retry a terminal scope.
  Cycle 22 pins a new task whose first startup `SessionStart` was compared to
  the verified clean terminal predecessor's root session. The projected
  `orch_dork_qualification_lifecycle_rehearsal.py` driver must read that whole
  persisted canonical authority, construct a different task identity, and run
  the real hook. Require startup `CONTINUE`, mismatched resume `STOPPED`, native
  PreToolUse `DENIED`, and zero live-boundary counters. The exception admits no
  tool action or authority rotation: host-signed predecessor settlement must
  already establish zero active capacity, and successor activation remains the
  only transition that can install new ownership.
  Cycle 23 pins the next ordering failure: startup continued, but the owner
  called `turn/start` before successor activation, so the first runtime
  observer met the predecessor's terminal binding and was denied
  `native_controller:exact_action_required`; its Stop hook then looped on
  `native_controller:terminal_state_required`. Cycle 24 then pinned the
  opposite false assumption: `thread/start` returned the exact idle task, but
  no health or durable startup event existed because Codex runs
  `SessionStart` as part of the first `turn/start`, before model execution.
  Its pre-turn driver refused on
  `successor_startup:session_health_unavailable` with no turn, canary, or
  activation. The owner must reserve the interval after `thread/start` but
  before `turn/start` for the installed
  `orch_dork_qualification_successor.py` driver. Pass only `--case-id`, the
  exact installed plugin and OpenCodex roots, canonical source/evidence and
  enrollment-registry roots, the app-server-returned task id, selected model,
  and a fresh controller id. The driver verifies the owner-bound idle task and
  whole terminal predecessor, then owns rehearsal, governed-input construction,
  settlement of only the exact action-null unmaterialized Issue 94 wave when
  present, the single canary, pre-spawn, signed activation handoff, activation,
  first stage, and the exact capacity-plus-spawn controller program without
  yielding reports to caller code. The prepared controller program is written
  create-only as a whole sealed artifact before the first turn. Require the
  driver's strict `qualification-successor-pre-turn/v5` artifact to return
  `READY_FOR_SESSION_START`, `expected_binding_status: WAITING`,
  `next_stage_action: capacity_admission`, and
  `root_thread_id == root_session_id == task id`. Call `turn/start` exactly
  once only after that report. The real startup hook must then return healthy
  against the already-current successor binding before any model action.

  Cycle 25 pins the next caller-contract failure. The real first-turn
  `SessionStart` passed against the activated successor, but ephemeral agent
  code submitted the capacity-admission stage with `proposed_action: null`.
  Capacity was reserved for the exact `spec` and `standards` lanes, then the
  native controller refused all eight malformed or absent proposal facts and
  required cleanup before any action, task, or worker existed. Replay v11
  preserves that terminal report. The fresh root must instead call the MCP
  tool `authorize_issue94_successor_first_action` with exactly
  `pre_turn_report_path` and `pre_turn_report_sha256`. The tool reads the whole
  mode-0600 pre-turn artifact, verifies the real hook-written startup health
  and durable event, verifies the bootstrap and prepared-action byte
  references, consumes the sealed prepared controller program unchanged, and
  advances the controller atomically. It must not reconstruct the bootstrap
  under the MCP process's different working directory. Only its sealed
  `READY_FOR_ONE_ATTEMPT` report may supply the native tool name and input;
  callers must not translate fields or independently construct the stage or
  proposal.

  Cycle 26 pins the terminal predecessor-capacity seam. The atomic first-action
  repair was present, but the prior null-proposal run had already reserved the
  exact `spec` and `standards` lanes and then terminalized on an empty release
  receipt set. The next pre-turn activation therefore refused
  `activation:active_controller_conflict` after one canary and before any turn,
  action, grant, task, or worker. Replay v12 preserves that packet. Before the
  canary or successor activation, the pre-turn driver now inspects the whole
  canonical predecessor stream and shared authority. It may settle capacity
  only when the predecessor is terminal, action-null, grant-null, intent-free,
  cleanup-free, and its sole admitted wave is the exact two unmaterialized
  Issue 94 lanes followed by
  `shared_capacity:release_receipt_set_invalid`. It issues host-signed cleanup
  observations with `cleanup_status: not_required`, evaluates one canonical
  capacity-settlement program, and requires an empty verified authority
  readback. The sealed predecessor-settlement report is carried whole into the
  successor report. Any other active-capacity shape refuses; it is never an
  activation bypass or a general stale-lane cleanup path.

  Cycle 28 pins the next predecessor seam. The prior qualification completed
  its first turn and owner-process cleanup, but the first-action bridge failed
  before controller advance, leaving the persisted controller `WAITING` at
  the successful `pre_spawn` stage with no action, grant, intent, cleanup, or
  active capacity. A later task must not relabel that state as terminal. It may
  instead supply all six references owned by the pre-turn driver: the exact
  mode-0600 dedicated-run packet and byte digest, the exact mode-0600
  canonical-authority snapshot and byte digest, and the immutable historical
  runtime root and package digest. The repository constructor re-reads both
  whole JSON artifacts, verifies the interrupted turn, clean process group,
  real startup hook, blocked terminal-required Stop hook, original pre-turn
  report, unchanged controller cursor/identity, historical generation and
  hook bytes, and an empty verified capacity authority. Only that pristine
  pre-native shape may append the explicit terminal stage and project a clean
  terminal hook binding. Wrong, partial, aliased, drifted, action-bearing,
  capacity-bearing, non-interrupted, or dirty-cleanup evidence refuses before
  mutation. The v5 successor report carries the complete typed settlement;
  callers never translate its fields.

  Cycle 29 pins the first post-native caller seam. Codex returned the
  successful `spawn_agent` result as one top-level JSON string; the hook
  accepted only a mapping at that level, recorded the result as unavailable,
  and left the exact first action `OUTCOME_UNKNOWN` after creating one worker.
  Replay v15 binds the terminal snapshot, durable PostTool report, raw-result
  digest, controller action/cursor, capacity state, dead-worker state and
  rollout, owner rollout, generation, commit, and package digest. The hook now
  decodes a top-level JSON string once and still requires the decoded value to
  be an object. After every direct action, call
  `advance_issue94_successor_after_native_action` with the unchanged pre-turn
  report path and SHA-256. That repository-owned MCP bridge reads canonical
  action, grant, and durable hook evidence, constructs the native observation
  and receipt internally, advances once, and returns the next exact action.
  Do not translate worker ids, lane ids, hashes, or observations in caller
  code.

  The consumed Cycle 29 predecessor cannot use that ordinary advance: its
  owner process was interrupted after the worker terminated and the grant is
  permanently ambiguous. Before installing a successor generation, run
  `orch_dork_partial_native_failure_recovery.py` once with the exact
  create-only terminal snapshot, worker-state, owner-runner, historical
  runtime, commit, generation, and package bindings. It may append a terminal
  stage and release the two Issue 94 capacity lanes only when every artifact
  and zero-process fact matches. Any partial, live-worker, different-controller,
  altered-rollout, changed-runtime, or non-`OUTCOME_UNKNOWN` state refuses
  without mutation. This is not a general stale-lane cleanup path.

  Cycle 30 pins the owner-rotation seam after that exact recovery. The one
  route canary passed, but successor activation refused
  `activation:active_controller_conflict` before controller activation,
  reservation, turn start, native action, or worker creation. The recovered
  Cycle 29 owner was terminal and shared capacity was empty, yet its claimed
  grant correctly remained `OUTCOME_UNKNOWN`; the legacy rotation path could
  retire only an unclaimed stale `AUTHORIZED` spawn. Replay v16 binds the
  consumed canary, activation refusal, dedicated-run packet, task, generation,
  commit, runtime package, first action, zero-effect counters, and no-retry
  disposition. A later distinct owner may now rotate only after the grant
  store reopens the exact terminal controller stage, confirms that claimed
  spawn is the sole unsettled grant, independently verifies the current empty
  capacity authority and later cursor, and changes only its state to
  `TERMINAL_OUTCOME_UNKNOWN`. This does not revise the historical unknown
  outcome or authorize another native attempt.

  Cycle 31 pins the two-worker post-spawn boundary. Both exact spawn actions
  were durably observed and reduced to an action-null aggregate at controller
  sequence 9, but caller-authored `spawn_outcome` was refused at sequence 11,
  leaving the root and both workers interrupted with cleanup required. Replay
  v17 binds that generation, source commit, package digest, controller/task/
  worker identities, both rollouts, the dedicated owner run, attempt envelope,
  pre-turn artifact, active capacity, refused stage, and clean process group.
  It grants no retry. Before reinstalling or activating a successor, copy those
  exact artifacts into one private evidence root with mode 0600 and run
  `orch_dork_post_spawn_failure_recovery.py` once. Supply both lane-qualified
  worker rollout paths and raw SHA-256 values plus the root rollout, dedicated
  run, attempt envelope, pre-turn report, source root, plugin-data root, and
  still-installed historical runtime/package digest. The driver accepts only
  the complete two-worker spawn bijection at that exact blocked cursor,
  appends one terminal stage, obtains two host-signed `complete` cleanup
  receipts, releases the exact active lanes, and requires a closed empty
  authority. Missing, aliased, changed, live, partial, cross-generation, or
  capacity-mismatched evidence refuses before mutation.

  A successor spawn now begins with a controller-owned acknowledgement
  handshake. Each exact spawn packet contains its sealed TaskSpec-bound
  `pre_work_receipt` and directs the no-history worker to emit only that JSON,
  call no tool, perform no substantive work, and yield. Call
  `advance_issue94_successor_after_native_action` unchanged after each native
  action and again at the typed wait. Until both worker rollouts expose the
  exact zero-tool receipt and frozen model/effort/no-history route, it returns
  `AWAITING_WORKER_ACKNOWLEDGEMENTS`, action null, and names that same MCP tool
  as the sole next invocation. A malformed or early-work receipt refuses with
  no controller mutation. Once both receipts are runtime-observed, the bridge
  alone constructs `worker_start` and returns the first exact
  `multi_agent_v1__send_input` continuation. That continuation binds the
  TaskSpec digest and a bounded source-hash/excerpt-hash review corpus, so the
  worker needs no filesystem tool; only then may substantive review begin.
  A controller-bound child may yield at either handshake boundary without a
  terminal claim, while root `Stop`, arbitrary child mutation, and qualified
  completion remain gated. Large MCP reports preserve their canonical
  `structuredContent`; only the redundant text form becomes a hash-bound
  action projection so stdio framing remains within its fixed ceiling.

  Cycle 32 pins the post-acknowledgement rollout-discovery boundary. Both exact
  spawn observations completed, both no-history workers emitted only their
  TaskSpec-bound acknowledgement and terminated with zero tools, and the
  controller remained action-null, grant-null, intent-free, cleanup-free, and
  `WAITING_FOR_STAGE` with the exact two lanes active. The public bridge then
  refused `successor_action_advance:codex_home_unavailable` because the MCP
  process had no explicit `CODEX_HOME`, even though inherited `HOME` located
  the standard `$HOME/.codex/sessions` tree. Replay v18 binds the immutable
  generation, commit, package, owner packet, pre-turn report, controller event,
  bridge refusal, root rollout, both ACK-only worker rollouts, clean process
  group, zero continuations/substantive work, and no-retry disposition.

  Worker-rollout discovery now prefers explicit `CODEX_HOME` and otherwise
  uses the documented `$HOME/.codex` default; it still refuses when neither is
  available or when the resulting root is unsafe. The selected Codex home must
  be an absolute, non-symlink, owner-owned directory with no group or other
  permission bits. Behind that private access gate, a rollout must remain a
  regular owner-owned file no larger than 128 MiB and may not be world
  writable; this admits Codex's normal mode-0664 rollout while preserving the
  private-root boundary. Before replacing Cycle 32, Cycle 33, or Cycle 34, run
  `orch_dork_post_ack_bridge_failure_recovery.py` once with its exact
  create-only dedicated-run, attempt-envelope, pre-turn, root-rollout, and two
  lane-qualified worker-rollout artifacts and raw SHA-256 values, plus the
  source/evidence/plugin-data roots and still-installed historical runtime and
  package digest. Cycle 32 and Cycle 33 accept only the exact action-null
  ACK-only wait state under their closed per-generation profiles. Cycle 34
  additionally requires its copied mode-0600 durable PreTool denial artifact
  and SHA-256, rereads the canonical plugin-data event, and binds the one exact
  authorized continuation whose flattened hook spelling was denied before
  dispatch. Every profile rereads both runtime observations as one terminal
  TaskSpec receipt with zero tool calls and proves exact active capacity. The
  driver appends one terminal stage, obtains two host-signed `complete` cleanup
  observations, releases both lanes, and requires closed predecessor authority
  plus empty capacity. For Cycle 34 only, it then changes the still-authorized
  continuation grant to `TERMINAL_PRETOOL_DENIED`, retaining the historical
  fact that the native action never executed. Changed, partial, live,
  substantive, incorrectly continued, aliased, cross-generation, or
  capacity-mismatched evidence refuses before mutation. This is not a general
  stale-worker cleanup path. The CLI additionally requires the exact paired
  `--observer-trust-store` and `--observer-replay-db` files from one canonical
  host authority directory. It refuses non-absolute, symlinked, missing,
  misnamed, cross-directory, or ambient-conflicting bindings, installs them
  only for the bounded recovery call, and validates and captures the signing
  authority before constructing or terminalizing the predecessor controller.

  Cycle 33 pins the next rollout-discovery boundary. Its exact private
  `$HOME/.codex` root was mode 0700, while both owner-owned ACK-only worker
  rollouts used Codex's normal mode 0664. The bridge found both files but
  refused `successor_action_advance:worker_rollout_invalid`; the controller
  stayed action/grant/intent/cleanup-free at sequence 9 with both lanes active.
  Replay v19 binds the two exact zero-tool acknowledgements, two identical
  bridge refusals, ten Stop denials, four typed waits, clean owner-process-group
  teardown, and the no-retry/no-receipt result. Its recovery profile admits
  only the matching Cycle 33 envelope and dedicated-run schemas, refusal code,
  and counts; it cannot widen the Cycle 32 profile or authorize general
  cleanup.

  Cycle 34 pins the first controller-authorized continuation boundary. Both
  acknowledgements validated and the controller authorized exactly one
  `multi_agent_v1__send_input`, but Codex exposed the hook event as
  `multi_agent_v1send_input`; the older matcher treated those spellings as
  different and denied `native_controller:exact_action_required` before native
  dispatch. Replay v20 binds the exact authorization, canonical input digest,
  durable denial, one `send_input` call, two separately blocked bridge calls,
  ten Stop denials, zero waits, clean owner-process-group teardown, the still-
  authorized grant, and zero substantive work, receipt, retry, fallback, or
  replacement. Its recovery profile accepts no other pending action or denial.

  Issue 171 owner launch v6 pins the remaining first-turn ordering failure.
  The owner retained one WebSocket across `thread/start`, reconciliation, and
  `turn/start`, but Cycle 36 was still canonically `ACTIVE` with one pending
  continuation. The clean-terminal successor exception was therefore false,
  and the fresh root `SessionStart` stopped at
  `native_controller:root_session_mismatch` before model execution. Replay v21
  binds the exact task, turn, generation, source commit, installed package,
  preparation, owner inventory, app-server argv, rollout, protected
  controller/action, terminal records, zero live effects, clean process group,
  and no-resume/no-retry disposition. Its repair is the process-attested
  read-only qualification-owner context above; it does not reinterpret or
  mutate Cycle 36.

  The pre-CI regression calls that same constructor with only readiness and
  route transport injected, runs against a runtime projection, then invokes
  the real projected `SessionStart` hook against the activated binding and the
  real projected stdio MCP launcher from the plugin runtime working directory.
  The first bridge consumes the prepared first-action artifact and seals
  `READY_FOR_ONE_ATTEMPT`. The rehearsal then invokes real `PreToolUse` and
  `PostToolUse` with a synthetic top-level JSON-string result, calls the real
  projected post-action bridge, and requires the exact second `standards`
  action at batch index 1. It never invokes the native spawn and asserts no
  live boundary, network, provider, model, native call, task, or worker.
  Generic pre-activation
  controller/native mutation remains denied. A fatal unactivated successor
  may stop with `native_controller:successor_not_activated`; that is a
  nonqualification marker and never reuses the predecessor's terminal
  evidence as success. Once the successor binding is installed, the hook
  permits only the exact root controller control-plane transition valid for
  the current lifecycle state, while ordinary mutation still requires the
  controller's exact action hash. The shell read exception accepts only one
  literal command and enumerated non-writing options. Unknown options,
  substitution, composition, redirection, caller-selected execution machinery
  and path-qualified executables remain guarded. Git branch/tag creation and
  deletion, mutating find actions, sed programs, sort output and uniq's output operand
  require authority; the bounded sed line-print form remains a read. Git diff
  and show reads also require `--no-ext-diff --no-textconv`. This qualification
  exception does not change the watcher's admitted project coding authority.
  The read grammar is deliberately smaller than the former executable-name
  allowlist: `cut`, `jq`, `md5`, `test` and `tr` now require an exact grant,
  as do unenumerated options and glob patterns, even when quoted. Supported
  reads include `pwd`, `ls -la`, `rg -n`, Git status and explicit branch/tag
  listing, bounded `head`/`tail` counts, `wc -l`, and sed's bounded line print.
  Git recognizes `--list` before or after a listing pattern; after `--` it is
  an operand and cannot establish the read exception.
  Successful `PreToolUse` output is an
  implicit allow with no `permissionDecision`; explicit `deny` plus a reason
  remains the fail-closed encoding accepted by current Codex.
  The lifecycle driver accepts `--plugin-root`, `--plugin-data`, `--cwd`,
  `--new-task-id`, and `--model`; `--pre-turn-report` selects the activated
  startup-plus-first-action path, while omission preserves terminal-predecessor replay. It
  has no `--case` or `--output` transport. In the fresh installed task, run the primary artifact rehearsal
  driver directly from the sole
  installed root with `--case`, `--plugin-root`, `--opencodex-root`, and
  `--evidence-root` before the live boundary. Also provide one absolute,
  nonexistent private `--output` path. The final driver stage builds and seals
  the complete `live-test-preflight/report/v1`, writes the whole rehearsal
  create-only at mode `0600`, reads it back through the installed public
  rehearsal, approval, route-request, activation, and structural validators,
  and prints only a compact sealed artifact receipt. Require every named
  validation to be `PASS`, stdout to remain below 4,096 bytes, and the receipt
  to bind the artifact path, byte digest, report digest, exact downstream
  digests, zero counters, and stopped boundary. This receipt is the secondary
  validation; do not pipe, encode, store, or revalidate the report through a
  PTY or JavaScript wrapper. Load the whole artifact only through
  `read_qualification_artifact(path)` and pass its typed reports to canonical
  consumers unchanged. Never translate generic validation fields or
  reconstruct TaskSpecs, candidates, logical plans, requests, preflight
  reports, or prepared activation payloads in agent code. The artifact also
  carries one sealed `qualification-route-canary-program/v1`; its route
  request is the same complete request object and its dispatch flag remains
  false throughout rehearsal.

  Before crossing the canary boundary, pass that whole artifact to the
  installed `orch_dork_qualification_governed_inputs.py` with the canonical
  source root and a new absolute private `--output` path. The driver derives
  research claims only from the frozen TaskSpec read scopes, derives project
  and generation identity from the complete activation payload plus canonical
  project binding, binds every named lane to its unique real acceptance
  criterion through the production closure binder, and revalidates the full
  logical plan. Require its compact
  `qualification-governed-inputs-receipt/v1` to bind one create-only mode-0600
  report, logical-plan, closure, and research-manifest digests with all
  provider/model/controller/capacity/grant/native/worker counters zero. Pass
  that complete typed inputs artifact to the governed pre-spawn consumer;
  never import a test fixture or rebuild either contained report in agent code.

  At the separately authorized live boundary, invoke only the installed
  `orch_dork_qualification_route_canary.py` with the qualification artifact,
  exact OpenCodex and evidence roots, two new create-only output paths, and the
  exact approval-report digest. The consumer executes the bundled OpenCodex
  `ready --json` command once, accepts exactly `ready`, `status`, `pid`, and
  `port`, derives the literal loopback Responses endpoint internally, creates
  an unpersisted process-local admission value, and passes the artifact's
  whole route request and constructor-owned authority binding to
  `invoke_route_preflight_loopback_once`. It rejects extra readiness fields,
  stderr, a non-ready result, mixed runtime metadata, a changed approval or
  program, existing output paths, and any endpoint or admission value in
  evidence. The full sanitized invocation report is persisted create-only at
  mode `0600`; stdout is only its compact receipt. Load it through
  `read_route_canary_artifact(path)` and pass the typed candidate and complete
  runtime observation onward unchanged. Then invoke the installed
  `orch_dork_qualification_bootstrap.py` once with the complete qualification,
  governed-input, and canary artifacts, the canonical source root, exact root
  task id, canonical external `--enrollment-registry-root`, stable controller
  id, and distinct new pre-spawn, activation, and bootstrap output paths.
  Create the evidence directory as a
  caller-owned mode-0700 directory first (for example with `mktemp -d` under a
  private umask, or `install -d -m 0700`); the driver rejects group/other
  access and writes each component create-only at mode 0600. Here
  `--source-root` binds project/research ground. Execution readiness always
  observes the running driver's own package root, so a runtime-projected CLI
  qualifies the projection rather than silently importing the development
  checkout. The driver derives run/attempt
  identity, obtains ticket-admission v2 and every subordinate stage schema from
  production constructors, reads the exact manifest-keyed active enrollment
  record, constructs the whole read-only enrollment inspection program, and
  requires the real evaluator's sealed `PASS`/`ACTIVE` report. It passes that
  program unchanged into activation preparation and evaluates all twelve
  governed pre-spawn stages. Without yielding to caller code, it re-observes
  the exact task-owning app-server argv, requires one real
  `--dangerously-bypass-hook-trust` flag before `app-server`, reads the fixed
  host observer authority, and create-only persists one host-signed,
  content-addressed hook-trust receipt. The sealed activation handoff retains the
  exact resolved `source` and `evidence` root map. The driver then passes its
  repository-built activation program through the canonical governed native
  controller, builds the first stage only through
  `build_governed_native_stage_program`, and immediately revalidates the whole
  pre-spawn program against those roots while its evidence is fresh.

  Require `ACTIVATED_READ_ONLY`, then `STAGE_ADVANCED` with
  `next_stage_action: capacity_admission`, no published action, and compact
  `READY_FOR_CAPACITY_ADMISSION`. Load the complete result only through
  `read_issue94_controller_bootstrap_artifact`; pass its whole pre-spawn report
  to `build_capacity_admission_program` without selecting, renaming, hashing,
  or resealing fields. The bootstrap owns one controller activation and one
  provider-free stage, but performs zero capacity reservations, grants,
  network/model/native actions, or worker calls. Never read
  `runtime-port.json`, hand-build an endpoint, pass the binding manifest as an
  enrollment program, copy binding fields, or expose a process-local admission
  value in agent code. Do not fall back to the legacy separate pre-spawn and
  activation commands: that reintroduces the exact root-omission and freshness
  race preserved by the Cycle 20 replay. Any bootstrap refusal is terminal for
  the generation, never permission to reissue or retry. The projected
  qualification rehearsal runs this installed bootstrap against fixture host
  authority and a real fixture controller, reaches capacity-admission
  readiness in seconds, and stops before the live capacity/model/native
  boundary.

  The enrollment registry follows the project-ground maintenance contract,
  not the evidence-directory contract: its owner-controlled directories may
  inherit mode `0775` from `apply_project_enrollment`, but they must be owned by
  the current uid and never world-writable. The manifest must not be
  group-writable and the selected record must be owner-only. Both are opened
  with no-follow descriptor checks before parsing, so callers must not copy or
  loosen either file for qualification.
- **Pre-authorization transport qualification — synthetic installed-runtime gate.**
  Before generating any new active authority scope, build the deterministic
  representative zero-tool request and call
  `qualify_zero_tool_transport(request, runtime_closure)` with the exact
  installed plugin and OpenCodex roots. The contained process must use the
  bundled interpreter and shipped probe, the scrubbed environment, and the
  exact parser/adapter/bridge sources. It runs fixed content-only and
  reasoning-rich fixtures through the strict observer and checks the schema
  vocabulary without a loopback POST, credential, network, model, or hosted
  call. Retain only its sealed path-free report. Any FAIL, process uncertainty,
  changed source-tree digest, changed report, or missing runtime root stops
  before packet, scope, decision-sheet, bundle, grant, registration, or
  reservation work. This catches deterministic transport incompatibility; it
  is not a provider-availability or model-quality canary.
- **Failure-aware N=2 recovery packet — provider-free prerequisite.** Before
  registering a successor to a failed live tranche, call
  `derive_issue111_v8_evidence` over the immutable host-local experiment root.
  It reopens the shipped, sealed v4-v7 file and record manifest, validates each
  campaign and shard chain plus the v7 failure artifact, verifies shard
  source-path bindings, and refuses any missing, changed, contradictory, or
  unknown-required evidence. The terminal v4 join proves its third reservation
  had no model call, so that slot is recorded as reserved-but-unstarted and is
  not counted as a lane session. Unsettled v6 usage stays explicitly
  `UNKNOWN`; it is never reconstructed from prose. The estimator includes scored
  zero-tool responses and the v7 22,372-token compliant companion, while the
  45,815-token tool-call continuation remains transport-failure evidence and
  is excluded from normal-lane sizing.

  Derive the transport identity with
  `derive_structural_transport_identity` from the exact current plugin
  manifest and `orch_dork_live_zero_tool.py` bytes. The old
  `build_v8_recovery_packet` v1 result remains deterministic replay evidence
  only. For a new proposal, first call `derive_terminal_predecessor_capsule`
  on the exact immediate closed tranche root. The derivation recognizes the
  immutable r4 terminal family separately from the earlier replay-compatible
  family, validates the exact source schema, and retains the source seals rather
  than rewriting history. Then call
  `build_v8_successor_packet` with that `terminal_predecessor_root` for packet-v2
  replay. `validate_v8_successor_packet` must re-read the same root; never
  accept the path-free capsule from its self-seal alone. For a new proposal,
  call `build_v8_qualified_successor_packet` with that root plus the exact
  current `opencodex_root` and `plugin_root`; only a fresh matching
  qualification PASS may emit packet v3. Packet v3 is fixed to one
  evidence-extraction/high/acceptance-unit N=2 cell at seed 11101, one cell in
  flight, two live lane sessions, 27,000 total and 4,096 output tokens per
  lane, 54,000 aggregate tokens, 65,536 response bytes, 120,000 ms per lane,
  and a 600,000 ms campaign backstop. Preparation, review, retry, fallback,
  replacement, and hosted-call counts are all zero. Persist the historical
  manifest, sanitized terminal-predecessor capsule, packet, authority audit sheet, and
  self-sealed receipt only through `write_v8_recovery_bundle`, passing all
  three roots; it creates a new owner-only directory and refuses overwrite.

  A valid packet has `authorized: false` and grants no registration or
  model-call authority. Its audit sheet exposes the closed standing-policy
  digest, exact packet digest, and stable `v8_authority_scope_sha256`; the
  packet is provenance and the scope is the standing-authority target. Call
  `grant_from_v8_packet` without authority hashes; it derives the Owner-source
  digest from the policy digest, qualified-recovery class, and exact scope. It
  still requires `terminal_predecessor_root`,
  `opencodex_root`, and `plugin_root`, and refuses unless the target packet
  validates against the current runtime, freshly matching transport
  qualification, re-derived immediate terminal capsule, and exact scope.
  Legacy v1 and successor v2 packets cannot create an active scope, decision
  sheet, grant, or bundle. The same standing binding may therefore accompany
  metadata-only packet regeneration only when the scope remains identical,
  never a changed campaign, limit, transport runtime closure, historical or
  immediate predecessor evidence, or terminal rule. Explicit malformed or
  mismatched recovery authority never falls back to standing authority. The
  additive v5 grant carries its policy/class/scope binding. Pass the packet and
  all three runtime roots in `standing_authority_context` at registration; the
  boundary reruns `grant_from_v8_packet`, requires the exact campaign/grant,
  then consumes one create-only claim in fixed owner-local state. The same
  source cannot register in another process or ledger, including under a
  regenerated campaign label.
  PASS requires two strict
  single-response, zero-tool lanes and ordinary governed settlement. Any route,
  tool, continuation, schema, usage, source, authority, transport, or
  settlement mismatch drains and terminally stops without retry, repair, or
  replacement. PASS and failure both consume the decision scope and authorize
  nothing further; derive a fresh successor decision from the sealed terminal
  evidence.
- **Record/replay — downstream experiment adapter.** Register one sealed
  replay plan before the first model call, then invoke `record_model_call` at
  that exact boundary so full bounded request/response JSON stays ledger-local
  under canonical hashes. `replay_campaign` accepts no model callback and
  refuses a missing cell rather than dispatching. Record live holdout scores
  only with exact governed receipt hashes and lineage-disjoint evidence;
  `record_live_holdout` computes demotion from the ledger and the plan's sealed
  tolerance. Reports contain hashes, typed metadata, and rational scores, never
  request or response content. Neither replay nor holdout grants default,
  execution, retry, fallback, or completion authority.
- **DBOS — PILOT later beneath Orch Dork.** Use it only as a durability and
  queue adapter. Orch Dork retains topology, retry, cancellation, budget, and
  termination authority. SQLite is acceptable only for a prototype or
  single-process run; require Postgres before real concurrent or distributed
  use. Model and tool I/O must be idempotent DBOS steps.
- **PydanticAI — PILOT later at the model-call/executor boundary.** Canonical
  standard-library contract validators remain authoritative. Disable provider
  and PydanticAI retries whenever the controller or DBOS owns retries, and
  canary Qwen structured-output behavior before activation.
- **OpenHands SDK/Agent Server — PILOT later as a coding `WorkerPort`
  backend.** Run it only in an Orch-Dork-created pinned worktree or container.
  It may not own planning, graph state, worktree lifecycle, budgets, or
  completion. Require loopback binding or authenticated access plus explicit
  secret and network hardening.
- **LiteLLM — DEFER as an external gateway.** It duplicates retry, fallback,
  and budget authority, and official project reporting identified a 2026 PyPI
  compromise in 1.82.7 and 1.82.8. If revisited, isolate it, pin and attest
  exact hashes, disable governed-call retry/fallback, and reconcile usage back
  to Orch Dork.
- **CAID — REFERENCE/BLACK-BOX TEST only.** It is a small benchmark research
  implementation, lacks root LICENSE text despite package metadata, and
  overlaps Orch Dork. Do not fork or copy it.
- **AOrchestra — ADOPT CONCEPT only.** Map
  `<Instruction, Context, Tools, Model>` into `TaskSpecV2`; the `allowed_tools`
  field makes Tools explicit. Do not depend on its benchmark-heavy runtime.
- **MOC — DEFER the algorithm.** It lacks a root LICENSE and brings a
  heavyweight experiment harness. Implement a native trace-driven, bounded
  two-hop evidence selector later only if measurements justify it.
- **Workspace custody — ADOPT, one module.** The workspace-custody module
  owns the frozen `WorkspaceSandboxPolicy` (schema
  `orch-dork/workspace-sandbox-policy/v1`: non-empty NUL-free `attempt_id`
  and `lane_id`; an existing `workspace` directory serving as the
  disposable-namespace root; up to `MAX_WRITABLE_ROOTS` (6) `writable_roots`
  each contained in the workspace with no root nested in another;
  existing `scratch_dir` and `tmp_dir` outside the policy scope; a
  `network_granted` bool defaulting false (launches isolate the network);
  a `command` absolute argv array capped at `MAX_ARGV_ELEMENTS` (64)
  elements, `MAX_ARGV_BYTES` (65536) total, and `MAX_ARG_BYTES` (8192) per
  argument, or `None`; `WorkspaceLimits` with `wall_seconds`,
  `cpu_seconds`, `max_address_space_bytes`, `stdout_bytes`, and
  `stderr_bytes`, each capped by a fixed v1 ceiling: `MAX_WALL_SECONDS`
  10.0, `MAX_CPU_SECONDS` 30.0, `MAX_ADDRESS_SPACE_BYTES` 2 GiB,
  `MAX_OUTPUT_BYTES` 4 MiB per stream, with defaults `cpu_seconds` 5.0,
  `max_address_space_bytes` 1 GiB, and `stdout_bytes`/`stderr_bytes` 1 MiB;
  there is no v1 `descendants` limit and widening any field is rejected
  with the stable reason `LIMIT_WIDENING`). `launch()` is
  policy-first: `launch(policy, *, plan=None, dry_run=False, executor=None)`
  revalidates the policy fresh, re-probes bwrap, and deterministically
  rebuilds the expected plan, rejecting any caller-supplied plan that
  mismatches byte-for-byte with the stable reason `PLAN_FORGED` before
  dry-run or execution; an executor whose `attested_limits` keys are not
  exactly `LIMIT_CONTRACT_FIELDS` is refused with the stable reason
  `ENFORCEMENT_UNAVAILABLE`. It owns both the bwrap launch (scratch and
  tmp tmpfs mounts
  sized `SCRATCH_TMPFS_BYTES` = 64 MiB and `TMP_TMPFS_BYTES` = 16 MiB) and
  the disposable SQLite snapshot adapter because launch enforcement and
  evidence capture are two sides of one custody boundary: one reason
  registry, one normalized-scope check, and one fail-closed precondition
  chain govern both, so a custody decision and its evidence capture can
  never drift apart.
- **OpenTelemetry — later one-way exporter.** Export from the canonical
  append-only Orch Dork event/receipt ledger. Imported telemetry never becomes
  the source of truth or grants authority.

## V3 run-state telemetry and integration

Issue 95 (frozen plan f8b99dc3, ticket
`orch-dork-v3-durable-integration`) lands the v3 durable-integration
surface. The canonical v3 run state is one closed, append-only event stream
per run: `lane.started`, `lane.completed`, `integrator.started`,
`integrator.completed`, `run.terminal`, with strictly increasing integer
`seq` and optional non-regressing integer `ts` seconds, ending in
exactly one `run.terminal`. The canonical `RunEngine` stream is the sole
authority for run state; this lane event stream is the explicitly
non-authoritative lifecycle compatibility projection of it, and everything
downstream is a one-way projection.

### Emission: projections are outbound only

Projections never update run state and never feed the canonical stream.
Dogfood summaries and OTel-shaped export records are stamped
`authority: projection` and `run_state_authoritative: false`, and carry
a `source_sha256` binding each to the exact canonical input it was derived
from, so re-projection is byte-identical and mapping or event order cannot
change the digest. When a canonical lifecycle projection wrapper is the
input, `source_sha256` is the carried kernel stream digest, not a digest
of the lane mapping. The OTel run span start uses only the first event
timestamp; when the first event carries none, the span start is 0 with the
`orch-dork.time.origin: absent` marker even if later events carry
timestamps. Emit both only from a valid `ingest_lane_events` state;
neither surface is required for a lane to be valid in the first place.

### Re-entry: imported evidence is the only form

A projection may re-enter a LaneResult only as an imported evidence entry via
`imported_evidence_entry`. Entries are stamped `origin: imported` and
`authority: imported` with the bounding projection's digest and a bounded
provenance pointer. The closed pairing rule rejects `origin: imported`
with `authority: canonical`, and a LaneResult supported only by imported
or derived evidence cannot reach `status: complete`; imported telemetry is
never authoritative run state, so imported entries can witness a projection
but never terminate a run.

### RunEngine seam

The released run kernel (`orch_dork_run_engine`) is the sole authority for
run state: its per-run, hash-chained event stream (kinds `started`,
`applied`, `completed`, `terminated`; integer seq from 1; `prev_hash` and
`event_hash` per row) is verified by the public `verify_event_chain`
and digested by the public `stream_digest` (the state `stream_sha256`
reduced over the verified rows). The verifier is two-phase: it
validates row fields first (strict-integer seq, a kind within the
closed set, 64-hex prev and event hashes, no duplicate seq), then
normalizes by sorting on seq before enforcing the protocol (seq 1
is the single `started` row, seqs contiguous, `applied` only while
open, exactly one terminal of `completed` or `terminated`, nothing
after it) before expressing the terminal run result
over `RUN_RESULT_DIMENSIONS` (execution, deliverable, conformance,
evidence), a run-result dimension set that is distinct from the release
adjudication axes and never conflated with them.

The compatibility lane event stream is non-authoritative: it reduces only
through `ingest_lane_events`, the explicitly non-authoritative lifecycle
compatibility reducer, whose state `stream_sha256` is a digest of the lane
mapping and carries no run-state authority. The one canonical bridge is
`canonical_lifecycle_projection`: it accepts only real, kernel-verified
`RunEngine` events, validates the chain through `verify_event_chain`, and
emits the `orch-dork/canonical-lifecycle-projection/v1` wrapper (authority
`projection`, run_state_authoritative `false`, `source_sha256` the kernel
stream digest of the verified rows, with a nested lane-events stream).
Dogfood and OTel projections consume the wrapper (or the legacy lane
stream) and preserve its `source_sha256`. A cross-contract test feeds real
`RunEngine` events through the bridge and asserts the wrapper markers and
kernel stream-digest equality.

### Governance gates and the release-integration boundary

Lanes that take writes or release work must be governed by the closed
`orch-dork/governance-profile/v1` records: scan for read-only inspection,
mutation for scoped writes under exact writable custody, and release for
final delivery under complete canonical evidence plus one independent
four-axis adjudication (`outcome`, `evidence`, `custody`,
`verification`). Release integration (root-owned) happens on a clean cut
after the kernel release: the sealed release receipt is replayed from
`stream_sha256` against the profiles, and only then may merged or released
status be claimed. Until that cut lands, telemetry and projections remain
advisory surfaces and the profiles' structured fields are the only basis for
a governed claim.

## Read custody, lane workspaces, and exceptions

Issue 96 closes the gap between the plan model's promise of resource
isolation and shared-checkout execution. Three mechanisms compose, in
increasing strength; a coordinator uses every mechanism the run's mode
requires and records which were active.

### Worker preamble and interface freeze (process layer)

Every lane brief opens with `orch-dork/worker-preamble/v2`. Its canonical
topology names `base_checkout` and `lane_workspace`, the exact branch and brief
path, protected resources, applicable instruction files, a positive bounded
`context_budget_tokens`, and a calibrated first-patch deadline. When the two
checkout paths differ, the preamble makes the base checkout read-only and
confines writes to the lane workspace. When they are equal, it truthfully says
path isolation is advisory; it never tells a worker that the shared checkout is
untouchable. The brief also freezes the `apply_patch` pathway, stop/report
deadline behavior, post-compaction reread, and no-nesting/no-widening clauses.

Instruction discovery is exact. Repeated `--agents-file` arguments list the
inherited `AGENTS.md` chain; without them, the renderer discovers existing,
non-symlink `AGENTS.md` files from the base checkout through its ancestors and
orders them root-to-leaf. A missing file, symlink, duplicate, sibling file, or
other non-inherited instruction path fails closed. The worker reads every
listed file in order before any other repository action.

`brief_shape_sha256` binds the topology, branch, brief path, protected
resources, instruction chain, and context budget. A closed
`orch-dork/brief-deadline-calibration/v1` payload is carried inside a
host-signed `orch-dork/signed-observer-receipt/v1`; it binds that digest and
exactly
these calibration fields: `mode`, `observed_startup_seconds`,
`bootstrap_allowance_seconds`, `fixed_margin_seconds`, `deadline_seconds`,
`calibrated_at`, `source_pointer`, and `receipt_sha256`. In `observed` mode,
the bootstrap value is null and the deadline is observed startup plus margin.
In `bootstrap` mode, observed startup is null and the deadline is the explicit
bootstrap allowance plus margin. Bootstrap is honest first-shape allowance,
never an observed measurement. An unbound shape, an
unsigned/self-hashed receipt, an unavailable host trust store or replay
registry, invalid arithmetic, or a changed calibration aborts before spawn.

Generate the byte-zero preamble and lint the completed on-disk brief with the
same arguments. The host process must set `ORCH_DORK_OBSERVER_TRUST_STORE` to
the canonical pinned public-key store and `ORCH_DORK_OBSERVER_REPLAY_DB` to a
host-owned durable nonce database; neither path belongs in the receipt:

```bash
python3 scripts/orch_dork_brief_lint.py render \
  --base-checkout /abs/repo --branch lane-a \
  --lane-workspace /abs/worktree --brief-path /abs/worktree/.orch-dork-brief.md \
  --agents-file /abs/AGENTS.md --agents-file /abs/repo/AGENTS.md \
  --protected-resource /abs/repo/protected \
  --context-budget-tokens 16000 --calibration-receipt /abs/calibration.json
python3 scripts/orch_dork_brief_lint.py lint \
  --base-checkout /abs/repo --branch lane-a \
  --lane-workspace /abs/worktree --brief-path /abs/worktree/.orch-dork-brief.md \
  --agents-file /abs/AGENTS.md --agents-file /abs/repo/AGENTS.md \
  --protected-resource /abs/repo/protected \
  --context-budget-tokens 16000 --calibration-receipt /abs/calibration.json
```

The digest-bound `orch-dork/worker-brief-lint/v2` report must be `PASS`. A
missing, duplicate, changed, escaped, NUL-containing, non-UTF-8, or oversized
brief aborts before task creation. While the deadline runs, the coordinator
monitors only terminal state and the owned-file patch name, not partial output
or intent. Expiry without an owned-file patch aborts in place with no nudge,
retry, replacement, or reuse; a successor needs a fresh attempt.

For scan-shaped work, each worker leaves its full report as a content-addressed
artifact and returns a typed handoff no larger than 1,200 estimated tokens. The
handoff carries claim IDs, evidence pointers, unknowns, conflicts, and artifact
references. The deterministic semantic join deduplicates identical claims but
preserves disagreement and evidence quality; it never majority-votes. Reveal a
full artifact only for conflict resolution or final verification. A measured
three-lane local single-GPU baseline may seed scheduling, but is not universal
capacity evidence; the native capacity receipt remains authoritative.

Cross-lane needs must be frozen as interfaces, not discovered as reads: a
lane that needs a sibling's contract gets an exact interface stanza in its
frozen brief (symbol names, signatures, schema fields, reason codes). If an
interface cannot be pinned at freeze time, the lanes are merged or
sequenced; a plan whose lane would need to inspect sibling internals
mid-run is misdecomposed and fails the planning gate.

### Lane workspace materialization (mechanism layer)

`orch_dork_lane_workspace.LaneWorkspace` materializes one disposable git
worktree per lane (delegating pinning, containment, and cleanup receipts
to the worktree runner), removes every sibling-owned path named by the
frozen plan before the lane runs (`lane-workspace-manifest/v1`, masks
recorded with pre-removal digests), and makes release a filesystem event:
the coordinator copies exact released files into the workspace and holds
the hash-bound `lane-release-receipt/v1`. A masked read is impossible
rather than forbidden, and sibling uncommitted progress is invisible even
where a path is unmasked because the worktree is pinned to the base revision.

### Workspace launch binding (enforcement layer)

`orch_dork_workspace_launch` closes the execution gap between a materialized
worktree and the process that performs work. It consumes the live
`LaneWorkspace` object and expected manifest digest, not a caller-recreated
path claim.

- `NativeCollaborationAdapter.launch` owns the native task-creation seam and
  invokes its worker factory exactly once only for a read-only lane. The
  current native spawn schema has no cwd field or runtime cwd observation, so
  every write-capable request is refused as
  `NATIVE_CWD_BINDING_UNAVAILABLE` before the factory, with zero model calls
  and workers created. `authorize` is the pure decision half, not a substitute
  launch path. A creation exception is `NATIVE_CREATION_AMBIGUOUS`; do not
  retry or replace it without independent reconciliation.
- `ContainedProcessAdapter.plan` re-derives a
  `workspace-sandbox-policy/v1` from the active manifest. The exact disposable
  worktree is both the enforced `--chdir` target and the sole writable bind;
  `/` remains read-only and scratch/tmp remain isolated.
- `ContainedProcessAdapter.launch` rechecks the live manifest, base revision,
  real path, plan seal, sandbox policy digest, and complete argv immediately
  before execution. A stale workspace, forged plan, unavailable bubblewrap, or
  unenforced limits refuses before the worker command.

Read-only native analysis remains unbound and must still pass the mechanical
audit below. Prompt text is never accepted as a write-binding adapter. A future
native adapter may permit writes only after the spawn API and independent
session observation both expose and match the exact lane cwd.

### Mechanical read-custody audit (verification layer)

`orch_dork_read_custody` replaces forensic session-tailing with a
deterministic evaluator. `extract_accesses` performs conservative,
provider-free extraction from one bounded session JSONL file: patch
envelope targets become `write` accesses and known repo paths mentioned
in tool-call inputs become `read` accesses, each carrying a hash-bound
source pointer (line number plus SHA-256 of the raw line) so findings are
independently re-verifiable without copying private bodies.
`audit_read_custody` classifies every access against the frozen
`read-custody-map/v1` (lane ownership, shared read allowlist, ordered
releases): `owned`, `shared_allowlist`, or `released` pass; any
`out_of_custody_read` or `out_of_custody_write` fails the audit closed.
A release authorizes only the named receiving lane and only accesses at
or after the release order. Extraction is intentionally over-inclusive;
the shared allowlist is the pressure valve, and a disputed finding is
settled by its source pointer.

The audit is wired into qualification through the `qualify_read_custody`
policy evaluator (MCP tool of the same name): it recomputes the audit
report digest, validates any submitted custody-exception records, and
passes the read-custody axis only when every violation is covered by a
cured or superseded exception. Recorded exceptions, uncovered
violations, forged digests, and malformed reports refuse the axis, and a
PASS never permits a terminal qualification or completion claim by
itself.

### Custody-exception lifecycle

A violation no longer poisons an attempt forever.
`validate_custody_exception` (`custody-exception/v1`) gives each
exception one of three dispositions: `recorded` (acknowledged; the trace
stays non-qualifying), `cured` (every tainted artifact rebuilt from
released state by an actor distinct from the violating lane, with rebuilt
paths covering the exception and a verification pointer), or
`superseded` (a later commit independently rewrote and re-verified every
tainted surface; requires the 40-hex superseding commit, the re-verifier,
and a verification pointer). Cured and superseded exceptions stop blocking
qualification; the records themselves are never deleted.

Persist those records in the host-local ledger through
`orch_dork_custody_exception_ledger.py <ledger> --host <host> --append
'<custody-exception-json>'`. The ledger is canonical JSONL under
`orch-dork/custody-exception-ledger-record/v1`: one host, contiguous sequence,
prior-record digest, normalized exception, and record digest. Every append
locks and validates the full existing chain before writing. Malformed schema,
host drift, chain or digest drift, reordering, and partial truncation fail
closed without an append. The same command without `--append` emits the
digest-bound `orch-dork/custody-exception-ledger-summary/v1`; the ledger stays
host-local like the dogfood corpus and is never packaged as run evidence.
