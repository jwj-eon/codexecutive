# Orch Dork observability contract

This is the public evidence boundary for Orch Dork. A displayed fact says how
it was obtained and how strongly it is bound. It never presents actions,
messages, tool calls, or decisions as private chain-of-thought.

## Contents

- [Evidence classes](#evidence-classes)
- [Permanent privacy boundary](#permanent-privacy-boundary)
- [Release boundary](#release-boundary)
- [Advisory completion display](#advisory-completion-display)
- [Replayable scenario gallery](#replayable-scenario-gallery)

## Evidence classes

| Class | What it means | What it cannot establish by itself |
| --- | --- | --- |
| `runtime` | A bounded runtime adapter observed a task, lifecycle event, route, action, mutation, check, timing value, or usage value. | Semantic correctness, authority, or a sealed terminal claim. |
| `ui` | A human-visible app surface was inspected, such as the Subagents panel. | Runtime custody or governed success. UI and runtime evidence remain separate. |
| `submitted` | A caller or active task declared a plan, event, result, or trace. | Independent terminality or governed success. |
| `inferred` | A deterministic projection derived a fact from named inputs, such as first-finisher selection. | Direct observation. The derivation and sources must remain visible. |
| `sealed` | A manifest or receipt cryptographically binds exact content and its source hashes. | Truth outside the sealed sources or authority not contained in them. |
| `unknown` | Required evidence is missing, ambiguous, unavailable, or not attributable. | Success. Unknown is a first-class displayed result, never zero or pass. |
| `contradictory` | Two or more sources disagree, or a bound source hash does not match. | Any success claim. Contradiction is a failure, not an unknown. |

Every staged governed-attempt report exposes the exact Orch Dork manifest
version and contract, frozen graph/revision and native lane membership, root
and worker model/effort routing, latest independently observed Sol/total token
ingress and tool count, verification and claim-ledger digests, observer/trace
identities, and one explicit final verdict. A missing receipt leaves those
summaries null or empty; it never manufactures a graph, zero usage, successful
verification, or final verdict.

Evidence class and evidence tier answer different questions. The class says how
the displayed fact was obtained. The tier says how far source binding has
progressed:

- `submitted` is caller-supplied and unobserved;
- `runtime-observed` is independently reconstructed from bounded runtime or UI
  sources; and
- `sealed-runtime` binds the exact observed material into a verified receipt.

The raw evidence bundle is authoritative when a UI projection, summary, or
registry row disagrees with it. Registry and UI views are rebuildable
projections, not new evidence stores.

## Permanent privacy boundary

Orch Dork may expose sanitized assignments, task identities, parent edges,
messages at the permitted evidence boundary, tool actions and arguments,
patches, tests, statuses, timing, usage, releases, and source pointers. It does
not expose or reconstruct private chain-of-thought, hidden reasoning, session
bodies, credentials, secrets, or raw authorization material. An action or
decision trace is evidence of what happened, not why a model privately thought
it should happen.

## Release boundary

Ordinary skill and policy-tool use is `advisory`. A submitted trace `PASS`
means only that the submitted structure conforms to its frozen plan. It keeps
`qualified: false`, `claim_permitted: false`, and requires later independent
terminal observation.

Route evidence is displayed by subject. `root_route_evidence_tier` and
`root_route_verified` describe only the root; `worker_route_evidence_tier` and
`worker_route_verified` describe spawned sessions. A current-turn root
observation cannot verify worker routing. Submitted v1/v2 wave reports remain
unverified; only complete independent v3 runtime observations may verify them.

Capacity evidence is displayed separately as `capacity_authoritative`,
`capacity_claim_permitted`, `capacity_scope`, and `capacity_evidence_tier`.
Caller-submitted v1 inventory is advisory even when structurally valid. A
closed independent native observation may be authoritative only when its exact
payload verifies inside `orch-dork/signed-observer-receipt/v1` against a
host-owned Ed25519 trust store and replay registry. Bare self-hashed
observations remain advisory. Authoritative reports expose the signed receipt,
key, and trust-generation bindings; advisory capacity can guide
parent-authorized scheduling but cannot support a governed-success claim.

Submitted custody has the same boundary: event conformance does not establish
coverage, so it displays `coverage: unknown`, `custody_preserved: null`, and
`claim_permitted: false`. Complete custody requires a matching independent
host-signed observer receipt. The compatibility SHA-256 seal is checked inside
the signed payload but cannot authenticate its own author; omitted or forged
access evidence cannot be upgraded by a caller label or caller-supplied key.

The same signed-envelope boundary protects brief deadline calibration. Missing
host trust or replay state is displayed as unavailable evidence, not converted
to a bootstrap or inferred timestamp. Because calibration controls a live
deadline, verification uses the current host time and expired receipts fail;
post-terminal custody is durable historical evidence and verifies the signed
issuance instant instead. The shared `orch_dork_evidence_core`
keeps canonical bytes, seals, timestamps, freshness, and authority projections
identical across these views.

The packaged `orch_dork_observer_authority.py` provisioner creates that trust
boundary outside the replaceable plugin cache. Its create-once state contains
one private seed, the matching public trust generation, and one durable replay
database under owner-only permissions. Provisioning and launcher discovery
emit identity metadata only. The seed is never included in an MCP request,
receipt, report, trace, environment variable, or installed package; explicit
rotation preserves the prior generation for historical audit.

`governed` success exists only when the provider-free external controller owns
the post-terminal decision and verifies all required facts: exact bound hosted
identity, terminal lifecycle, frozen plan and graph, routing, custody,
releases, verification, known compatible typed timing, exact attributable
usage, zero forbidden retry/fallback/replacement/nesting, and a separate
submitted conformance `PASS`. Missing required evidence blocks success as
`UNKNOWN`; contradictory evidence is `FAILURE`. Cancellation, timeout, budget
exhaustion, and blocked extra work remain their actual durable outcomes.

For substantive delegated logical waves, routing evidence includes exact
lane/role/native-worker/session set equality from wave-routing v3, plus one
independently observed typed-output preflight per spawned model profile. The
session-runtime receipt binds exact rollout bytes, no-history route, terminal
JSON digest, and exact-or-unknown native token ingress. Terminal evidence
includes the exact TaskSpec digest, contiguous unique compact progress packet
digests, pre-exhaustion completion-reserve decision, typed handoff digest, and
observed-versus-declared terminal budget decision.
A submitted route label, free-form worker answer, or unknown usage cannot fill
any of those fields.

For a structural zero-tool measurement lane, absence of tools is established
jointly by the re-derived request (`tools: []`, `tool_choice: none`) and the
single accepted terminal shape (one completed assistant output-text item, with
at most one preceding opaque hidden-reasoning envelope, and no tool-call item).
Prompt text alone is never displayed as enforcement. The
public live-zero-tool receipt and projected runtime observation expose the
request/response/terminal/source hashes, exact route and usage, zero tool
counts, and no-continuation fact. The assignment, rendered prompt, raw
response, loopback endpoint, credential, and private reasoning remain outside
that boundary. An invalid response may remain in its owner-only create-once
evidence file, but no public report copies its body or turns it into a scored
result.

Before an authorization-ready recovery packet exists, the provider-free transport
qualification report displays its PASS/FAIL disposition, stable issue codes,
request and runtime-identity digests, schema-profile result, contained-process
cleanup state, and the status/output-type summary for fixed content-only and
reasoning-rich cases. It displays aggregate hashes for the installed OpenCodex
source closure and exact Orch Dork probe closure, never absolute paths, source
text, request or response bodies, prompts, environment values, credentials, or
reasoning content. Its zero credential/network/model/hosted counters describe
the synthetic gate only. A FAIL suppresses the authority-scope and audit-sheet
display; it is not a live invocation or evidence about provider availability.

A failure-aware successor manifest exposes only immutable campaign, shard,
record, request, reservation, completion, and failure-artifact digests plus
derived counts and distributions. It never publishes source paths or response
bodies. Its lane populations are separate rows: scored, malformed,
evidence-failed slots, transport-failed sessions, compliant single responses,
terminal-ledger-proven unstarted reservations, and the lane-count-matched
estimator. The compliant aggregate explicitly spans all observed lane counts;
the estimator names its exact matching N. Unsettled usage is displayed as
`UNKNOWN`; the v7 compliant companion remains measurement evidence, while its
tool-call continuation is displayed as excluded transport-failure evidence.

The v8 packet-v3 and create-only bundle receipt additionally expose the exact
zero-tool module, runtime-closure, plugin-version identity, transport-
qualification digest, fixed resource limits, terminal rule, predecessor and
manifest digests, packet digest, authority-scope digest, and
`STANDING_AUTHORITY_READY`. They always report `authorized: false`, zero model
and hosted calls, and no host path. A later authority binding names only the
closed standing-policy, exact current packet, stable authority scope, transport
qualification, standing Owner-source, campaign, and grant digests. The source
digest binds policy, class, and scope; the packet digest is provenance, not the
authority target. A standing v5 registration additionally reports the sanitized
atomic-claim digest but no host path; missing/failed class revalidation,
duplicate claim, or unavailable claim state refuses before ledger append.
Packet v1/v2 projections are labeled replay-only
and do not display a new authority scope. Neither the decision packet nor its
rendered sheet is execution evidence, and a PASS/failure result cannot be
projected as authority for another cell.

Issue 149 topology and Champion/Challenger inspections are submitted inactive
evidence. The Control Tower displays the nested evaluator status, decision,
report digest, and one sealed optimization-inspection digest. The topology
view displays the registry and enumeration identities, declared and feasible
candidate counts, stable prune-reason counts, deterministic process mode,
budget-matched direct baseline, separate objective rows, Pareto candidate
digests, evidence completeness, and the inactive future-Qwen selection when
present. It does not display a synthetic quality score for a pruned candidate,
an opaque reward, a raw candidate population, process completion order, model
prompt, credential, or private reasoning.

One-process and multi-process reports are comparable only when their complete
registry, evidence, baseline, ordered-stream, and archive digests agree. Equal output is
deterministic provider-free evidence; it is not evidence that Qwen executed or
that a topology is semantically superior on live work. CPU pool processes are
reported separately from Orch Dork workers. Resident-Qwen state remains an
unchanged operating constraint, never an inferred model call or unload event.

The promotion view displays exact Champion, Challenger, corpus, and per-result
digests; frozen, recent-failure, adversarial, and lineage-disjoint holdout
coverage; separate safety/privacy/authority/correctness/human-usefulness/cost/
latency metrics; ordered gate decisions; the last-known-good Champion; and
whether the Challenger was retained offline. A later gate visibly reads
`NOT_EVALUATED` after the first failure. The human-usefulness metric keeps its
human-review evidence digest; it is never presented as model confidence.

Both optimization views display `projection_only: true`, provider-free
execution, zero model calls, hosted calls, retries, fallbacks, and replacements,
and false append, mutation, production intent, dispatch, shadow, canary,
activation, release, installation, worker, and authority permissions. A nested
refusal remains `EVALUATOR_REJECTED`, not an unknown and not an invitation to
retry. No Issue 149 projection changes RunEngine state, production policy,
resident Qwen, or the evidence that selected it.

## Advisory completion display

The advisory scan report displays three independent rows of state:

| Field | Meaning |
| --- | --- |
| `execution_status` | Whether every declared lane drained or any lane failed. |
| `handoff_status` | Whether every required same-TaskSpec typed handoff and root verification is valid. |
| `qualification_status` | Whether this contract can issue a governed claim; advisory v1 and v2 are always `ADVISORY_ONLY`. |
| `native_observation` | In v2, the digest-bound observed native graph or one allow-listed typed unavailability. |

Therefore a completed read-only scan may truthfully show `DRAINED`, `COMPLETE`,
and `ADVISORY_ONLY` together. Unknown usage, packet, or custody evidence remains
listed beside the completed work and keeps `claim_permitted: false`; it does not
erase valid deliverables. Failed execution or an invalid handoff remains a
failure and cannot hide behind the advisory label.

The native scan observer is an evidence bridge, not an evaluator of semantic
quality. It reads only the explicit complete-file hashes and selectors in an
attempt manifest, then emits compact IDs, source and report digests, allow-listed
route facts, terminal schema/digest, exact-or-unknown usage, and stable issue
codes. It omits source paths and raw records from its report. Optional host
signing authenticates that compact digest but does not change the report into a
terminal qualification receipt.

Advisory-scan v2 makes that bridge mandatory at logical finalization. An
observed binding displays the attempt ID, completeness, observed lane IDs,
observation digest, and report digest after exact graph matching. A typed
unknown displays either `native_session_records_unavailable` or
`native_observer_unavailable` and its source pointer. It is not an inferred
zero, success, or permission to ignore the cause. Broken seals and available
but contradictory evidence display as finalization failures; recurring typed
unknowns should be investigated at the Codex evidence source.

This display does not move lifecycle authority. Codex owns physical worker
creation, waiting, interruption, and closure. Orch Dork owns the logical plan,
typed handoff policy, and the final observation binding.

Evidence-integrity views keep generation, execution, and use distinct. A
produced-evidence row displays its producer node/operation, subject digest,
kind, and exact execution receipt. Failure origin and candidate-quality value
are separate fields. Advisory views show both novel claim IDs and exact used
IDs, including zero use. Evidence Reveal shows the sealed manifest, selected
claim/artifact IDs, freshness decision, bytes released, and digest decision;
it never shows an expanded transcript by default.

Dogfood recovery uses a full-file digest only for a single-run immutable
session. A multi-run Codex task uses a v1.1 physical-line segment bound to the
exact ticket and frozen plan. Later appends are permitted; mutation,
truncation, wrong bounds, a wrong ticket, or a wrong plan fails replay. A spine
remains mechanical evidence only. If any aggregate or outcome analysis was
seen, a later human or model label must cite that analysis digest and remain
non-blind.

`BlindLabeler` is provenance-neutral. The model path deterministically projects
one bounded frozen-plan/effective-spine packet, excluding aggregate fields,
prior or peer labels, raw session bodies, prompts, private reasoning,
credentials, source paths, and worker/root model hints. A strict answer cites
packet-local evidence for every judgment and may return `unclear` or one
preserved abstention. The model identity, version when known, transport,
inference configuration, packet/rubric/answer hashes, invocation identity when
known, and fresh-context/exposure declarations are sealed as model provenance.
Unknown provenance stays unknown. There is no retry, fallback, partial repair,
or conversion into a human identity.

The optional `dogfood-model-request/v1` is a sealed formatting contract, not a
verdict. It exposes only the deterministic packet-specific instruction, strict
answer JSON Schema, context policy, and their digests. The strict transport
returns exactly one closed `answer` envelope whose nested supported `anyOf`
separates complete verdict and abstention objects; the semantic chain still
stores the normalized flat v1 answer. It contains no provider
or model hint. A transport-observed schema-conforming final message is still
submitted model output until the ordinary packet, answer, evidence-reference,
provenance, host, duplicate, and chain checks pass. A prose-wrapped response is
one refused invocation and remains visible as such; no extractor silently
turns it into accepted evidence.

Human records remain byte-intact in `dogfood-corpus.jsonl`; model verdicts use
the separate `dogfood-model-verdicts.jsonl` append-only chain. The combined
projection reads both exact host-local chains without concatenating them,
refuses duplicate runs or cross-host input, applies exact additive corrections,
and reports human/model, blind/non-blind, abstention, correction, and unresolved
strata. Only one effective accepted verdict per real run can count toward the
standing floor.

A known multi-turn v1.0 full-file spine is unresolved, not label-ready. It is
excluded from shortfall availability, and both worksheet rendering and verdict
writing refuse it until an exact v1.1 segment supersedes it. Supersession is an
additive `orch-dork/dogfood-run-spine-correction/v1` entry: it cites the exact
currently effective sequence, corpus-entry hash, and spine hash and embeds one
replayable replacement spine. The prior line remains byte-intact; stale,
forked, orphaned, cross-run, cross-host, or digest-invalid corrections fail
closed. Effective projections count one run and separately expose the number
of spine corrections. A correction carries no verdict and changes no blind
label.

Recovery displays frozen logical lanes separately from observed worker
attempts. `lane_count` follows the frozen plan when one exists;
`worker_attempt_count` and `extra_worker_attempt_count` retain replacements or
other extra starts instead of calling them new lanes. Unsafe or absolute
deliverable paths remain redacted, but declared and redacted counts stay
visible. Spawn-wave status and final submitted trace qualification are separate
facts: a passing original wave never becomes a qualified completion claim.

Spawn recovery recognizes both direct native tool records and bounded Codex
code-mode `custom_tool_call`/`custom_tool_call_output` pairs for the exact
`tools.multi_agent_v1__spawn_agent` call. It retains only lane keys and worker
IDs, deduplicates duplicate projections, and marks absent or mismatched evidence
`contradictory`; a declared passing wave can never silently become a zero-spawn
record. Gate summaries retain call, stage, status, and retry history. A retry is
a failed same-stage reattempt, not a normal pre-freeze/pre-spawn check or
capsule update. Every appended corpus or recovered-spine record requires an
explicit non-null `host`.

Quorum views count stable independence groups and retain exact worker/session/
route membership. Serving-epoch views mark cross-epoch comparisons
`descriptive_only`. Campaign views retain permanently charged draw/token
reservations, evaluator-witness and hostile-probe results, and exactly one
batch disposition per input, with high, unknown, and incompatible items
visibly extracted for root review.

## Replayable scenario gallery

Run the complete provider-free gallery from the plugin root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  skills/orch-dork/scripts/orch_dork_observability.py \
  skills/orch-dork/runtime/observability-scenarios
```

Each displayed result includes the exact fixture path and a canonical scenario
hash. Absolute historical source pointers are also hash-verified when present.

| Scenario | Displayed result | Replayable sanitized evidence |
| --- | --- | --- |
| Governed success | `SUCCESS`; exact claim permitted | [success.json](../runtime/observability-scenarios/success.json) |
| Missing exact usage | `UNKNOWN`; success withheld | [missing-evidence.json](../runtime/observability-scenarios/missing-evidence.json) |
| Conflicting root identity | `FAILURE` | [contradiction.json](../runtime/observability-scenarios/contradiction.json) |
| Cancellation with cleanup | `CANCELLED`; history is not rewritten | [cancellation.json](../runtime/observability-scenarios/cancellation.json) |
| Wrong subagent routing | `FAILURE`; no substitution | [wrong-routing.json](../runtime/observability-scenarios/wrong-routing.json) |
| Hard budget exhausted | `BLOCKED`; candidate is `NOT_STARTED` | [budget-exhaustion.json](../runtime/observability-scenarios/budget-exhaustion.json) |
| Undeclared extra work | `BLOCKED`; no extra worker starts | [blocked-extra-work.json](../runtime/observability-scenarios/blocked-extra-work.json) |
| Issue 17 canary timeout | `FAILURE`; correctness remains visible, usage is `UNKNOWN`, cleanup is clean, and the grant is nonreusable | [issue17-timeout.json](../runtime/observability-scenarios/issue17-timeout.json) |

The Issue 17 scenario reads only its preserved terminal, recovery, and
authorization-ledger records. It does not retry, resume, relabel, consume, or
replace the failed one-shot grant. Its executor finalization/evidence-extractor
defect remains a separate ticket rather than being hidden by this gallery.
