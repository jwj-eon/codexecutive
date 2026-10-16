# Skill-contract generation and forward evaluations

## Contents

- [Contract inventory](#contract-inventory)
- [First-load budget](#first-load-budget)
- [Trigger matrix](#trigger-matrix)
- [Fresh-context evaluations](#fresh-context-evaluations)
- [Forbidden-action controls](#forbidden-action-controls)
- [Stale and missing behavior](#stale-and-missing-behavior)
- [Installed and fresh-task boundary](#installed-and-fresh-task-boundary)

This reference defines provider-free behavioral checks for the skill contract.
It does not replace ticket admission, create workers, contact a model, or turn
submitted evidence into terminal qualification. It also does not accept the
host's work-summary intake, ticket-row selection, or ticket-status write-back:
those are the host intake seam's own domain and its own tests. This contract
judges whether the skill is invoked at all and what the first load costs.

## Contract inventory

The contract generation is the SHA-256 digest of a canonical inventory that
contains `SKILL.md` and every direct local reference linked from it. Inventory
rows contain only normalized skill-relative paths, byte counts, and content
hashes. Symlinks, missing files, paths outside the skill root, duplicate paths,
and nested reference loading are rejected.

Frontmatter must contain exactly `name` and `description`. The description is
the discovery contract and explicitly names the positive trigger contexts.
The body stays under 500 lines. Every directly linked reference over 100 lines
has a `## Contents` section.

## First-load budget

The first load is exactly `SKILL.md`: a fresh task reads it before any journey,
tool, or reference. The inventory therefore records that file's measured byte
count, its line count, the byte budget, and the total bytes left behind the
five lazily loaded references.

Bytes are the recorded budget because bytes are what the host measures exactly.
No tokenizer runs; the report carries `tokens_measured: false` and makes no
token estimate or bound. Exceeding the byte budget
is the named refusal `REFUSED_FIRST_LOAD_BUDGET_EXCEEDED`, not a warning, and
the line bound keeps its separate stop.

## Trigger matrix

The versioned `orch-dork/trigger-matrix/v2` fixture, which keeps accepting v1,
contains user-like prompts, declared judgment inputs,
applicable instruction facts, and expected outcomes. Expected fields are never
passed to the evaluator with the prompt. A test rejects prompts containing
their own expected classification or reason code.

Exactly three things trigger the skill: an explicit request, an applicable
instruction that requires observable delegation, or Codex's own judgment that
the work is worth splitting or worth substantive independent verification.

Positive rows cover explicit requests to orchestrate, delegate, parallelize,
use subagents, make orchestration the default, inspect an orchestration trace,
work the ticket list, and run work as a governed run; applicable project or
global policy requiring observable delegation; and accepted judgment over
opaque input, including a pasted free-form ticket file and a supplied issue
body.

A judgment input is a declaration Codex makes before any evidence exists. Every
case result labels it `codex_declared_judgment` with
`is_model_inference_evidence: false`, and the report repeats
`judgment_inputs_are_declarations` beside zero model and hosted calls. The
fixture simulates no model and infers nothing: it records what a declaration
would say and checks the disposition that follows.

A declaration is accepted only when it carries what it claims. Splitting needs
at least two declared lanes with disjoint declared writes; verification needs a
declared substantive change and at least one declared check. Otherwise the
result is untriggered with a named rejection:
`JUDGMENT_WITHOUT_TWO_DECLARED_LANES`,
`JUDGMENT_LANES_SHARE_DECLARED_WRITES`,
`JUDGMENT_WITHOUT_SUBSTANTIVE_CHANGE_AND_CHECK`,
`JUDGMENT_CLAIMS_NEITHER_SPLITTING_NOR_VERIFICATION`, or
`JUDGMENT_NOT_DECLARED`.

Negative rows cover an ordinary direct answer, one coherent low-impact edit, a
plain request carrying no accepted judgment, and a request word used as a word
rather than as a request, which is recorded as `suppressed_bare_mention`.
Without an applicable delegation requirement or an accepted declared judgment,
none of them trigger. An applicable policy remains an independent trigger.
The evaluator keeps
`SKILL_NOT_TRIGGERED` distinct from a triggered `ATOMIC_ADMITTED` decision.
Trigger evidence records the matched explicit intent or bound policy fact; a
bare keyword without request semantics is insufficient.

The deterministic fixture matcher suppresses each request-word occurrence
inside its own definition span. Comma-separated continuations stay in that span
when they contain only individual terms, quoted phrases or recognized request
phrases joined by `and` or `or`. A command with an object, such as `delegate the
CLI fix`, or an unquoted `please` command cue ends the list; a semicolon,
period, question mark or newline also
ends it. Definition questions cover the words before `mean`. A separate actual
request still triggers even if another occurrence was a bare mention, so
`triggered: true` and `suppressed_bare_mention: true` may coexist. This is a
provider-free fixture rule, not a model inference or an execution permission.

Trigger evaluation covers new work in a requesting task. A task already bound
to an admitted ticket, a frozen plan, an activated controller stage, or a
qualification driver stays on its selected journey and driver; it never
re-enters intake or starts a second run.

## Fresh-context evaluations

Each case starts from a closed fresh-context input with no prior conversation
and no expected answer in the prompt. The evaluator receives the prompt,
instruction facts, deliverable topology, coupling, authority, evidence, model,
ownership, admission freshness, worker state, and forbidden-action counters.

The atomic case has one coherent operation. It must be root-owned, admit zero
workers, fabricate no trace, and return `ATOMIC_ADMITTED` only after a fresh
ticket gate.

The orchestrated case has two or more independently ownable lanes; the
compatibility plan form and `first_completed_worker/v1` cap that at four,
while `finite_dag/v1` admits a larger dependency program. It must
return `ORCHESTRATION_PLAN_REQUIRED` and require frozen plan, resource closure,
ownership, capacity, lifecycle, and spawn-wave gates before any worker. Release
and integration ownership stay explicit; undeclared work is rejected.

The refused case lacks required authority, model, evidence, or safe ownership.
It stops before mutation with a stable named reason. Missing facts remain
unknown. Contradictions fail.

Every result records trigger disposition, classification, root ownership,
worker and trace disposition, required gates, unknowns, mutation permission,
and forbidden-action checks.

## Forbidden-action controls

Negative controls fail the campaign if any case permits or records an
undeclared worker, retry, replacement, fallback, nesting, stale admission,
credential access, prompt/session-body retention, private reasoning, hidden
chain-of-thought claim, or advisory-to-governed promotion.

Shared documentation or policy wiring does not collapse disjoint lanes.
Explicit atomic requests remain atomic. A submitted conformance `PASS` never
becomes terminal qualification without an independent post-terminal observer.

## Stale and missing behavior

Stable stops are:

- `UNKNOWN_MISSING_FRONTMATTER`
- `UNKNOWN_MALFORMED_FRONTMATTER`
- `UNKNOWN_BROKEN_DIRECT_REFERENCE`
- `REFUSED_STALE_CONTRACT_GENERATION`
- `REFUSED_STALE_TRIGGER_MATRIX`
- `REFUSED_FIRST_LOAD_BUDGET_EXCEEDED`
- `READ_ONLY_SOURCE_INSTALLED_MISMATCH`
- `UNKNOWN_EVALUATOR_UNAVAILABLE`
- `READ_ONLY_ACTIVE_TASK_OLDER_GENERATION`

None may be repaired by guessing, fallback loading, version switching, or
rewriting last-known-good evidence. The evaluator reports the exact stop and
preserves the previous bytes.

## Installed and fresh-task boundary

Run the same inventory, matrix, and evaluation cases against source, staged,
installed, and disposable clean-profile copies. Exact contract, trigger, and
fixture hashes must match. No copy may depend on the development checkout.

An active task that loaded an older contract stays on that generation and
reports `READ_ONLY_ACTIVE_TASK_OLDER_GENERATION` for changed-contract work.
Only a fresh task may load and exercise the newer installed generation.
The staged governed-attempt identity repeats source, installed, and
task-loaded versions plus `fresh_task: true`; any mismatch blocks `pre_spawn`.
An implementation task that cachebusts or reinstalls therefore records only
source/install verification. It cannot qualify the generation it changed.
