# Per-project improvements

## Contents

- [Per-project improvements](#per-project-improvements)
- [Promotion evidence](#promotion-evidence)
- [Adoption and later work](#adoption-and-later-work)

Issue 199 compares one enrolled project's host-local outcomes. It proposes
observed Workflow Profiles, worker counts and role models, without running a
model or changing policy. The production floor is twenty distinct eligible
project runs and five comparable runs per baseline and candidate choice.
Comparisons use the latest 256 eligible terminals ordered by terminal time
and run id. The report discloses selected and total counts and a digest of
omitted ids; all original terminals remain retained on the host.
Fixture-only lower floors are never available through MCP or adoption.
All observed candidate configurations are evaluated in batches of at most
sixteen against the same history and baseline. Each stored proposal retains
its exact evaluation batch; additional configurations neither overflow the
public evaluator contract nor disappear from the comparison.

Call `propose_project_improvements` with `project_root`. Without adopted
defaults, its `BASELINE_REQUIRED` asks for an observed `baseline_run_id`;
repeat with that id. `INSUFFICIENT_EVIDENCE` and `NO_IMPROVEMENT` end the
comparison. `PROPOSALS_RECORDED` returns proposal hashes and summaries.
Call `read_project_improvement` with the project and `proposal_sha256` to
show the entire proposal before any decision: the proposed settings, full
Champion and Challenger configurations, supporting, contradicting, neutral,
unknown and non-comparable runs, measures, floors and promotion gaps.

Profiles follow the admitted worker count, so a shape proposal reports the
coupled profile, count and role assignment changes. It makes no isolated
causal claim. Role-model comparisons hold the other roles, efforts, count
and profile fixed. Known implementation acceptance comes from the host's
Verified or Failed checks verdict; planner acceptance stays unknown.
Per-role cost and elapsed time stay unknown where the watcher cannot
attribute them. Whole-run latency uses the host's monotonic measurement;
historical equal or backward wall-clock stamps are unknown, never zero.
Recovered runs also have unknown latency: a replacement watcher did not time
the run it closes. Optional compiler-file absences are recorded in the digest;
missing required files still fail the freeze.
Ordinary runs have no configured total-token or ingress ceiling; the additive
CC v3 configuration records those two absent limits as null. V1/v2 numeric
contracts keep their historical meaning. A model checkpoint digest here
identifies retained onboarding observations, not model weights.

After explicit user approval or rejection, call `decide_project_improvement`
with `project_root`, the exact `confirm_proposal_sha256`, and `decision`
(`approve` or `reject`). The requesting task must be the same one that
created the proposal. Each decision is recorded once. An approval changes
no default and supplies no canary authority.

## Promotion evidence

The existing FR60 Champion/Challenger evaluator replays each stage's complete
configurations, frozen representative, recent-failure and adversarial corpus,
and lineage-disjoint holdout. Its gates remain safety/privacy/authority,
correctness, human usefulness, then cost and latency. Offline, shadow and
canary stages use disjoint fixture, lineage, result and corpus identities in
strict chronological order. No input can assert that a stage passed.

Local operator tooling captures results from this project's retained watcher
terminals, the frozen case inputs, explicit human review and observed
billing. It re-derives every result again at adoption. Budget reservations
are not observed cost. Missing review, unknown billing, unmeasured latency,
revised work, configuration drift or unsupported terminal conformance
produces no promotion result. There is no MCP argument for importing history,
measurements, an evaluation verdict or a promotion report.

The operator commands use the installed module, the originating task id and
the exact proposal hash. `INPUT.json` is a bounded local JSON file:

```bash
python3 -B skills/orch-dork/scripts/orch_dork_project_improvements.py \
  capture-result --project-root PROJECT --requesting-thread-id TASK \
  --proposal-sha256 PROPOSAL --stage offline --input-json INPUT.json

python3 -B skills/orch-dork/scripts/orch_dork_project_improvements.py \
  record-stage --project-root PROJECT --requesting-thread-id TASK \
  --proposal-sha256 PROPOSAL --stage offline --input-json STAGE.json

python3 -B skills/orch-dork/scripts/orch_dork_project_improvements.py \
  prepare-canary --project-root PROJECT --requesting-thread-id TASK \
  --proposal-sha256 PROPOSAL --input-json CANARY.json
```

`capture-result` takes exactly `run_id`, `configuration`, `corpus`, `fixture`,
`feedback` and `cost`. The result is computed from the stored context,
request and host terminal, not from caller-supplied success flags. The local
fixture is `orch-dork/project-evaluation-fixture/v1`, exactly `schema`,
`project_id`, `fixture_id`, `goal`, `lanes` (a map of `champion` and
`challenger` lane arrays), `partition` and `lineage_sha256`. Its identity
is SHA-256 of canonical JSON plus a newline. Its content and lineage must
belong to the frozen CC corpus before the run. Both configurations evaluate
the same fixture, using their respective declared lane assignment.

Feedback is `orch-dork/project-human-review/v1`, exactly `schema`,
`project_id`, `run_id`, `reviewer`, `reviewed_at`, `human_usefulness_bps`
(0–10000). Cost is `orch-dork/project-cost-observation/v1`, exactly
`schema`, `project_id`, `run_id`, `currency` (`USD`), `micros`, `source`
and `observed_at`. These are explicit local operator observations; model
self-review, a price estimate or a reserved budget must not fill them.
Their times follow the terminal. The host retains the originals by their
content digests. Declared safety/privacy/authority PASS means the watcher's
supported hook/owner and check contract agreed; it does not extend the
governed-mode promise to unobserved external processes or hosted tools.

`record-stage` takes the existing CC `evaluate_offline` request: `champion`,
`challenger`, `corpus`, `champion_results`, `challenger_results` and
`evaluated_at`. Use the returned capture results. Repeat for `shadow` only
after offline, and for `canary` only after its separate authorization and
actual cases. `prepare-canary` takes exactly `corpus` and `fixtures`; it
freezes the cases after offline and shadow pass. Read the proposal again to
show these cases, models, worker counts and maximum reserved cost to the
user. Only after separate explicit approval call `authorize_project_canary`
with `proposal_sha256` and the exact `confirm_canary_sha256`. That approval
expires in one hour and changes no defaults.

Start each approved case through ordinary `start_governed_run`, with the
case's exact goal, lanes, models and efforts, and a `project_canary` mapping
of `proposal_sha256`, `intent_sha256`, `fixture_sha256` and `role`
(`champion` or `challenger`). Ordinary standing authority and per-run
approval still apply. The host claims each case once before the first model
turn. Capturing a canary requires that claim. It cannot retrospectively
authorize an earlier run or substitute a different source, model or budget.

## Adoption and later work

After all stages pass and the user explicitly confirms adoption, call
`adopt_project_improvement` with the exact `confirm_proposal_sha256`.
The host replays the complete promotion, checks the unchanged enrollment and
prior preferences, refuses active or starting project runs, consumes the
confirmation once, and atomically writes the next private preference version.
Unknown promotion measurements cannot be overridden by user approval.

These per-project settings are separate from global registry role defaults.
ADR 0012's onboarding admits models; release qualification covers the plugin
generation on its pinned pair. Adoption adds no per-user or per-role model
qualification gate and grants no release authority.

New `prepare_work_summary` calls fill omitted models and efforts from active
preferences; explicit choices win. A one-worker plain request becomes one
implementation lane using the enrolled checks. Larger counts require drafted
disjoint lanes or enough ready disjoint tickets. Ticket selection uses the
adopted count, preserves document order and never chains another run. Zero
workers selects one ready ticket for root work. The prepared summary binds
the preference version and becomes stale if that version changes before
start. Every started plan and earlier terminal remains immutable. At the next
host intake, a Failed checks run governed by those exact active preferences
suspends them; it neither rewrites the run nor silently restores a different
policy. A new proposal and promotion are needed to activate another version.
