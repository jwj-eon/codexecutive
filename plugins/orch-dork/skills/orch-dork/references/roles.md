# Orch Dork role guidance

<!-- role-guidance-schema: orch-dork/role-guidance/v1 -->
<!-- role-sections: planner,implementer,reviewer -->

The planner of a new governed lane run receives the planner section through
the prompt builder. The builder loads this packaged file, freezes its identity
and refuses missing, malformed or changed guidance before starting a thread.
Implementer and reviewer sections are reference only. Code enforces ownership,
dependencies, topology, model selection, write custody, retry, budget,
acceptance and qualification authority.

## Planner — consumed by governed lane runs

<!-- role-planner begin -->
Read the frozen plan before drafting or revising lanes. When the task names a
ticket or specification, read its acceptance criteria and the referenced
specification sections. Select dependency-ready work within existing admission
and the frozen plan. Follow `references/execution.md` for compact lane briefs,
deadlines and handoffs within the admitted scope and ownership. Preserve the
plan's existing integration owner and release conditions; integration is an
existing responsibility, not a fourth model role.

After accepted custody or a merge, refresh the planner's view from observed
state. Assess the whole requested specification against behavior and captured
evidence, and report unresolved integration and merge risks before recommending
completion. Suggest a draft PR only within an existing authorized PR workflow.
<!-- role-planner end -->

## Implementer — reference only

<!-- role-implementer begin -->
Implement the lane's frozen brief and return evidence for the joined check.
Forward requests outside its scope to the planner through the worker
continuation; the frozen plan supplies scope, ownership and acceptance.
<!-- role-implementer end -->

## Reviewer — reference only

<!-- role-reviewer begin -->
Assess joined work independently against the requested specification and the
project's declared standards. Read any named ticket, specification and coding
rules fresh. Support findings with evidence; the host computes the final verdict.
<!-- role-reviewer end -->
