"""Execute and independently check lifecycle paths with explicit coverage gaps.

The integrated checkpoint profile consumes whole production observations from
a bounded fixture driver, checking each boundary before the next operation.
Its source and registry checklist cannot authorize release or qualification.
Host-observed execution custody and exhaustive coverage remain separate gates.
The original deterministic Issue 165 initial-to-wait entry points remain public.
"""

from __future__ import annotations

from lifecycle_conformance import values
from lifecycle_conformance import registries
from lifecycle_conformance import model
from lifecycle_conformance import fragment
from lifecycle_conformance import reference_model as reference
from lifecycle_conformance import reference_values as rv
from lifecycle_conformance import explorer, injection_oracle, protocol, public_inventory

CAMPAIGN_SCHEMA = "orch-dork/lifecycle-campaign-trace/v1"
MINIMAL_CASE_ID = "min-165"
MIN_TRANSITION_ID = "lc-trans:min-165:t1"
MIN_INITIAL_STATE_ID = "lc-state:min-165:init"
MIN_SUCCESSOR_STATE_ID = "lc-state:min-165:1"
MIN_BOUNDARY_ID = "lc-boundary:min-165:provider"

MIN_TRANSITION = {
    "from": "pre_turn",
    "to": "host_readiness",
    "trigger": "host_readiness_observed",
}

MIN_BOUNDARY = {
    "topic": "provider_availability",
    "observation_class": "unknown",
    "rationale":
        "live provider availability is outside the finite model",
    "owner": "issue-170",
    "evidence_expectation": "fresh-qualification-live-seam",
}

MIN_STIMULUS_PHRASE = "controller:activation"


def minimal_stimulus() -> dict:
    """The one closed typed stimulus of the minimal case."""
    return {
        "kind": "transition_reference",
        "reference": MIN_TRANSITION_ID,
        "phrase": MIN_STIMULUS_PHRASE,
        "evidence": None,
    }


def minimal_store() -> registries.RegistryStore:
    """One closed minimal registry store: initial state, transition, boundary."""
    store = registries.RegistryStore()
    store.add("lc-state", MIN_INITIAL_STATE_ID, MINIMAL_CASE_ID, {"phase": "pre_turn"})
    store.add("lc-trans", MIN_TRANSITION_ID, MINIMAL_CASE_ID, dict(MIN_TRANSITION))
    store.add("lc-boundary", MIN_BOUNDARY_ID, MINIMAL_CASE_ID, dict(MIN_BOUNDARY))
    return store


def _case_entries(case_id: str, initial_state: dict, successor: dict) -> list[dict]:
    return [
        {
            "id": [MIN_INITIAL_STATE_ID],
            "status": fragment.STATUS_COVERED,
            "cases": [{"id": case_id + "-init", "strength": fragment.CASE_STRENGTH_DIRECT}],
            "rationale": "",
        },
        {
            "id": [MIN_TRANSITION_ID],
            "status": fragment.STATUS_COVERED,
            "cases": [{"id": case_id + "-init", "strength": fragment.CASE_STRENGTH_DIRECT}],
            "rationale": "",
        },
        {
            "id": [successor["id"]],
            "status": fragment.STATUS_COVERED,
            "cases": [{"id": case_id + "-wait", "strength": fragment.CASE_STRENGTH_DIRECT}],
            "rationale": "",
        },
        {
            "id": [MIN_BOUNDARY_ID],
            "status": fragment.STATUS_EXTERNAL_BOUNDARY,
            "cases": [],
            "rationale": "",
        },
    ]


def generate_minimal_trace() -> dict:
    """Generate one registry-derived initial-to-wait trace."""
    store = minimal_store()
    state = model.initial_state(MINIMAL_CASE_ID)
    if state["id"] != MIN_INITIAL_STATE_ID:
        raise values.LifecycleContractError("campaign:case_mismatch")
    reduction = model.reduce(state, minimal_stimulus(), store)
    if reduction.successor["id"] != MIN_SUCCESSOR_STATE_ID:
        raise values.LifecycleContractError("campaign:case_mismatch")
    # The trace partition registers the successor so the coverage fragment
    # can bound it from the same registry view.
    store.add("lc-state", MIN_SUCCESSOR_STATE_ID, MINIMAL_CASE_ID, {
        "phase": reduction.successor["phase"],
    })
    fragment_doc = fragment.build_fragment(
        MINIMAL_CASE_ID,
        values.vocabulary_digest(),
        store.digest(),
        _case_entries(MINIMAL_CASE_ID, state, reduction.successor),
    )
    report = fragment.validate_fragment(fragment_doc, owner=MINIMAL_CASE_ID, store=store)
    trace = {
        "schema": CAMPAIGN_SCHEMA,
        "case": MINIMAL_CASE_ID,
        "initial_state": state,
        "stimulus": dict(minimal_stimulus()),
        "transition_id": reduction.transition_id,
        "successor": reduction.successor,
        "directive": reduction.directive,
        "registry_segment": store.items_of("lc-state"),
        "fragment": fragment_doc,
        "fragment_report": report,
    }
    return trace


def trace_bytes(trace: dict) -> str:
    """The deterministic canonical byte string of one generated trace."""
    if not isinstance(trace, dict) or trace.get("schema") != CAMPAIGN_SCHEMA:
        raise values.LifecycleContractError("campaign:schema_mismatch")
    return values.canonical_json(trace)


def generate_trace_bytes() -> str:
    """One-shot public seam: generate the minimal trace and return its bytes."""
    return trace_bytes(generate_minimal_trace())


# This bounded profile groups readiness, acknowledgement and join observations
# at the actual production commit boundaries. It is not every interleaving.
# Counts describe reference transitions, never a production report projection.
CHECKPOINT_PATH = (
    ('activation', 4), ('preparation', 0), ('capacity_admission', 1),
    ('before_spawn_spec', 0), ('observed_spawn_spec', 2),
    ('before_spawn_standards', 0), ('observed_spawn_standards', 1),
    ('worker_start', 2), ('before_continue_spec', 0), ('observed_continue_spec', 1),
    ('before_continue_standards', 0), ('observed_continue_standards', 1),
    ('checkpoint_progress', 3), ('before_continue_spec', 0), ('observed_continue_spec', 1),
    ('before_continue_standards', 0), ('observed_continue_standards', 1),
    ('worker_results', 2), ('result_aggregation', 1), ('review_submission', 0),
    ('semantic_review', 1), ('terminal_verification', 1), ('cleanup_authorization', 1),
    ('before_stop_spec', 0), ('observed_stop_spec', 2),
    ('before_stop_standards', 0), ('observed_stop_standards', 1),
    ('process_pending', 0), ('process_cleanup', 1), ('capacity_settlement', 1),
    ('final_qualification', 1), ('controller_quiescence', 0), ('owner_rotation', 1),
)
INTEGRATED_SCHEMA = 'orch-dork/integrated-lifecycle-path/v3'
GRAPH_PATH_MAPPING_SCHEMA = 'orch-dork/production-graph-path-mapping/v1'
REVIEW_PROFILES = ('review-pass', 'review-fail', 'review-inconclusive', 'review-refused')
RELEASE_PROFILES = tuple(f'release-{point}-{outcome}'
                        for point in ('submission', 'pending', 'observation')
                        for outcome in ('pass', 'fail', 'inconclusive', 'refused'))
_FRAME_FIELDS = {'report', 'state', 'authority', 'grants', 'capacity', 'process_observation', 'owner_observation'}
_RETAINED_FIELDS = ('worker_results', 'review_packet', 'review_submission', 'review_context',
                    'review_acknowledgement', 'review_observation', 'review_outcome', 'terminal_verification')


def _require(condition, reason):
    if condition is not True:
        raise values.LifecycleContractError('campaign:' + reason)


def _same(left, right):
    return rv.freeze(left) == rv.freeze(right)


def _profile_path(profile):
    if profile == 'checkpoint':
        return CHECKPOINT_PATH
    if type(profile) is str and profile in RELEASE_PROFILES:
        _, point, outcome = profile.split('-')
        semantic = 'semantic_review_refused' if outcome == 'refused' else 'semantic_review'
        path = list(CHECKPOINT_PATH[:20]) + [('review_pending_1', 0), ('review_pending_2', 0), (semantic, 1)]
        release_after = {'submission': 'review_submission', 'pending': 'review_pending_1', 'observation': semantic}[point]
        index = next(i for i, row in enumerate(path) if row[0] == release_after)
        path.insert(index + 1, ('signed_release', 1))
        path.append(('review_retry_refused', 0) if outcome == 'refused' else ('terminal_verification', 1))
        return tuple(path)
    _require(type(profile) is str and profile in REVIEW_PROFILES, 'profile')
    prefix = CHECKPOINT_PATH[:20] + (('review_pending_1', 0), ('review_pending_2', 0))
    if profile == 'review-refused':
        return prefix + (('semantic_review_refused', 1), ('review_retry_refused', 0))
    tail = CHECKPOINT_PATH[20:]
    if profile != 'review-pass':
        tail = tuple(('failure_closure' if label == 'final_qualification' else label, count)
                     for label, count in tail)
    return prefix + tail


def _review_profile(profile):
    return 'review-' + profile.rsplit('-', 1)[-1] if profile in RELEASE_PROFILES else profile


def _frame_fields(profile):
    return _FRAME_FIELDS | {'release_evidence'} if profile in RELEASE_PROFILES else _FRAME_FIELDS


def _advance_reference(state, outcome='accepted', variant=None):
    before = state.to_plain()
    stage = before.get('stage', '')
    if stage == 'ack':
        variant = 'SUCCESS'
    elif stage.startswith('continue.'):
        variant = ('checkpoint_deferred' if before['progress_admission'] in ('unrequested', 'pending')
                   else 'deferred')
    options = [event for event in reference.outgoing_stimuli(state).to_plain()
               if event.get('outcome', 'accepted') == outcome
               and (variant is None or event.get('variant') == variant)]
    _require(bool(options), 'profile_transition_missing')
    # The declared serial profile chooses the public registry's first lane.
    event = options[0]
    reduction = reference.reduce(state, event).to_plain()
    successor = rv.freeze(reduction['successor'])
    _require(_same(reduction['directive'], reference.legal_directive(successor).to_plain()), 'model_directive')
    injection_oracle.state_invariants(successor, reduction['directive'])
    return successor, {'before_sha256': state.digest(), 'stimulus': event,
                       'after_sha256': successor.digest(), 'transition_id': reduction['transition_id']}


def _advance_graph_reference(state, transition):
    """Replay one selected campaign transition in the canonical Issue 166 graph."""
    choice = explorer.abstract_event(transition['stimulus'])
    options = [event for event in reference.outgoing_stimuli(state).to_plain()
               if protocol.strict_equal(explorer.abstract_event(event), choice)]
    _require(len(options) == 1, 'graph_transition_alignment')
    event = options[0]
    source = explorer.state_identity(state)
    reduction = reference.reduce(state, event).to_plain()
    successor = rv.freeze(reduction['successor'])
    target = explorer.state_identity(successor)
    _require(_same(reduction['directive'], reference.legal_directive(successor).to_plain()),
             'graph_model_directive')
    injection_oracle.state_invariants(successor, reduction['directive'])
    return successor, {
        'choice': choice,
        'source_state_id': source,
        'target_state_id': target,
        'transition_id': explorer.edge_identity(source, event, target),
    }


def _release_evidence(frame, retained):
    """Check signed fixture semantics; host custody/authenticity remains a gate.

    The production authority verifies signatures when it consumes these exact
    receipts. This independent comparison checks lane/proof bindings and hashes,
    and never treats the owner-query fixture process as an observed empty group.
    """
    evidence = frame['release_evidence']
    if evidence is None:
        _require('release_evidence' not in retained, 'lost_release_evidence')
        return []
    _require(type(evidence) is dict and set(evidence) == {'scope', 'program', 'capacity_before'}
             and evidence['scope'] == 'signed_worker_cleanup_fixture', 'release_evidence_shape')
    if 'release_evidence' in retained:
        _require(_same(evidence, retained['release_evidence']), 'retained_release_evidence')
    else:
        retained['release_evidence'] = rv.freeze(evidence).to_plain()
    program = evidence['program']
    _require(program['operation'] == 'capacity_settlement', 'release_operation')
    receipts = program['payload']['release_receipts']
    lanes = evidence['capacity_before']['state']['active_lane_ids']
    _require(type(receipts) is list and len(receipts) == len(lanes) == 2
             and sorted(row['lane_id'] for row in receipts) == sorted(lanes)
             and len(set(lanes)) == 2, 'release_lane_coverage')
    for row in receipts:
        signed = row['cleanup_observer_receipt']
        payload = signed['payload']
        _require(row['schema'] == 'orch-dork/lane-capacity-release/v1' and row['status'] == 'RELEASED'
                 and row['released'] is True and row['identity_retained_not_reusable'] is True
                 and row['reason_codes'] == [] and row['cleanup_status'] == 'complete'
                 and row['terminal_state'] == 'completed'
                 and type(row['owned_descendants']) is int and row['owned_descendants'] == 0, 'release_facts')
        _require(row['receipt_sha256'] == values.canonical_digest({k: v for k, v in row.items() if k != 'receipt_sha256'})
                 and row['cleanup_evidence_sha256'] == values.canonical_digest(signed)
                 and signed['payload_sha256'] == values.canonical_digest(payload), 'release_proof_hash')
        _require(signed['schema'] == 'orch-dork/signed-observer-receipt/v1'
                 and signed['receipt_kind'] == 'lane-cleanup-observation' and signed['algorithm'] == 'ed25519'
                 and type(signed['signature']) is str and bool(signed['signature'])
                 and payload['schema'] == 'orch-dork/lane-cleanup-observer-payload/v1', 'release_proof_shape')
        for key in ('lane_id', 'run_id', 'route', 'cleanup_status', 'terminal_state', 'terminal_evidence_sha256', 'owned_descendants'):
            _require(_same(row[key], payload[key]), 'release_proof_binding')
    _require(frame['capacity']['state']['active_lane_ids'] == [], 'release_capacity')
    return sorted(lane.rsplit(':', 1)[-1] for lane in lanes)


def _sealed(value, field, reason):
    _require(type(value) is dict and value.get(field) == values.canonical_digest(
        {key: child for key, child in value.items() if key != field}), reason)


def _review_expectation(bindings, activation, controller_id, source):
    """Derive the cross-boundary identity independently of production validators."""
    packet, submission = bindings['review_packet'], bindings['review_submission']
    context, acknowledgement = bindings['review_context'], bindings['review_acknowledgement']
    _require(_same(packet['source_report'], source), 'review_source')
    _sealed(packet, 'packet_sha256', 'review_packet_seal')
    _sealed(submission, 'submission_sha256', 'review_submission_seal')
    receipt = source['receipt']
    subject = {key: receipt[key] for key in (
        'identity_sha256', 'run_id', 'attempt_id', 'root_task_id', 'plan_id', 'plan_revision', 'plan_sha256')}
    subject.update(root_model=source['routing']['root']['model'], root_effort=source['routing']['root']['effort'],
                   installed_version=source['tool']['version'], worker_results=receipt['bindings']['worker_results'])
    _require(packet['schema'] == 'orch-dork/qualification-review-packet/v1'
             and packet['subject_sha256'] == values.canonical_digest(subject)
             and submission['schema'] == 'orch-dork/qualification-review-submission/v1'
             and submission['subject_sha256'] == packet['subject_sha256'], 'review_subject')
    native, hooks = context['native_call'], context['owner_hook_inventory_report']
    identity = activation['identity']
    _require(context['schema'] == 'orch-dork/qualification-review-context/v1'
             and context['controller_id'] == controller_id
             and native['schema'] == 'orch-dork/host-mcp-call-context/v1'
             and native['task_id'] == identity['root_thread_id'] == source['root_task_id']
             and native['session_id'] == identity['root_session_id'] == native['task_id']
             and native['model'] == identity['root_model'] == source['routing']['root']['model']
             and native['effort'] == identity['root_effort'] == source['routing']['root']['effort'], 'review_context_identity')
    _sealed(hooks, 'report_sha256', 'review_owner_seal')
    _require(hooks['report_sha256'] == activation['hook_trust']['hook_inventory_report_sha256']
             and hooks['status'] == 'PASS' and hooks['issues'] == [], 'review_activation_owner')
    expected_ack = {'schema': 'orch-dork/qualification-review-acknowledgement/v1',
        'status': 'PASS', 'decision': 'REVIEW_SUBMITTED', 'controller_id': controller_id,
        'subject_sha256': packet['subject_sha256'], 'submission_sha256': submission['submission_sha256'],
        'native_call': native}
    expected_ack['acknowledgement_sha256'] = values.canonical_digest(expected_ack)
    _require(_same(acknowledgement, expected_ack), 'review_acknowledgement')
    return {'task_id': native['task_id'], 'turn_id': native['turn_id'], 'tool_call_id': native['tool_call_id'],
        'owner_identity_sha256': hooks['owner_identity_sha256'],
        'app_server_argv_sha256': hooks['app_server_argv_sha256'], 'hook_inventory_report_sha256': hooks['report_sha256'],
        'server': 'orch-dork', 'tool': 'submit_issue94_semantic_review', 'structured_result': acknowledgement,
        'arguments': {'pre_turn_report_path': context['pre_turn_report_path'],
                      'pre_turn_report_sha256': context['pre_turn_report_sha256'],
                      'subject_sha256': packet['subject_sha256'], 'verifications': submission['verifications']}}


def _review_owner_observation(report, expected, hooks):
    """Compare retained transport facts; hashes never establish host custody."""
    counters = {'model_calls', 'hosted_calls', 'credential_reads', 'network_calls', 'task_creations', 'native_calls'}
    _require(type(report) is dict and set(report) == {
        'schema', 'status', 'issues', 'expectation', 'observation', 'provider_free', 'report_sha256', *counters},
        'review_observation_shape')
    _sealed(report, 'report_sha256', 'review_observation_seal')
    _require(report['schema'] == 'orch-dork/current-local-task-mcp-observation/v1'
             and report['provider_free'] is True
             and all(type(report[key]) is int and report[key] == 0 for key in counters), 'review_observation_effects')
    _require(_same(report['expectation'], expected), 'review_observation_expectation')
    status, observation = report['status'], report['observation']
    if status == 'PENDING':
        _require(observation is None and report['issues'] == ['mcp_observation:awaiting_completed_call'],
                 'review_pending_evidence')
    elif status == 'REFUSED':
        reasons = ('owner_mismatch', 'route_mismatch', 'hooks_unavailable', 'turn_inventory_invalid',
                   'call_ambiguous', 'turn_mismatch', 'result_mismatch', 'source_digest_invalid',
                   'source_invalid', 'owner_unavailable')
        _require(observation is None and report['issues'] in [['mcp_observation:' + reason] for reason in reasons],
                 'review_refused_evidence')
    else:
        _require(status == 'OBSERVED' and report['issues'] == [] and type(observation) is dict
                 and set(observation) == {'task_id', 'turn_id', 'model_provider', 'owner_identity_sha256',
                     'app_server_argv_sha256', 'hook_inventory_report', 'call', 'thread_read_sha256'},
                 'review_observed_shape')
        _require(all(observation[key] == expected[key] for key in (
            'task_id', 'turn_id', 'owner_identity_sha256', 'app_server_argv_sha256'))
            and observation['model_provider'] == 'openai'
            and _same(observation['hook_inventory_report'], hooks), 'review_observed_owner')
        digest = observation['thread_read_sha256']
        _require(type(digest) is str and len(digest) == 64 and not set(digest) - set('0123456789abcdef'),
                 'review_observed_source')
        call = observation['call']
        _require(type(call) is dict and set(call) == {'type', 'id', 'server', 'tool', 'arguments', 'result',
            'error', 'status', 'durationMs', 'pluginId', 'appContext', 'readOnlyHint'}, 'review_call_shape')
        _require(call['type'] == 'mcpToolCall' and call['status'] == 'completed' and call['error'] is None
                 and call['pluginId'] == 'orch-dork@orch-dork-local' and call['id'] == expected['tool_call_id']
                 and call['server'] == expected['server'] and call['tool'] == expected['tool']
                 and type(call['durationMs']) is int and call['durationMs'] >= 0
                 and (call['appContext'] is None or type(call['appContext']) is dict)
                 and (call['readOnlyHint'] is None or type(call['readOnlyHint']) is bool)
                 and _same(call['arguments'], expected['arguments']), 'review_completed_call')
        result = call['result']
        _require(type(result) is dict and set(result) == {'_meta', 'content', 'structuredContent'}
                 and (result['_meta'] is None or type(result['_meta']) is dict)
                 and type(result['content']) is list and all(type(item) is dict for item in result['content'])
                 and _same(result['structuredContent'], expected['structured_result']), 'review_completed_result')
    return status


def _review_attribution(frame, bindings, retained):
    if 'review_submission' not in bindings:
        _require(not any(key.startswith('review_') for key in bindings), 'premature_review_context')
        return None
    expected = _review_expectation(bindings, retained['activation'], frame['report']['controller_id'],
                                   retained['review_source_report'])
    observation = bindings.get('review_observation')
    pending = frame['report'].get('review_observation')
    if pending is not None:
        _require(observation is None, 'duplicate_review_observation')
        observation = pending
    status = 'NOT_OBSERVED' if observation is None else _review_owner_observation(
        observation, expected, bindings['review_context']['owner_hook_inventory_report'])
    return {'scope': 'retained_review_owner_call_binding', 'expectation_sha256': values.canonical_digest(expected),
            'observation_status': status, 'observation_sha256': None if observation is None else values.canonical_digest(observation),
            'host_authentication': 'REQUIRED', 'authority_created': False}


def _compare_boundary(frame, state, label, retained, initial_owner, profile='checkpoint'):
    _require(type(frame) is dict and set(frame) == _frame_fields(profile), 'frame_shape')
    review_profile = _review_profile(profile)
    plain = state.to_plain()
    report, durable = frame['report'], frame['state']
    authority, grants, capacity = frame['authority'], frame['grants'], frame['capacity']
    for key, value in (('activation', durable['activation']), ('controller_id', report['controller_id'])):
        if key not in retained:
            retained[key] = rv.freeze(value).to_plain()
        _require(_same(value, retained[key]), 'retained_' + key)
    status = 'BLOCKED' if label == 'review_retry_refused' else 'PASS'
    _require(report['status'] == status and report['provider_free'] is True, 'production_report')
    for field in ('model_calls', 'hosted_calls', 'credential_reads', 'native_calls', 'task_creations', 'worker_creations'):
        _require(type(report[field]) is int and report[field] == 0, 'production_effect_counter')
    _require(_same(report['stage_report'], durable['stage_report']), 'durable_stage_report')
    _require(_same(report['action'], durable['action']), 'durable_action')
    _require(durable['pending_intent'] is None, 'pending_intent')
    action, expected = report['action'], plain['action']
    if expected is not None and expected['method'] == 'rotate_owner':
        _require(report['next_stage_action'] in ('owner_disposition', 'await_successor_owner'), 'owner_barrier')
        expected = None  # Owner CAS is a separate host obligation, not a worker grant.
    _require((action is None) == (expected is None), 'action_presence')
    if action is not None:
        _require(action['tool_name'].split('__')[-1] == expected['method']
                 and action['lane_ids'] == [expected['lane']], 'next_action')
        _require(durable['grant_state'] == 'AUTHORIZED', 'action_grant')
    _require(type(grants['unsettled_grant_count']) is int
             and grants['unsettled_grant_count'] == int(action is not None), 'unsettled_grants')
    occupied = sorted(lane for lane, row in plain['lanes'].items() if row['capacity'] in ('reserved', 'occupied'))
    active = capacity['state']['active_lane_ids']
    _require(len(active) == len(set(active)) and sorted(lane.rsplit(':', 1)[-1] for lane in active) == occupied,
             'occupied_resources')
    histories = durable['action_evidence']
    signatures = [(row['action']['kind'], row['action']['lane_ids'][0]) for row in histories]
    expected_history = []
    for event in plain['history']:
        stage = event['stage']
        kind = 'spawn' if stage.startswith('spawn.') else 'continue' if stage.startswith('continue.') else (
            'stop' if stage.startswith('close.') else None)
        if kind is not None:
            expected_history.append((kind, event['lane']))
    _require(signatures == expected_history, 'retained_action_history')
    _require(grants['state_counts']['POST_OBSERVED'] == len(histories), 'settled_action_history')
    stage_report = report['stage_report'] or {}
    bindings = (stage_report.get('receipt') or {}).get('bindings', {})
    for key in _RETAINED_FIELDS:
        if key in retained:
            _require(key in bindings and _same(bindings[key], retained[key]), 'retained_' + key)
        elif key in bindings:
            retained[key] = rv.freeze(bindings[key]).to_plain()
    results = bindings.get('worker_results', [])
    observed = sorted(row['binding']['logical_worker_id'] for row in results
                      if row['status'] == 'OBSERVED' and row['handoff_receipt']['disposition'] == 'complete')
    _require(observed == sorted(lane for lane, row in plain['lanes'].items() if row['typed_result'] is not None),
             'typed_results')
    for key in ('checkpoint_sources', 'final_sources'):
        if key in retained:
            _require(key in durable and _same(durable[key], retained[key]), 'retained_' + key)
        elif key in durable:
            retained[key] = rv.freeze(durable[key]).to_plain()
    _require(('checkpoint_sources' in durable) == any(row['checkpoint'] is not None for row in plain['lanes'].values()),
             'checkpoint_evidence')
    _require(('final_sources' in durable) == bool(observed), 'final_evidence')
    if label == 'result_aggregation':
        retained['review_source_report'] = rv.freeze(stage_report).to_plain()
    review_attribution = _review_attribution(frame, bindings, retained)
    review_events = [row for row in plain['history'] if row['stage'] == 'review']
    if review_events:
        outcome = review_events[-1]['outcome']
        expected_review = {'accepted': 'accepted', 'failed': 'rejected', 'unknown': 'evidence_required'}[outcome]
        _require(bindings.get('review_outcome') == expected_review
                 and bindings.get('review_observation', {}).get('status') == (
                     'REFUSED' if outcome == 'unknown' else 'OBSERVED'), 'review_evidence')
    else:
        _require('review_outcome' not in bindings, 'premature_review')
    if review_profile in REVIEW_PROFILES and 'review_submission' in bindings:
        disposition = review_profile.removeprefix('review-') if review_profile != 'review-refused' else 'pass'
        receipts = bindings['review_submission']['verifications']
        _require([row['verification_receipt']['disposition'] for row in receipts] == [disposition, 'pass'],
                 'review_disposition')
        _require(all(row['verification_receipt']['pass'] is (row['verification_receipt']['disposition'] == 'pass')
                     for row in receipts), 'review_scalar')
    _require(('terminal_verification' in bindings) == (plain['terminal_verification'] == 'accepted'), 'verification_evidence')
    if 'terminal_verification' in bindings:
        _require(bindings['terminal_verification']['outcome'] == plain['outcome'], 'verification_outcome')
    process = frame['process_observation']
    process_closed = plain['process_group'] == 'zero_owned_descendants'
    released_lanes = _release_evidence(frame, retained) if profile in RELEASE_PROFILES else []
    if released_lanes:
        _require(process_closed and process is None, 'signed_release_process_scope')
    elif process_closed:
        _require(type(process) is dict and process['status'] == 'OBSERVED'
                 and process['observation']['group_absent'] is True
                 and type(process['observation']['group_members']) is int
                 and process['observation']['group_members'] == 0, 'process_obligation')
    elif process is not None:
        _require(label == 'process_pending' and process['status'] == 'PENDING', 'premature_process_release')
    closed_lanes = sorted(lane for lane, row in plain['lanes'].items() if row['cleanup'] == 'closed')
    _require(sorted(set(lane for kind, lane in signatures if kind == 'stop') | set(released_lanes)) == closed_lanes, 'cleanup_obligations')
    rotated = plain['controller']['owner_disposition'] == 'rotated'
    observation = frame['owner_observation']
    if rotated:
        _require(label == 'owner_rotation' and observation['status'] == 'OBSERVED'
                 and observation['owner_released'] is True and not _same(authority['owner'], initial_owner), 'owner_observation')
    else:
        _require(_same(authority['owner'], initial_owner) and observation is None, 'retained_owner')
    _require(durable['terminal'] is (label in ('controller_quiescence', 'owner_rotation')), 'controller_terminal')
    barrier = plain['requirement'] is not None
    if barrier:
        _require(review_profile == 'review-refused'
                 and label in ('semantic_review_refused', 'review_retry_refused', 'signed_release')
                 and plain['requirement']['stage'] == 'review'
                 and plain['requirement']['observation'] == 'unknown'
                 and report['next_stage_action'] == 'review_evidence', 'review_barrier')
    else:
        _require(plain['requirement'] is None, 'unresolved_model_requirement')
    compared = {'action': None if expected is None else {'method': expected['method'], 'lane': expected['lane']},
        'occupied_lanes': occupied, 'closed_lanes': closed_lanes,
        'unsettled_grants': grants['unsettled_grant_count'], 'process_closed': process_closed,
        'owner_disposition': plain['controller']['owner_disposition'],
        'retained_evidence_sha256': {key: values.canonical_digest(value) for key, value in retained.items()},
        'obligations': {'worker_cleanup': sorted(lane for lane, row in plain['lanes'].items() if row['cleanup'] == 'pending'),
            'process_cleanup': not process_closed, 'capacity_release': occupied, 'owner_release': not rotated}}
    if review_attribution is not None:
        compared['review_attribution'] = review_attribution
    if profile != 'checkpoint':
        compared['outcome'] = plain['outcome']
        compared['external_requirement'] = plain['requirement']
    if profile in RELEASE_PROFILES:
        compared['physical_evidence_scope'] = 'signed_worker_cleanup_fixture' if released_lanes else None
    return compared


class _PathVerifier:
    def __init__(self, profile='checkpoint'):
        self.profile, self.path = profile, _profile_path(profile)
        self.state = reference.initial_state('campaign-170-checkpoint')
        self.retained, self.trace, self.frames = {}, [], []
        self.initial_owner = None
        self.failed = False

    def observe(self, label, observation):
        """Reject a mismatch before the driver performs its next operation."""
        _require(not self.failed, 'prior_mismatch')
        self.failed = True
        self._observe(label, observation)
        self.failed = False

    def _observe(self, label, observation):
        row = rv.freeze({'boundary': label, 'observation': observation}).to_plain()
        index = len(self.frames)
        _require(index < len(self.path), 'extra_boundary')
        expected_label, count = self.path[index]
        _require(label == expected_label, 'boundary_order')
        frame = row['observation']
        _require(type(frame) is dict and set(frame) == _frame_fields(self.profile), 'frame_shape')
        if index == 0:
            _require(type(frame['authority']) is dict and type(frame['authority'].get('owner')) is dict, 'owner_shape')
            self.initial_owner = frame['authority']['owner']
        transitions = []
        for _ in range(count):
            outcome = ('unknown' if label == 'semantic_review_refused' else 'failed'
                       if label == 'semantic_review' and _review_profile(self.profile) in ('review-fail', 'review-inconclusive')
                       else 'accepted')
            self.state, transition = _advance_reference(self.state, outcome, 'sealed_release' if label == 'signed_release' else None)
            transitions.append(transition)
        try:
            compared = _compare_boundary(frame, self.state, label, self.retained, self.initial_owner, self.profile)
            if label == 'signed_release':
                previous = self.frames[-1]['observation']
                evidence = frame['release_evidence']
                _require(previous['release_evidence'] is None, 'duplicate_release')
                _require(_same(evidence['capacity_before'], previous['capacity'])
                         and _same(evidence['program']['predecessor_receipt'], previous['report']['stage_report']['receipt']),
                         'release_predecessor')
            if label.startswith('review_pending_') or label == 'review_retry_refused':
                previous = self.frames[-1]['observation']
                for key in ('state', 'authority', 'grants', 'capacity', 'process_observation', 'owner_observation'):
                    _require(_same(frame[key], previous[key]), 'stationary_' + key)
                _require(_same(frame['report']['cursor'], previous['report']['cursor']), 'stationary_cursor')
                if label.startswith('review_pending_'):
                    _require(frame['report']['decision'] == 'REVIEW_OBSERVATION_PENDING'
                             and frame['report']['review_observation']['status'] == 'PENDING', 'pending_observation')
        except values.LifecycleContractError:
            raise
        except (KeyError, TypeError, ValueError, IndexError) as error:
            raise values.LifecycleContractError('campaign:malformed_observation') from error
        self.trace.append({'index': index, 'boundary': label, 'observation_sha256': values.canonical_digest(frame),
            'model_state_sha256': self.state.digest(), 'model_stage': self.state.to_plain()['stage'],
            'transitions': transitions, 'comparison': compared})
        self.frames.append(row)

    def finish(self):
        _require(not self.failed, 'prior_mismatch')
        refused = _review_profile(self.profile) == 'review-refused'
        released = self.profile in RELEASE_PROFILES
        _require(len(self.frames) == len(self.path), 'incomplete_lifecycle')
        claim = injection_oracle.state_invariants(self.state, reference.legal_directive(self.state).to_plain()).to_plain()['resource_claim']
        final_stage = 'review' if refused else (
            'final_qualification' if _review_profile(self.profile) == 'review-pass' else 'failure_closure') if released else 'terminal'
        _require(self.state.to_plain()['stage'] == final_stage
                 and claim == ('retained' if refused or released else 'closed'), 'incomplete_lifecycle')
        if released:
            _require(self.state.to_plain()['capacity_settlement'] == 'released', 'missing_release')
        result = {'schema': INTEGRATED_SCHEMA, 'status': 'BARRIER_PASS_COVERAGE_INCOMPLETE' if refused else (
            'PREFIX_PASS_COVERAGE_INCOMPLETE' if released else 'PATH_PASS_COVERAGE_INCOMPLETE'),
            'case': 'campaign-170-checkpoint', 'frames_sha256': values.canonical_digest(self.frames), 'trace': self.trace,
            'completed_lifecycle': not (refused or released), 'unresolved_mismatches': [],
            'execution_attested': False, 'qualification_authorized': False}
        if self.profile != 'checkpoint':
            result.update(profile=self.profile)
        return rv.freeze(result)


def replay_integrated_path(frames: list[dict], *, profile='checkpoint') -> rv.FrozenValue:
    """Independently replay one complete observed path; establish no host custody."""
    _require(type(frames) is list and len(frames) == len(_profile_path(profile)), 'path_length')
    verifier = _PathVerifier(profile)
    for row in frames:
        _require(type(row) is dict and set(row) == {'boundary', 'observation'}, 'boundary_shape')
        verifier.observe(row['boundary'], row['observation'])
    return verifier.finish()


def run_integrated_path(execute, *, profile='checkpoint') -> tuple[rv.FrozenValue, list[dict]]:
    """Run a bounded fixture driver and then verify all original observations.

    The host owns process/time/source-exit custody. This entry point never runs
    a live provider or authorizes release; a callback alone cannot attest that.
    """
    _require(callable(execute), 'executor')
    verifier = _PathVerifier(profile)
    execute(verifier.observe)
    return verifier.finish(), verifier.frames


def validate_integrated_path(report: rv.FrozenValue, frames: list[dict], *, profile='checkpoint') -> None:
    """Rebuild against every original observation; self-resealing cannot omit gaps."""
    _require(type(report) is rv.FrozenValue and report == replay_integrated_path(frames, profile=profile), 'path_binding')


def map_integrated_path_to_graph(path: rv.FrozenValue) -> rv.FrozenValue:
    """Map a checked path's model bridges into the canonical Issue 166 graph.

    This sidecar does not authenticate the submitted path or alter its canonical
    report. Global graph totals stay unknown until a complete graph index is
    supplied to a later reader.
    """
    _require(type(path) is rv.FrozenValue, 'graph_path_not_immutable')
    plain = path.to_plain()
    _require(type(plain) is dict and plain.get('schema') == INTEGRATED_SCHEMA
             and type(plain.get('trace')) is list, 'graph_path_shape')
    graph_state = reference.initial_state(explorer.GRAPH_CASE)
    mapped_states = [explorer.state_identity(graph_state)]
    mapped_transitions = []
    trace = []
    for index, row in enumerate(plain['trace']):
        _require(type(row) is dict and row.get('index') == index
                 and type(row.get('boundary')) is str
                 and type(row.get('transitions')) is list, 'graph_trace_shape')
        bridges = []
        for transition in row['transitions']:
            graph_state, bridge = _advance_graph_reference(graph_state, transition)
            bridges.append(bridge)
            mapped_states.append(bridge['target_state_id'])
            mapped_transitions.append(bridge['transition_id'])
        _require(row.get('model_stage') == graph_state.to_plain().get('stage'),
                 'graph_stage_alignment')
        trace.append({'index': index, 'boundary': row['boundary'],
                      'graph_state_id': explorer.state_identity(graph_state),
                      'model_bridge_transitions': bridges})
    state_ids = list(dict.fromkeys(mapped_states))
    transition_ids = list(dict.fromkeys(mapped_transitions))
    return rv.freeze({
        'schema': GRAPH_PATH_MAPPING_SCHEMA,
        'status': 'PATH_ONLY',
        'graph_case': explorer.GRAPH_CASE,
        'graph_owner': explorer.OWNER,
        'input_sha256': values.canonical_digest(plain),
        'trace': trace,
        'mapped_reference': {
            'state_ids': state_ids,
            'transition_ids': transition_ids,
        },
        'coverage_gap': {
            'inventory_status': 'UNAVAILABLE',
            'states': {'mapped': len(state_ids), 'total': None, 'uncovered': None},
            'transitions': {'mapped': len(transition_ids), 'total': None, 'uncovered': None},
        },
        'execution_attested': False,
        'production_graph_complete': False,
        'release_authorized': False,
        'qualification_authorized': False,
    })


def build_coverage_checklist(sources: dict[str, str], registry_components: dict[str, dict]) -> rv.FrozenValue:
    """Enumerate current source sites and supplied registries without closing them.

    Exact feasible PASS alternatives and reachable state/interleaving expansion
    remain named derivation obligations. No old graph's counts are reused as
    evidence of current coverage; source-backed role decisions stay explicit.
    """
    source = public_inventory.describe_source_obligations(sources)
    required = {'replays', 'host_fixtures', 'host_mcp_fixtures', 'injection_sites', 'injection_schedule'}
    _require(type(registry_components) is dict and set(registry_components) == required, 'registry_components')
    obligations = dict(source.to_plain()['obligations'])
    for component, items in sorted(registry_components.items()):
        _require(type(items) is dict and bool(items), 'registry_items')
        for item, record in sorted(items.items()):
            _require(type(item) is str and bool(item), 'registry_item')
            identity = 'registry:' + component + ':' + item
            obligations[identity] = {'kind': component, 'status': 'PENDING', 'record_sha256': values.canonical_digest(record),
                'reason': 'Bind this exact registered item to an executed integrated case and current model identifiers.'}
    for stage, record in protocol.STAGES.to_plain().items():
        obligations['stage:' + stage] = {'kind': 'lifecycle_stage', 'status': 'PENDING',
            'record_sha256': values.canonical_digest(record),
            'reason': 'Expand and execute all applicable observations, orders and failure/cleanup outcomes.'}
    for identity, reason in {
        'reachable_states_and_interleavings': 'Enumerate current model graph and all causal paths; compare every applicable production boundary.',
        'site_state_cartesian': 'Expand each injection job across every current applicable reachable state.',
        'semantic_pass_branches': 'Resolve each source branch obligation into feasible PASS cases or a reviewed source-backed exclusion.',
        'complete_module_and_pair_scope': 'Bind runtime allowlist and classify aliases, omitted exports, helpers and actual constructor/validator roles.',
        'independent_mutation_gate': 'Reject missing, stale, duplicate, changed, unexplained and incomplete execution evidence.',
        'deterministic_shard_union': 'Prove exact final shard union against the unsharded executed inventory.',
        'host_execution_custody': 'Bind source/runtime digests and host-observed exits, cleanup and exact executed cases.',
        'final_rehearsal_full_suite': 'Regenerate final campaign, rehearsal and full suite on identical final runtime bytes.',
        'release_qualification_gate': 'Mechanically enforce incomplete/consumed/stale refusal before the single candidate and qualification.',
    }.items():
        obligations['derivation:' + identity] = {'kind': 'integration_gate', 'status': 'PENDING', 'reason': reason}
    counts = {}
    for row in obligations.values():
        counts[row['kind']] = counts.get(row['kind'], 0) + 1
    return rv.freeze({'schema': 'orch-dork/integrated-coverage-checklist/v1',
        'status': 'COVERAGE_INCOMPLETE', 'source_inventory': source.to_plain(),
        'registry_sha256': values.canonical_digest(registry_components), 'obligations': obligations,
        'counts': counts, 'semantic_branch_inventory_complete': False, 'reachable_state_inventory_complete': False,
        'execution_attested': False, 'qualification_authorized': False})


def run_integrated_campaign(execute, *, sources, registry_components, profile='checkpoint'):
    """Execute the complete seed and publish one explicit blocked coverage gate."""
    checklist = build_coverage_checklist(sources, registry_components)
    path, frames = run_integrated_path(execute, profile=profile)
    return _campaign_report(path, checklist), frames


def _campaign_report(path, checklist):
    return rv.freeze({'schema': 'orch-dork/integrated-lifecycle-campaign/v1',
        'status': path.to_plain()['status'], 'path': path.to_plain(), 'coverage': checklist.to_plain(),
        'acceptance': {'complete_path': 'PASS' if path.to_plain()['completed_lifecycle'] else 'BLOCKED',
                       'complete_coverage': 'BLOCKED', 'host_execution_custody': 'REQUIRED'},
        'qualification_authorized': False, 'release_authorized': False})


def validate_integrated_campaign(report, frames, *, sources, registry_components, profile='checkpoint'):
    """Readback requires all original frames, exact source bytes and registries."""
    rebuilt = _campaign_report(replay_integrated_path(frames, profile=profile), build_coverage_checklist(sources, registry_components))
    _require(type(report) is rv.FrozenValue and report == rebuilt, 'campaign_binding')


def build_completion_gate(evidence, *, sources, registry_components,
                          host_runs=None, consumption_anchor=None):
    """Build the fixed-reader gate while retaining process-local host custody."""
    from lifecycle_conformance import completion_gate
    return completion_gate.build_completion_report(
        evidence, sources=sources, registry_components=registry_components,
        host_runs=host_runs, consumption_anchor=consumption_anchor)


def validate_completion_gate(report, evidence, *, sources, registry_components,
                             host_runs=None, consumption_anchor=None):
    """Rebuild the aggregate gate from preserved original evidence."""
    from lifecycle_conformance import completion_gate
    completion_gate.validate_completion_report(
        report, evidence, sources=sources, registry_components=registry_components,
        host_runs=host_runs, consumption_anchor=consumption_anchor)
