"""Pinned MCP fixture extension and exact current-host vocabulary coverage.

The original host corpus stays immutable and separately replayable. This module
joins both executed components and refuses a current kind without fixtures.
Captured wire facts are transport examples, never live owner authority.
"""
from __future__ import annotations

from pathlib import Path

from lifecycle_conformance import catalog, fragment, host_adapter as host
from lifecycle_conformance import host_fixtures as legacy, reference_values as rv, registries, values
from lifecycle_conformance import explorer, production_adapter as production, reference_model as model

OWNER = "issue-170-host-mcp"
CORPUS_DIGEST = "7f23b6732dd7de227f3fef6e7e532b03f51309498c8182b157d027422e5aba95"
KINDS = ("completed_mcp_tool_call", "mcp_call_context")
CASE_COUNT = 18


def _refuse(reason):
    raise values.LifecycleContractError("host_mcp_fixtures:" + reason)


def _normalized_observation(adapter, kind, raw):
    try:
        return {'decision': 'ACCEPTED', 'value': adapter.normalize(kind, raw)}
    except values.LifecycleContractError as error:
        return {'decision': 'REFUSED', 'reason': error.reason}


def _validate(corpus):
    if type(corpus) is not rv.FrozenValue or corpus.digest() != CORPUS_DIGEST:
        _refuse("identity")
    data = corpus.to_plain()
    rows = data["cases"]
    if (data["schema"] != "orch-dork/host-mcp-extension-fixture-corpus/v1"
            or data["profile"] != host.HOST_PROFILE.to_plain()
            or data["supported_kinds"] != list(KINDS)
            or {row["kind"] for row in rows} != set(KINDS)
            or len(rows) != CASE_COUNT or len({row["id"] for row in rows}) != CASE_COUNT):
        _refuse("inventory")
    for row in rows:
        if (values.canonical_digest(row["raw_input"]) != row["raw_input_sha256"]
                or values.canonical_digest(row["raw_output"]) != row["raw_output_sha256"]):
            _refuse("raw_binding")
    return data


def load_corpus(root: Path = legacy.FIXTURES) -> rv.FrozenValue:
    corpus = legacy._read(root / "mcp-context-extension-v1.json")
    _validate(corpus)
    return corpus


def replay(corpus: rv.FrozenValue | None = None, *, shard_index=0, shard_count=1) -> dict:
    if (type(shard_index) is not int or type(shard_count) is not int
            or not 1 <= shard_count <= CASE_COUNT or not 0 <= shard_index < shard_count):
        _refuse("shard")
    data = _validate(load_corpus() if corpus is None else corpus)
    store = registries.RegistryStore()
    entries, results = [], []
    for index, row in enumerate(data["cases"]):
        if index % shard_count != shard_index:
            continue
        adapter = host.CodexHostAdapter(row["host_profile"])
        observed = _normalized_observation(adapter, row["kind"], row["raw_input"])
        if (observed["decision"] != row["expected_disposition"]
                or values.canonical_digest(observed) != row["raw_output_sha256"]):
            _refuse("canonical_observation")
        item, case = "lc-fix:" + OWNER + ":" + row["id"], "host-mcp-" + row["id"]
        store.add("lc-fix", item, OWNER, {
            "host_profile_sha256": values.canonical_digest(row["host_profile"]),
            "observation_kind": row["kind"], "origin": row["origin"],
            "raw_input_sha256": row["raw_input_sha256"], "raw_output_sha256": row["raw_output_sha256"],
            "capture_provenance_sha256": values.canonical_digest(data["provenance"]),
        })
        entries.append({"id": [item], "status": "covered",
                        "cases": [{"id": case, "strength": "direct"}], "rationale": ""})
        results.append({"case": case, "item": item,
                        "observation_sha256": values.canonical_digest(observed), "status": "PASS"})
    coverage = fragment.build_fragment(OWNER, values.vocabulary_digest(), store.digest(), entries)
    verified = fragment.validate_fragment(coverage, owner=OWNER, store=store)
    return {"schema": "orch-dork/host-mcp-extension-conformance/v1", "status": "PASS",
            "corpus_sha256": CORPUS_DIGEST, "cases": results,
            "registry": {kind: store.items_of(kind) for kind in store.kinds()},
            "coverage": coverage, "coverage_validation": verified,
            "boundary": {"fixture_replay_only": True, "physical_calls": 0,
                         "authority_created": False, "qualification_authorized": False}}


def replay_current_profile(host_corpus=None, adapter_corpus=None, extension_corpus=None) -> dict:
    """Execute the complete pinned profile; no unknown current kind is waived."""
    supplied = (host_corpus, adapter_corpus, extension_corpus)
    if all(item is None for item in supplied):
        host_corpus, adapter_corpus = legacy.load_corpora()
        extension_corpus = load_corpus()
    elif any(item is None for item in supplied):
        _refuse("partial_inputs")
    legacy.validate_corpora(host_corpus, adapter_corpus)
    extension = _validate(extension_corpus)
    old_kinds = {row["kind"] for row in host_corpus.to_plain()["cases"]}
    new_kinds = {row["kind"] for row in extension["cases"]}
    if old_kinds & new_kinds or old_kinds | new_kinds != set(host.OBSERVATIONS):
        _refuse("current_vocabulary_gap")
    original_report, extension_report = legacy.replay(host_corpus, adapter_corpus), replay(extension_corpus)
    joined = catalog.build_catalog([
        catalog.component(legacy.OWNER, original_report["registry"], original_report["coverage"], original_report),
        catalog.component(OWNER, extension_report["registry"], extension_report["coverage"], extension_report),
    ])
    return {"schema": "orch-dork/current-host-profile-conformance/v1", "status": "PASS",
            "host_profile_sha256": host.HOST_PROFILE.digest(), "observed_kinds": sorted(old_kinds | new_kinds),
            "legacy_report": original_report, "extension_report": extension_report, "catalog": joined.to_plain(),
            "boundary": {"fixture_replay_only": True, "physical_calls": 0,
                         "all_public_constructor_pairs_closed": False, "qualification_authorized": False}}


def validate_current_profile(report, host_corpus, adapter_corpus, extension_corpus) -> None:
    if (type(report) is not dict
            or rv.freeze(report) != rv.freeze(replay_current_profile(host_corpus, adapter_corpus, extension_corpus))):
        _refuse("profile_binding")


def _action_name_path():
    """Replay one complete direct-result path; retain whole states and directives."""
    state = model.initial_state(explorer.GRAPH_CASE)
    states, edges, trace, contexts = {}, {}, [], {}
    expected = {method: [prefix + '.spec', prefix + '.standards'] for method, prefix in
                (('spawn_agent', 'spawn'), ('send_input', 'continue'), ('close_agent', 'close'))}
    for _ in range(32):
        data, directive = state.to_plain(), model.legal_directive(state).to_plain()
        identity = explorer.state_identity(state)
        states[identity] = {'phase': data['phase'], 'state_digest': state.digest(),
            'stage': data.get('stage', 'activate' if data['generation'] == 3 else data['phase']),
            'directive_kind': directive['kind']}
        trace.append({'state': identity, 'value': data, 'directive': directive})
        action = data.get('action')
        if action is not None and action['method'] in expected:
            if (directive['kind'] != 'action' or directive['payload'].get('action') != action
                    or data['stage'] not in expected[action['method']] or data['stage'] in contexts):
                _refuse('action_context')
            contexts[data['stage']] = {'state': identity, 'method': action['method'],
                'lane': action['lane'], 'state_sha256': state.digest(),
                'directive_sha256': values.canonical_digest(directive)}
        if data.get('stage') == 'terminal':
            break
        options = [event for event in model.outgoing_stimuli(state).to_plain()
                   if event.get('outcome', 'accepted') == 'accepted'
                   and event.get('variant', 'evidence') in ('evidence', 'SUCCESS', 'direct')]
        if not options:
            _refuse('action_path_dead_end')
        event = options[0]
        transition = model.registry_snapshot(state).to_plain()[event['transition']]
        reduced = model.reduce(state, event).to_plain()
        successor = rv.freeze(reduced['successor'])
        if rv.freeze(reduced['directive']) != model.legal_directive(successor):
            _refuse('action_path_directive')
        target, choice = explorer.state_identity(successor), explorer.abstract_event(event)
        edge = 'lc-trans:issue-166:' + values.canonical_digest({'from': identity, 'choice': choice, 'to': target})
        edges[edge] = {'from': data['phase'], 'to': successor.to_plain()['phase'],
            'trigger': transition['trigger'], 'source_state': identity, 'target_state': target,
            'model_transition': event['transition'], 'choice': choice}
        trace[-1]['transition'] = edge
        state = successor
    if (state.to_plain().get('stage') != 'terminal'
            or set(contexts) != {stage for stages in expected.values() for stage in stages}):
        _refuse('action_path_incomplete')
    return {'profile': 'direct-results-spec-first', 'graph_registry': {'lc-state': states, 'lc-trans': edges},
            'trace': trace, 'contexts': contexts}


def bind_action_names(host_corpus, adapter_corpus, extension_corpus) -> rv.FrozenValue:
    """Bind transport-name compatibility to selected live model action states.

    Normalization executes on pinned original fixtures. It never dispatches an
    action, consumes a grant or advances the model. Other host semantics and the
    absent dispatched wait_agent action remain explicit mapping requirements.
    """
    legacy.validate_corpora(host_corpus, adapter_corpus)
    extension = _validate(extension_corpus)
    path = _action_name_path()
    bindings, pending = {}, {}
    cases, comparisons = 0, 0
    for row in host_corpus.to_plain()['cases']:
        item = 'lc-fix:issue-168:' + row['id']
        base = {'case': 'host-' + row['id'], 'item': item,
                'raw_input_sha256': row['raw_input_sha256'], 'observation_sha256': row['raw_output_sha256']}
        if row['kind'] != 'tool_name':
            pending[item] = {**base, 'reason': 'observation_kind_requires_contextual_mapping', 'kind': row['kind']}
            continue
        adapter = host.CodexHostAdapter(row['host_profile'])
        observed = _normalized_observation(adapter, row['kind'], row['raw_input'])
        if values.canonical_digest(observed) != row['raw_output_sha256']:
            _refuse('action_name_observation')
        cases += 1
        contexts = {stage: context for stage, context in path['contexts'].items()
                    if observed['decision'] == 'REFUSED'
                    or observed['value'] == 'multi_agent_v1__' + context['method']}
        if not contexts:
            if observed != {'decision': 'ACCEPTED', 'value': 'multi_agent_v1__wait_agent'}:
                _refuse('unexplained_action_name')
            pending[item] = {**base, 'reason': 'no_dispatched_wait_agent_action_in_model', 'kind': 'tool_name'}
            continue
        comparisons += len(contexts)
        bindings[item] = {**base, 'scope': 'selected_action_name_compatibility', 'observation': observed,
            'contexts': contexts, 'model_transitions_consumed': 0, 'action_dispatched': False,
            'authority_created': False}
    for row in adapter_corpus.to_plain()['cases']:
        item = 'lc-pair:issue-168:' + row['id']
        pending[item] = {'case': 'host-' + row['id'], 'item': item,
            'reason': 'preparation_is_zero_authority_not_activation', 'kind': 'activation_preparation'}
    for row in extension['cases']:
        item = 'lc-fix:' + OWNER + ':' + row['id']
        pending[item] = {'case': 'host-mcp-' + row['id'], 'item': item,
            'reason': 'mcp_wire_metadata_requires_owner_context', 'kind': row['kind']}
    return rv.freeze({'schema': 'orch-dork/host-action-name-model-bindings/v1',
        'status': 'SELECTED_ACTION_NAMES_BOUND_COVERAGE_INCOMPLETE',
        'input_digests': {'host_corpus': host_corpus.digest(), 'adapter_corpus': adapter_corpus.digest(),
                         'extension_corpus': extension_corpus.digest()},
        'path': path, 'bindings': bindings, 'pending': pending,
        'normalization_cases': cases, 'comparisons': comparisons,
        'full_graph_executed': False, 'execution_attested': False, 'qualification_authorized': False})


def validate_action_names(report, host_corpus, adapter_corpus, extension_corpus) -> None:
    if (type(report) is not rv.FrozenValue
            or report != bind_action_names(host_corpus, adapter_corpus, extension_corpus)):
        _refuse('action_name_binding')


def _unadmitted_boundary(path, stages, raw_input, observation, decoded=None, *, state_ids=None):
    """The independent model must reject each whole compatibility observation."""
    contexts = {}
    expected = set(stages if state_ids is None else state_ids)
    for row in path['trace']:
        stage = path['graph_registry']['lc-state'][row['state']]['stage']
        key = stage if state_ids is None else row['state']
        if key not in expected:
            continue
        if key in contexts:
            _refuse('duplicate_boundary_context')
        state = rv.freeze(row['value'])
        before, directive = state.digest(), model.legal_directive(state)
        reasons = {}
        observations = [('input', raw_input), ('output', observation)]
        if decoded is not None:
            observations.append(('decoded', decoded))
        for name, raw in observations:
            try:
                model.reduce(state, raw)
            except values.LifecycleContractError as error:
                reasons[name] = error.reason
            else:
                _refuse('unadmitted_observation_accepted')
            if state.digest() != before or model.legal_directive(state) != directive:
                _refuse('unadmitted_observation_mutated')
        contexts[key] = {'state': row['state'], 'state_sha256': before,
            'directive_sha256': directive.digest(), 'model_refusals': reasons}
        if state_ids is not None:
            contexts[key]['stage'] = stage
    if set(contexts) != expected:
        _refuse('boundary_context_gap')
    return contexts


def _wait_boundary_states(path):
    """Retain every observation wait, including repeated stages, by identity."""
    records = path['graph_registry']['lc-state']
    expected = {identity for identity, row in records.items() if row['directive_kind'] == 'wait_for_observation'}
    selected = []
    for row in path['trace']:
        if row['directive']['kind'] != 'wait_for_observation':
            continue
        state, identity = rv.freeze(row['value']), row['state']
        stage = row['value'].get('stage', 'activate' if row['value']['generation'] == 3 else row['value']['phase'])
        if (identity not in expected or identity in selected or identity != explorer.state_identity(state)
                or records[identity]['state_digest'] != state.digest() or records[identity]['stage'] != stage
                or row['value'].get('action') is not None or 'action' in row['directive']['payload']
                or rv.freeze(row['directive']) != model.legal_directive(state)):
            _refuse('wait_context')
        selected.append(identity)
    if not selected or set(selected) != expected:
        _refuse('wait_context_inventory')
    return tuple(selected)


def _process_boundary_stages(path):
    """Select unique cleanup/release contexts with their obligations retained."""
    for stage, proof, detail in (('process', 'unproven', 'process_group_proof'),
                                 ('settle', 'zero_owned_descendants', 'release_capacity')):
        rows = [row for row in path['trace']
                if path['graph_registry']['lc-state'][row['state']]['stage'] == stage]
        if len(rows) != 1:
            _refuse('process_context')
        state, directive = rows[0]['value'], rows[0]['directive']
        controller, lanes = state['controller'], state['lanes']
        if (state['process_group'] != proof or state['capacity_settlement'] != 'pending'
                or state['action'] is not None or state['attempt_closure'] is not None
                or controller['active'] is not True or controller['owner_disposition'] != 'retained'
                or controller['successor_owner'] is not None or set(lanes) != {'spec', 'standards'}
                or any(lane['capacity'] != 'occupied' or lane['cleanup'] != 'closed' for lane in lanes.values())
                or any(status != 'settled' for status in state['grants'].values())
                or directive['kind'] != 'wait_for_observation' or directive['payload']['detail'] != detail
                or 'action' in directive['payload']):
            _refuse('process_context')
    return ('pre_turn', 'process', 'settle')


def _mcp_boundary_stages(path):
    """MCP wire completion leaves semantic review and owner proof outstanding."""
    for stage, review, detail in (('review', 'pending', 'sol_review'),
                                  ('verify', 'accepted', 'terminal_verification')):
        rows = [row for row in path['trace']
                if path['graph_registry']['lc-state'][row['state']]['stage'] == stage]
        if len(rows) != 1:
            _refuse('mcp_context')
        state, directive = rows[0]['value'], rows[0]['directive']
        controller, lanes = state['controller'], state['lanes']
        if (state['sol_review'] != review or state['terminal_verification'] != 'pending'
                or state['aggregation'] != 'accepted' or state['process_group'] != 'unproven'
                or state['capacity_settlement'] != 'pending' or state['attempt_closure'] is not None
                or state['action'] is not None or controller['active'] is not True
                or controller['owner_disposition'] != 'retained' or controller['successor_owner'] is not None
                or set(lanes) != {'spec', 'standards'}
                or any(lane['capacity'] != 'occupied' or lane['cleanup'] != 'pending' for lane in lanes.values())
                or directive['kind'] != 'wait_for_observation' or directive['payload']['detail'] != detail
                or 'action' in directive['payload']):
            _refuse('mcp_context')
    return ('activate', 'review', 'verify')


def bind_preparation_boundaries(host_corpus, adapter_corpus, extension_corpus) -> rv.FrozenValue:
    """Join selected bootstrap, preparation, hook and transport observations.

    A ready preparation is not activation, and no denial is not a grant. The
    actual constructors/normalizer run; the independent model rejects their
    original inputs and complete outputs as unadmitted lifecycle transitions.
    This checks selected boundaries, not authenticated readiness or dispatch.
    Individual bootstrap observations leave all pre-turn readiness flags false;
    a complete owner-bound readiness bundle is still required.
    Successful transport decoding preserves the whole contained report and its
    disposition. Decoded values also need independent model guard refusals.
    PTY facts cannot supply owner process cleanup or release occupied capacity.
    Wait aliases are unadmitted at every selected observation-wait state; their
    names cannot satisfy a typed observation or authorize a native wait action.
    MCP call records and metadata require owner attribution and typed evidence;
    their wire completion cannot activate, accept a review or verify a run.
    """
    action_evidence = bind_action_names(host_corpus, adapter_corpus, extension_corpus).to_plain()
    path, pending, selected = action_evidence['path'], dict(action_evidence['pending']), {}
    bootstrap_kinds = ('environment', 'owned_file', 'javascript_globals', 'hook_inventory', 'session_start')
    transport_kinds = ('response', 'newline_frame', 'pty')
    bootstrap = [row for row in path['trace']
                 if path['graph_registry']['lc-state'][row['state']]['stage'] == 'pre_turn']
    if (len(bootstrap) != 1 or bootstrap[0]['value']['generation'] != 0
            or rv.freeze(bootstrap[0]['value']['readiness']) != rv.freeze({
                'shared': False, 'lanes': {'spec': False, 'standards': False}})
            or bootstrap[0]['directive']['kind'] != 'wait_for_observation'
            or bootstrap[0]['directive']['payload']['detail'] != 'pre_turn'
            or 'action' in bootstrap[0]['directive']['payload']):
        _refuse('bootstrap_context')
    activation = [row for row in path['trace']
                  if path['graph_registry']['lc-state'][row['state']]['stage'] == 'activate']
    if len(activation) != 1:
        _refuse('preactivation_context')
    seed, directive = activation[0]['value'], activation[0]['directive']
    # The public interface retains the completed readiness seed at generation3;
    # do not fabricate the controller/resource fields of its internal projection.
    if (set(seed) != {'id', 'phase', 'generation', 'result', 'readiness'} or seed['generation'] != 3
            or directive['kind'] != 'wait_for_observation' or directive['payload']['detail'] != 'activation'
            or 'action' in directive['payload'] or len(directive['payload']['bindings']) != 1
            or directive['payload']['bindings'][0]['grant_id'] != 'none'):
        _refuse('preactivation_context')
    counters = ('hosted_calls', 'model_calls', 'native_calls', 'task_creations', 'worker_creations',
                'credential_reads', 'authority_grants_minted', 'native_action_authorizations')
    # Keep the verifier's closed counter contract independent of the producer;
    # drift requires an explicit review, never silently fewer or different checks.
    if production.native.ACTIVATION_PREPARATION_ZERO_COUNTERS != counters:
        _refuse('preparation_counter_contract')
    process_stages = _process_boundary_stages(path)
    mcp_stages = _mcp_boundary_stages(path)
    wait_states = _wait_boundary_states(path)
    adapter_cases = adapter_corpus.to_plain()['cases']
    blocked_report = next(row for row in adapter_cases if row['id'] == 'activation-preparation-refused')
    jobs = [('activation_preparation', row) for row in adapter_cases]
    jobs += [(row['kind'], row) for row in host_corpus.to_plain()['cases']
             if row['kind'] in ('permission', *bootstrap_kinds, *transport_kinds)]
    jobs += [('wait_alias', row) for row in host_corpus.to_plain()['cases']
             if row['kind'] == 'tool_name'
             and row['raw_output'] == {'decision': 'ACCEPTED', 'value': 'multi_agent_v1__wait_agent'}]
    jobs += [(row['kind'], row) for row in extension_corpus.to_plain()['cases']]
    for kind, row in jobs:
        decoded, report_binding = None, None
        state_ids = None
        if kind == 'activation_preparation':
            item = 'lc-pair:issue-168:' + row['id']
            observed = production.ProductionLifecycleAdapter.prepare_activation(**row['raw_input'])
            valid = production.native.validate_activation_preparation_report(observed)
            if (valid.get('valid') is not True or type(observed) is not dict or observed.get('provider_free') is not True
                    or any(type(observed.get(field)) is not int or observed.get(field) != 0 for field in counters)):
                _refuse('preparation_authority')
            stages = ['activate']
            disposition = observed['decision']
        else:
            item = 'lc-fix:' + (OWNER if kind in KINDS else 'issue-168') + ':' + row['id']
            adapter = host.CodexHostAdapter(row['host_profile'])
            observed = _normalized_observation(adapter, 'tool_name' if kind == 'wait_alias' else kind, row['raw_input'])
            if kind != 'permission':
                disposition = observed['decision']
            elif observed['decision'] == 'ACCEPTED':
                value = observed['value']
                if (type(value) is not dict or value.get('authority_granted') is not False
                        or value.get('hook_disposition') not in ('no_denial', 'deny')):
                    _refuse('permission_authority')
                disposition = value['hook_disposition']
            else:
                disposition = 'REFUSED'
            stages = list(path['contexts']) if kind == 'permission' else ['pre_turn']
            if kind == 'response':
                stages = ['activate']
            elif kind == 'pty':
                stages = process_stages
            elif kind == 'wait_alias':
                if observed != {'decision': 'ACCEPTED', 'value': 'multi_agent_v1__wait_agent'}:
                    _refuse('wait_alias_observation')
                stages, state_ids, decoded = (), wait_states, observed['value']
            elif kind in KINDS:
                stages = mcp_stages
            if kind in (*transport_kinds, *KINDS) and observed['decision'] == 'ACCEPTED':
                decoded = observed['value']
                if kind == 'response':
                    valid = production.native.validate_activation_preparation_report(decoded)
                    if (valid.get('valid') is not True or blocked_report['expected_status'] != 'BLOCKED'
                            or rv.freeze(decoded) != rv.freeze(blocked_report['raw_output'])
                            or decoded.get('status') != 'BLOCKED' or decoded.get('decision') != 'REFUSED'):
                        _refuse('response_report_binding')
                    disposition = decoded['decision']
                    report_binding = {'item': 'lc-pair:issue-168:' + blocked_report['id'],
                        'report_sha256': values.canonical_digest(decoded),
                        'status': decoded['status'], 'decision': disposition}
        if (values.canonical_digest(observed) != row['raw_output_sha256']
                or values.canonical_digest(row['raw_input']) != row['raw_input_sha256']):
            _refuse('boundary_observation')
        if item not in pending or item in selected:
            _refuse('boundary_fixture_identity')
        contexts = _unadmitted_boundary(path, stages, row['raw_input'], observed, decoded, state_ids=state_ids)
        if (values.canonical_digest(observed) != row['raw_output_sha256']
                or values.canonical_digest(row['raw_input']) != row['raw_input_sha256']):
            _refuse('boundary_observation_mutated')
        selected[item] = {'case': pending.pop(item)['case'], 'item': item,
            'scope': 'selected_unadmitted_' + kind, 'raw_input_sha256': row['raw_input_sha256'],
            'observation_sha256': row['raw_output_sha256'], 'observation': observed,
            'disposition': disposition, 'contexts': contexts, 'model_transitions_consumed': 0,
            'action_dispatched': False, 'authority_created': False}
        if kind in bootstrap_kinds:
            selected[item].update(readiness_authorized=False, owner_readiness_binding='REQUIRED')
        if kind in transport_kinds:
            selected[item].update(transport_disposition=observed['decision'],
                lifecycle_transition_authorized=False, owner_transport_binding='REQUIRED')
            if report_binding is not None:
                selected[item]['decoded_report_binding'] = report_binding
        if kind == 'pty':
            selected[item].update(process_cleanup_authorized=False, capacity_release_authorized=False,
                owner_process_binding='REQUIRED')
        if kind == 'wait_alias':
            selected[item].update(transport_disposition=observed['decision'], context_identity='state',
                native_wait_action_authorized=False, lifecycle_transition_authorized=False,
                model_observation_binding='REQUIRED')
        if kind in KINDS:
            selected[item].update(transport_disposition=observed['decision'],
                lifecycle_transition_authorized=False, review_authorized=False, verification_authorized=False,
                owner_call_binding='REQUIRED', model_observation_binding='REQUIRED')
    comparisons = sum(len(row['contexts']) for row in selected.values())
    refusals = sum(len(context['model_refusals']) for row in selected.values() for context in row['contexts'].values())
    return rv.freeze({'schema': 'orch-dork/host-preparation-model-bindings/v6',
        'status': 'SELECTED_HOST_BOUNDARIES_BOUND_COVERAGE_INCOMPLETE',
        'input_digests': action_evidence['input_digests'], 'action_name_evidence': action_evidence,
        'boundary_evidence': selected, 'bindings': {**action_evidence['bindings'], **selected}, 'pending': pending,
        'boundary_comparisons': comparisons, 'model_guard_refusals': refusals,
        'full_graph_executed': False, 'execution_attested': False, 'qualification_authorized': False})


def validate_preparation_boundaries(report, host_corpus, adapter_corpus, extension_corpus) -> None:
    if (type(report) is not rv.FrozenValue
            or report != bind_preparation_boundaries(host_corpus, adapter_corpus, extension_corpus)):
        _refuse('preparation_binding')
