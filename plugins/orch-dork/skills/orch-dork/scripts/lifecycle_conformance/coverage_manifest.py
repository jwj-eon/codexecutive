"""Join pinned development observations without promoting them to qualification.

The caller preserves the plan before dispatch, original case observations, and
the bounded host's report/logs. This pure reader checks their bindings and
replays the independent verifiers. It cannot authenticate caller-supplied host
reports or establish runtime allowlist custody. Historical captures therefore
remain captured replays, even when their current independent replay succeeds.
"""
from __future__ import annotations

import ast
import hashlib
import re

from lifecycle_conformance import campaign, catalog, host_fixtures, host_mcp_fixtures
from lifecycle_conformance import public_pair_evidence, public_pair_registry, replay_bindings, replays
from lifecycle_conformance import reference_values as rv, values

__all__ = ['build_plan', 'build_manifest', 'validate_manifest', 'shard_cases', 'join_shards',
           'build_registry_manifest', 'validate_registry_manifest',
           'build_joined_manifest', 'validate_joined_manifest',
           'build_completion_manifest', 'validate_completion_manifest']
PROFILES = ('checkpoint', *campaign.REVIEW_PROFILES, *campaign.RELEASE_PROFILES)
MAX_CASES = 512
MAX_SHARDS = 64


def _require(condition, reason):
    if not condition:
        raise values.LifecycleContractError('coverage_manifest:' + reason)


def _shape(value, fields, reason):
    _require(type(value) is dict and set(value) == set(fields), reason)


def _sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _plan_rows(plan):
    _require(type(plan) is rv.FrozenValue, 'plan')
    data = plan.to_plain()
    _shape(data, ('schema', 'cases', 'qualification_authorized'), 'plan_shape')
    _require(data['schema'] == 'orch-dork/development-evidence-plan/v1'
             and data['qualification_authorized'] is False, 'plan_authority')
    rows = data['cases']
    _require(type(rows) is dict and len(PROFILES) < len(rows) <= MAX_CASES, 'case_count')
    profiles, pairs = set(), set()
    for identity, row in rows.items():
        _shape(row, ('kind', 'name', 'observation_sha256'), 'case_shape')
        name = row['name']
        _require(type(name) is str and 0 < len(name) <= 1024
                 and _sha(row['observation_sha256']), 'case_identity')
        if row['kind'] == 'lifecycle':
            _require(identity == 'lifecycle:' + name and name in PROFILES, 'profile')
            profiles.add(name)
        else:
            _require(row['kind'] == 'public_pair' and identity == 'public-pair:' + name, 'pair_case')
            pairs.add(name)
    _require(profiles == set(PROFILES) and bool(pairs), 'required_cases')
    return rows


def build_plan(lifecycle_frames: dict[str, list], public_observations: list[dict]) -> rv.FrozenValue:
    """Pin complete declared profiles and a selected public-pair capture inventory.

    Selecting public captures does not prove complete pair or PASS-branch scope.
    The retained plan is an independent input to readback, never inferred from
    only the shards that happened to arrive.
    """
    _require(type(lifecycle_frames) is dict and set(lifecycle_frames) == set(PROFILES), 'profiles')
    _require(type(public_observations) is list and bool(public_observations), 'public_observations')
    rows = {}
    for profile, frames in sorted(lifecycle_frames.items()):
        _require(type(frames) is list and bool(frames), 'frames')
        rows['lifecycle:' + profile] = {'kind': 'lifecycle', 'name': profile,
                                      'observation_sha256': values.canonical_digest(frames)}
    for observation in public_observations:
        _require(type(observation) is dict and type(observation.get('case')) is str, 'public_case')
        case = observation['case']
        identity = 'public-pair:' + case
        _require(identity not in rows, 'duplicate_case')
        rows[identity] = {'kind': 'public_pair', 'name': case,
                          'observation_sha256': values.canonical_digest(observation)}
    plan = rv.freeze({'schema': 'orch-dork/development-evidence-plan/v1', 'cases': rows,
                      'qualification_authorized': False})
    _plan_rows(plan)
    return plan


def _check_cases(rows, cases):
    _require(type(cases) is dict and set(cases) == set(rows), 'case_union')
    for identity, observation in cases.items():
        _require(values.canonical_digest(observation) == rows[identity]['observation_sha256'], 'observation_binding')


def shard_cases(plan, cases, *, index, count):
    """Partition captured evidence deterministically; do not claim execution."""
    rows = _plan_rows(plan)
    _check_cases(rows, cases)
    _require(type(index) is int and type(count) is int
             and 1 <= count <= min(MAX_SHARDS, len(rows)) and 0 <= index < count, 'shard_index')
    return {'index': index, 'count': count, 'plan_sha256': plan.digest(),
            'cases': {identity: rv.freeze(cases[identity]).to_plain()
                      for identity in sorted(rows)[index::count]}}


def join_shards(plan, shards):
    """Require the exact disjoint planned union, including each shard position."""
    rows = _plan_rows(plan)
    _require(type(shards) is list and 1 <= len(shards) <= min(MAX_SHARDS, len(rows)), 'shards')
    cases, seen = {}, set()
    for shard in shards:
        _shape(shard, ('index', 'count', 'plan_sha256', 'cases'), 'shard_shape')
        index, count = shard['index'], shard['count']
        _require(type(index) is int and type(count) is int and count == len(shards)
                 and 0 <= index < count and index not in seen, 'shard_index')
        _require(shard['plan_sha256'] == plan.digest(), 'shard_plan')
        selected = {identity: rows[identity] for identity in sorted(rows)[index::count]}
        _check_cases(selected, shard['cases'])
        seen.add(index)
        cases.update(shard['cases'])
    _check_cases(rows, cases)
    return rv.freeze(cases).to_plain()


def _source_binding(sources, runtime_source_hashes):
    _require(type(sources) is dict and bool(sources)
             and type(runtime_source_hashes) is dict and bool(runtime_source_hashes), 'sources')
    for path, digest in runtime_source_hashes.items():
        _require(type(path) is str and path and not path.startswith('/')
                 and all(part not in ('', '.', '..') for part in path.split('/'))
                 and '\\' not in path and _sha(digest), 'runtime_source_path')
    _require(set(sources) == {p for p in runtime_source_hashes if p.endswith('.py')}, 'python_source_scope')
    for path, source in sources.items():
        _require(type(source) is str and hashlib.sha256(source.encode('utf-8')).hexdigest()
                 == runtime_source_hashes[path], 'source_hash')


def _host_binding(plan, runtime_source_hashes, host_report, stdout, stderr):
    _shape(host_report, ('schema', 'execution_mode', 'plan_sha256', 'source_before', 'source_after',
                        'exit_code', 'cleanup', 'cases', 'stdout_sha256', 'stderr_sha256'), 'host_shape')
    _require(host_report['schema'] == 'orch-dork/development-manifest-replay-host/v1'
             and host_report['execution_mode'] == 'captured_replay', 'host_mode')
    _require(host_report['plan_sha256'] == plan.digest()
             and host_report['cases'] == sorted(_plan_rows(plan)), 'host_case_binding')
    _require(rv.freeze(host_report['source_before']) == rv.freeze(runtime_source_hashes)
             and rv.freeze(host_report['source_after']) == rv.freeze(runtime_source_hashes), 'host_source_binding')
    _require(type(host_report['exit_code']) is int and host_report['exit_code'] == 0
             and host_report['cleanup'] == 'observed_complete', 'host_exit')
    for output, field in ((stdout, 'stdout_sha256'), (stderr, 'stderr_sha256')):
        _require(type(output) is bytes and len(output) <= 65536
                 and hashlib.sha256(output).hexdigest() == host_report[field], 'host_output_binding')


def _namespace_role_binding(decision, sources):
    """Check namespace provenance against import syntax and both source files."""
    proof = decision.get('namespace_source')
    _shape(proof, ('package_path', 'package_sha256', 'module_path', 'module_sha256'), 'namespace_source')
    for kind in ('package', 'module'):
        path = proof[kind + '_path']
        _require(type(path) is str and path in sources
                 and hashlib.sha256(sources[path].encode()).hexdigest() == proof[kind + '_sha256'],
                 'namespace_source_hash')
    packages = [path for path in sources if path == 'lifecycle_conformance/__init__.py'
                or path.endswith('/lifecycle_conformance/__init__.py')]
    _require(packages == [proof['package_path']]
             and not any(path.rsplit('/', 1)[-1] == 'lifecycle_conformance.py' for path in sources), 'namespace_package')
    _require(all(isinstance(row, ast.Pass) or isinstance(row, ast.Expr)
                 and isinstance(row.value, ast.Constant) and type(row.value.value) is str
                 for row in ast.parse(sources[proof['package_path']]).body), 'namespace_initializer')
    imports = [node for node in ast.parse(sources[decision['path']]).body
               if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == 'lifecycle_conformance'
               and type(decision['line']) is int and node.lineno == decision['line']]
    aliases = [(node, alias) for node in imports for alias in node.names
               if (alias.asname or alias.name) == decision['name']]
    _require(len(aliases) == 1, 'namespace_import')
    node, alias = aliases[0]
    _require(not alias.name.startswith('_')
             and proof['module_path'] == proof['package_path'].removesuffix('__init__.py') + alias.name + '.py'
             and decision['origin'] == 'lifecycle_conformance.' + alias.name
             and decision['import_syntax'] == ast.get_source_segment(sources[decision['path']], node), 'namespace_origin')


def _classified_checklist(sources, registry_components):
    checklist = campaign.build_coverage_checklist(sources, registry_components).to_plain()
    roles = public_pair_registry.classify_supporting_imports(sources).to_plain()
    _require(roles['source_inventory_sha256'] == checklist['source_inventory']['source_inventory_sha256'],
             'source_role_inventory')
    for identity, decision in roles['decisions'].items():
        original = checklist['obligations'].get(identity)
        _require(type(original) is dict and original['kind'] == 'symbol_role'
                 and original['status'] == 'PENDING'
                 and checklist['source_inventory']['symbols'][identity.removesuffix(':role')]['role'] == 'import_binding'
                 and decision['status'] == 'CLASSIFIED_SUPPORTING_SOURCE'
                 and decision['role'] in ('supporting_standard_library_import', 'supporting_local_module_namespace')
                 and values.canonical_digest(original) == decision['obligation_sha256'], 'source_role_obligation')
        if decision['role'] == 'supporting_local_module_namespace':
            _namespace_role_binding(decision, sources)
        checklist['obligations'][identity] = {**original, 'status': decision['status'],
            'reason': decision['rationale'], 'classification_sha256': values.canonical_digest(decision)}
    checklist['schema'] = 'orch-dork/integrated-coverage-checklist/v2'
    checklist['source_role_classification'] = roles
    checklist['classified_source_role_count'] = roles['classified_roles']
    checklist['pending_obligation_count'] = sum(row['status'] == 'PENDING' for row in checklist['obligations'].values())
    return checklist


def build_manifest(plan, cases, *, sources, runtime_source_hashes, registry_components,
                   host_report, host_stdout, host_stderr):
    """Replay pinned originals and join witnesses while retaining every gap.

    A zero captured-replay exit establishes no fresh production execution.
    The host boundary must authenticate the plan, source inventory and report
    before any future release gate can credit execution. This format always
    blocks release, including when all selected seeds replay successfully.
    """
    rows = _plan_rows(plan)
    _check_cases(rows, cases)
    _source_binding(sources, runtime_source_hashes)
    _host_binding(plan, runtime_source_hashes, host_report, host_stdout, host_stderr)
    checklist = _classified_checklist(sources, registry_components)
    paths, public, stage_witnesses = {}, [], {}
    for identity, row in sorted(rows.items()):
        if row['kind'] == 'public_pair':
            _require(type(cases[identity]) is dict and cases[identity].get('case') == row['name'], 'pair_identity')
            public.append(cases[identity])
            continue
        path = campaign.replay_integrated_path(cases[identity], profile=row['name']).to_plain()
        paths[identity] = path
        for index, boundary in enumerate(path['trace']):
            stages = {boundary['model_stage']}
            stages.update(t['stimulus']['stage'] for t in boundary['transitions'] if 'stage' in t['stimulus'])
            for stage in sorted(stages):
                obligation = 'stage:' + stage
                _require(obligation in checklist['obligations'], 'stage_obligation')
                stage_witnesses.setdefault(obligation, []).append({'case': identity, 'boundary_index': index})
    pairs = public_pair_evidence.build_evidence(sources, public).to_plain()
    return rv.freeze({'schema': 'orch-dork/development-coverage-manifest/v2',
        'status': 'REPLAY_BOUND_COVERAGE_INCOMPLETE', 'plan_sha256': plan.digest(), 'cases': rows,
        'runtime_source_inventory_sha256': values.canonical_digest(runtime_source_hashes),
        'source_hashes': runtime_source_hashes, 'registry_sha256': values.canonical_digest(registry_components),
        'coverage': checklist, 'lifecycle_paths': paths, 'stage_witnesses': stage_witnesses,
        'public_pair_evidence': pairs, 'host_report': host_report,
        'host_report_sha256': values.canonical_digest(host_report),
        'acceptance': {'selected_evidence_replay': 'PASS', 'complete_coverage': 'BLOCKED',
                       'fresh_production_execution': 'REQUIRED', 'runtime_scope_custody': 'REQUIRED',
                       'host_execution_custody': 'REQUIRED'},
        'execution_attested': False, 'release_authorized': False, 'qualification_authorized': False})


def validate_manifest(manifest, plan, cases, **inputs):
    """Readback uses the separately retained plan and original observations."""
    _require(type(manifest) is rv.FrozenValue
             and manifest == build_manifest(plan, cases, **inputs), 'manifest_binding')


def build_registry_manifest(*, sources, runtime_source_hashes, registry_components,
                            graph_registry, replay_corpus, legacy_bytes,
                            host_corpus, adapter_corpus, extension_corpus):
    """Execute pinned history/host fixtures and bind every registered case.

    History must match current model records through the independent binding
    reader; its original failed verdicts remain unchanged. Host fixtures replay
    the canonical adapters; selected tool names additionally bind current model
    action states. Other fixture mappings remain explicit obligations. The
    supplied graph is exactly the touched historical subgraph,
    never evidence that the entire reachable graph was enumerated. This entry
    point is a development component of the campaign, with no host attestation.
    """
    _require(all(type(value) is rv.FrozenValue for value in
                 (graph_registry, replay_corpus, host_corpus, adapter_corpus, extension_corpus))
             and type(legacy_bytes) is bytes, 'registry_input_type')
    _source_binding(sources, runtime_source_hashes)
    checklist = _classified_checklist(sources, registry_components)
    history = replay_bindings.bind(graph_registry, replay_corpus, legacy_bytes=legacy_bytes).to_plain()
    hosts = host_mcp_fixtures.replay_current_profile(host_corpus, adapter_corpus, extension_corpus)
    host_contexts = host_mcp_fixtures.bind_preparation_boundaries(host_corpus, adapter_corpus, extension_corpus).to_plain()
    action_names = host_contexts['action_name_evidence']
    reports = {'replays': history['historical_report'],
               'host_fixtures': hosts['legacy_report'], 'host_mcp_fixtures': hosts['extension_report']}
    owners = {'replays': replays.OWNER, 'host_fixtures': host_fixtures.OWNER,
              'host_mcp_fixtures': host_mcp_fixtures.OWNER}
    components = []
    for name, report in reports.items():
        actual = {identity: record for rows in report['registry'].values() for identity, record in rows.items()}
        _require(rv.freeze(actual) == rv.freeze(registry_components[name]), 'executed_registry_binding')
        components.append(catalog.component(owners[name], report['registry'], report['coverage'], report))
    joined = catalog.build_catalog(components).to_plain()
    graph = graph_registry.to_plain()
    touched_states = {state for row in history['bindings'] for state in row['states']}
    touched_edges = {edge for row in history['bindings'] for edge in row['transitions']}
    _require(touched_states == set(graph['lc-state']) and touched_edges == set(graph['lc-trans']),
             'unexplained_graph_records')
    witnesses = {}

    def bind(component, item, case, evidence):
        identity = 'registry:' + component + ':' + item
        _require(identity in checklist['obligations'] and identity not in witnesses, 'registry_witness_identity')
        _require(case in joined['cases'] and item in joined['cases'][case]['items'], 'registry_case_binding')
        witnesses[identity] = {'case': case, 'item': item,
            'record_sha256': checklist['obligations'][identity]['record_sha256'], **evidence}

    historical_results = {row['case_id']: row for row in reports['replays']['cycles']}
    for row in history['bindings']:
        case = row['replay'].removeprefix('lc-replay:issue-167:')
        _require(case in historical_results, 'historical_case')
        original = historical_results[case]
        _require(values.canonical_digest(original) == row['historical_result_sha256'], 'historical_result')
        evidence = {'scope': 'normalized_history_to_current_model',
            'result_sha256': row['historical_result_sha256'], 'target': row['target'],
            'states': row['states'], 'transitions': row['transitions'],
            'original_host_validator_reexecuted': False}
        bind('replays', row['replay'], case, evidence)
        bind('replays', row['historical_mapping'], case, evidence)
    for component in ('host_fixtures', 'host_mcp_fixtures'):
        for row in reports[component]['cases']:
            item = row['item']
            selected = item in host_contexts['bindings']
            mapping = host_contexts['bindings'].get(item, host_contexts['pending'].get(item))
            _require(type(mapping) is dict and mapping['case'] == row['case'] and mapping['item'] == item,
                     'host_model_case_binding')
            if selected:
                _require(mapping['observation_sha256'] == row['observation_sha256']
                         and values.canonical_digest(mapping['observation']) == row['observation_sha256'],
                         'host_model_observation_binding')
            bind(component, row['item'], row['case'], {'scope': 'canonical_host_fixture_replay',
                 'observation_sha256': row['observation_sha256'],
                 'model_state_binding': ('SELECTED_ACTION_STATES_BOUND' if item in action_names['bindings'] else
                                         'SELECTED_UNADMITTED_STATES_BOUND' if selected else 'REQUIRED'),
                 'model_mapping': mapping})
    host_items = {row['item'] for component in ('host_fixtures', 'host_mcp_fixtures')
                  for row in reports[component]['cases']}
    _require(set(host_contexts['bindings']).isdisjoint(host_contexts['pending'])
             and set(host_contexts['bindings']) | set(host_contexts['pending']) == host_items, 'host_model_union')
    expected = {'registry:' + name + ':' + item for name in reports for item in registry_components[name]}
    _require(set(witnesses) == expected, 'registry_witness_union')
    return rv.freeze({'schema': 'orch-dork/development-registry-manifest/v4',
        'status': 'REGISTERED_REPLAYS_BOUND_COVERAGE_INCOMPLETE',
        'runtime_source_inventory_sha256': values.canonical_digest(runtime_source_hashes),
        'source_hashes': runtime_source_hashes, 'registry_sha256': values.canonical_digest(registry_components),
        'input_digests': {'graph_registry': graph_registry.digest(), 'replay_corpus': replay_corpus.digest(),
            'legacy_bytes': hashlib.sha256(legacy_bytes).hexdigest(), 'host_corpus': host_corpus.digest(),
            'adapter_corpus': adapter_corpus.digest(), 'extension_corpus': extension_corpus.digest()},
        'graph_registry': graph, 'historical_binding': history, 'host_profile': hosts,
        'host_action_bindings': action_names,
        'host_context_bindings': host_contexts,
        'catalog': joined, 'coverage': checklist, 'witnesses': witnesses,
        'acceptance': {'registered_case_replay': 'PASS', 'history_current_graph_binding': 'PASS',
            'host_fixture_model_binding': 'REQUIRED', 'complete_graph': 'REQUIRED',
            'complete_coverage': 'BLOCKED', 'host_execution_custody': 'REQUIRED'},
        'execution_attested': False, 'release_authorized': False, 'qualification_authorized': False})


def validate_registry_manifest(manifest, **inputs):
    """Re-execute from pinned originals; a supplied report cannot attest itself."""
    _require(type(manifest) is rv.FrozenValue
             and manifest == build_registry_manifest(**inputs), 'registry_manifest_binding')


def _paired_return_sites(checklist, evidence):
    """Account for one accepted value at an exact site, without branch closure."""
    coordinates = ('line', 'column', 'end_line', 'end_column')
    decisions, unresolved, selected = {}, [], set()
    for pair_id, pair in sorted(evidence['pairs'].items()):
        producer = pair['declaration']['producer']
        symbol = producer['path'] + '#' + producer['name']
        binding = checklist['source_inventory']['symbols'].get(symbol)
        _require(type(binding) is dict and binding['role'] in ('function_definition', 'method_definition')
                 and binding['source_sha256'] == producer['source_sha256'], 'public_return_source')
        sites = {identity: row for identity, row in checklist['obligations'].items()
                 if identity.startswith(symbol + ':return:') and row['kind'] == 'return_site'}
        expected_sites = [{key: row[key] for key in coordinates}
                          for row in sorted(sites.values(), key=lambda row: (row['line'], row['column']))]
        _require(rv.freeze(pair['declared_return_sites']) == rv.freeze(expected_sites), 'public_return_inventory')
        selected.update(sites)
        for output in pair['outputs']:
            case = output['case']
            _require(case in evidence['cases'], 'public_return_case')
            span = output['return_instruction_span']
            reason = ('validator_internal' if output['enclosing_validator_sequences'] else
                      'unmatched_output' if not output['validator_sequences'] else
                      'ambiguous_return_span' if rv.freeze(span) not in [rv.freeze(site) for site in expected_sites]
                      else None)
            if reason is not None:
                unresolved.append({'pair': pair_id, 'case': case,
                    'producer_sequence': output['producer_sequence'], 'reason': reason})
                continue
            identity = symbol + ':return:' + str(span['line']) + ':' + str(span['column'])
            original = sites[identity]
            _require(original['status'] == 'PENDING' and original['source_sha256'] == producer['source_sha256'],
                     'public_return_obligation')
            decision = decisions.setdefault(identity, {
                'path': producer['path'], 'name': producer['name'], 'source_sha256': producer['source_sha256'],
                'site': {key: original[key] for key in coordinates},
                'obligation_sha256': values.canonical_digest(original),
                'status': 'OBSERVED_ACCEPTED_RETURN_SITE', 'witnesses': [],
                'reason': 'At least one direct whole output from this exact return site reached an accepting '
                          'paired consumer; other values, consumers and control-flow alternatives remain separate.'})
            decision['witnesses'].append({'pair': pair_id, 'case': case,
                'case_observation_sha256': evidence['cases'][case]['observation_sha256'],
                **{key: output[key] for key in ('producer_sequence', 'value_sha256', 'validator_sequences')}})
    return {'schema': 'orch-dork/observed-public-pair-return-sites/v1',
        'source_inventory_sha256': checklist['source_inventory']['source_inventory_sha256'],
        'pair_evidence_sha256': values.canonical_digest(evidence), 'decisions': decisions,
        'unresolved_observations': unresolved, 'pending_selected_return_sites': sorted(selected - set(decisions)),
        'pass_branches_closed': False, 'all_paired_consumers_closed': False,
        'execution_attested': False, 'qualification_authorized': False}


def _paired_checklist(lifecycle, sources, observations):
    """Join declared source roles; runtime binding and branch closure stay open."""
    evidence = lifecycle['public_pair_evidence']
    expected_roles, expected_seeds = {}, {}
    for pair_id, pair in sorted(evidence['pairs'].items()):
        for role in ('producer', 'validator'):
            reference = pair['declaration'][role]
            symbol = reference['path'] + '#' + reference['name']
            expected_roles.setdefault(symbol, {}).setdefault(role, []).append(pair_id)
        witnesses = [row for row in pair['outputs'] if row['validator_sequences']
                     and not row['enclosing_validator_sequences']]
        expected_seeds[pair_id] = {'witnesses': witnesses, 'seed_present': bool(witnesses)}
    modules = sorted({symbol.split('#', 1)[0] for symbol in expected_roles})
    roles = public_pair_registry.build_registry(sources, observations, modules=modules).to_plain()
    checklist = rv.freeze(lifecycle['coverage']).to_plain()
    inventory = checklist['source_inventory']
    _require(roles['inventory_sha256'] == inventory['source_inventory_sha256']
             and roles['evidence_sha256'] == values.canonical_digest(evidence), 'public_role_inputs')
    _require(set(roles['modules']) == set(modules)
             and roles['pending_modules'] == sorted(set(sources) - set(modules)), 'public_role_modules')
    reported = {symbol: row['roles'] for module in roles['modules'].values()
                for symbol, row in module['symbols'].items() if row['kind'] == 'paired_function'}
    _require(rv.freeze(reported) == rv.freeze(expected_roles)
             and rv.freeze(roles['pair_seeds']) == rv.freeze(expected_seeds),
             'public_role_declarations')
    _require(rv.freeze(roles['evidence_gaps']) == rv.freeze(evidence['gaps'])
             and all(roles[key] is False for key in ('module_selection_verified', 'execution_attested',
                                                    'pass_branches_closed', 'qualification_authorized')),
             'public_role_scope')
    decisions, pending = {}, {}
    for symbol, declared in sorted(expected_roles.items()):
        identity = symbol + ':role'
        original = checklist['obligations'].get(identity)
        binding = inventory['symbols'].get(symbol)
        path, name = symbol.split('#', 1)
        _require(type(original) is dict and original['kind'] == 'symbol_role'
                 and original['status'] == 'PENDING' and type(binding) is dict
                 and binding['role'] in ('function_definition', 'method_definition')
                 and original['source_sha256'] == binding['source_sha256']
                 == roles['modules'][path]['source_sha256'], 'public_role_obligation')
        pair_ids = sorted({pair for pairs in declared.values() for pair in pairs})
        missing = [pair for pair in pair_ids if not expected_seeds[pair]['seed_present']]
        if missing:
            pending[identity] = {'roles': declared, 'missing_seed_pairs': missing}
            continue
        decision = {key: original[key] for key in ('path', 'source_sha256', 'line')}
        decision.update(name=name, roles=declared, status='CLASSIFIED_DECLARED_LIFECYCLE_ROLE',
            obligation_sha256=values.canonical_digest(original),
            seed_sha256={pair: values.canonical_digest(expected_seeds[pair]) for pair in pair_ids},
            rationale='Declared source function role with direct whole-output acceptance seed; '
                      'runtime binding, module effects and all branch/return obligations remain separate.')
        decisions[identity] = decision
        checklist['obligations'][identity] = {**original, 'status': decision['status'],
            'reason': decision['rationale'], 'classification_sha256': values.canonical_digest(decision)}
    checklist['schema'] = 'orch-dork/integrated-coverage-checklist/v4'
    checklist['public_pair_role_classification'] = {
        'schema': 'orch-dork/declared-public-pair-role-classification/v1',
        'source_inventory_sha256': inventory['source_inventory_sha256'],
        'registry_sha256': values.canonical_digest(roles), 'decisions': decisions,
        'pending_seed_roles': pending, 'runtime_role_verified': False,
        'pass_branches_closed': False, 'execution_attested': False, 'qualification_authorized': False}
    checklist['classified_source_role_count'] += len(decisions)
    returns = _paired_return_sites(checklist, evidence)
    for identity, decision in returns['decisions'].items():
        checklist['obligations'][identity] = {**checklist['obligations'][identity],
            'status': decision['status'], 'reason': decision['reason'],
            'classification_sha256': values.canonical_digest(decision)}
    checklist['paired_return_site_classification'] = returns
    checklist['observed_paired_return_site_count'] = len(returns['decisions'])
    checklist['pending_obligation_count'] = sum(row['status'] == 'PENDING' for row in checklist['obligations'].values())
    return checklist, roles


def build_joined_manifest(plan, cases, *, registry_inputs,
                          production_graph_inputs=None, **lifecycle_inputs):
    """Join execution components and source roles over one exact inventory.

    The lifecycle host report binds only its selected captured-replay cases.
    Registry fixture execution has its own input digests and case inventory;
    the enclosing host must observe that execution separately. Neither report
    grants authenticated execution custody or complete campaign acceptance.
    Combined coverage adds seeded function roles and exact accepted return sites
    to the narrower components. Every control-flow and custody obligation survives.
    """
    _shape(registry_inputs, ('graph_registry', 'replay_corpus', 'legacy_bytes',
                            'host_corpus', 'adapter_corpus', 'extension_corpus'), 'registry_inputs')
    lifecycle = build_manifest(plan, cases, **lifecycle_inputs).to_plain()
    registry = build_registry_manifest(**registry_inputs,
        **{key: lifecycle_inputs[key] for key in ('sources', 'runtime_source_hashes', 'registry_components')}).to_plain()
    _require(rv.freeze(lifecycle['coverage']) == rv.freeze(registry['coverage']), 'joined_inventory')
    public = [cases[identity] for identity, row in sorted(lifecycle['cases'].items()) if row['kind'] == 'public_pair']
    coverage, public_roles = _paired_checklist(lifecycle, lifecycle_inputs['sources'], public)
    result = {'schema': 'orch-dork/development-integrated-manifest/v6',
        'status': 'SELECTED_EVIDENCE_BOUND_COVERAGE_INCOMPLETE',
        'runtime_source_inventory_sha256': lifecycle['runtime_source_inventory_sha256'],
        'registry_sha256': lifecycle['registry_sha256'],
        'lifecycle_evidence': lifecycle, 'registry_evidence': registry,
        'coverage': coverage, 'public_pair_registry': public_roles,
        'acceptance': {'complete_coverage': 'BLOCKED', 'host_fixture_model_binding': 'REQUIRED',
            'complete_graph': 'REQUIRED', 'host_execution_custody': 'REQUIRED'},
        'execution_attested': False, 'release_authorized': False,
        'qualification_authorized': False}
    if production_graph_inputs is not None:
        _shape(production_graph_inputs, ('observations',),
               'production_graph_inputs')
        from lifecycle_conformance import production_graph_evidence
        graph_evidence = production_graph_evidence.build_evidence(
            lifecycle_inputs['sources'],
            production_graph_inputs['observations'],
        )
        graph = graph_evidence.to_plain()
        _shape(graph, (
            'schema', 'status', 'prefix_evidence',
            'prefix_evidence_sha256', 'path_reconciliation',
            'path_reconciliation_sha256', 'gaps',
            'production_path_reconciliation_complete',
            'model_graph_complete', 'production_graph_complete',
            'retained_owner_authentication', 'chronology_attested',
            'capture_authenticated', 'host_execution_custody',
            'controller_continuation_authorized', 'execution_attested',
            'complete_campaign', 'release_authorized',
            'qualification_authorized',
        ), 'production_graph_scope')
        prefix = graph['prefix_evidence']
        reconciliation = graph['path_reconciliation']
        _require(type(prefix) is dict and type(reconciliation) is dict,
                 'production_graph_scope')
        frozen_prefix = rv.freeze(prefix)
        frozen_reconciliation = rv.freeze(reconciliation)
        runtime_hashes = lifecycle_inputs['runtime_source_hashes']
        runtime_python_hashes = {
            path: digest for path, digest in sorted(runtime_hashes.items())
            if path.endswith('.py')
        }
        _require(graph.get('schema')
                 == production_graph_evidence.EVIDENCE_SCHEMA
                 and graph.get('status')
                 == 'UNATTESTED_PREFIX_RECONSTRUCTIONS_INCOMPLETE'
                 and graph.get('gaps') == [{
                     'obligation':
                         'derivation:reachable_states_and_interleavings',
                     'status': 'CLOSED',
                 }]
                 and graph.get('production_path_reconciliation_complete')
                 is True
                 and graph.get('model_graph_complete') is False
                 and graph.get('production_graph_complete') is False
                 and graph.get('retained_owner_authentication') is False
                 and graph.get('chronology_attested') is False
                 and graph.get('capture_authenticated') is False
                 and graph.get('host_execution_custody') is False
                 and graph.get('controller_continuation_authorized') is False
                 and graph.get('execution_attested') is False
                 and graph.get('complete_campaign') is False
                 and graph.get('release_authorized') is False
                 and graph.get('qualification_authorized') is False,
                 'production_graph_scope')
        _require(
            prefix.get('schema')
            == production_graph_evidence.PREFIX_EVIDENCE_SCHEMA
            and graph['prefix_evidence_sha256'] == frozen_prefix.digest()
            and reconciliation.get('schema')
            == production_graph_evidence.RECONCILIATION_SCHEMA
            and reconciliation.get('status') == 'CLOSED'
            and reconciliation.get('obligation') == {
                'id': 'derivation:reachable_states_and_interleavings',
                'status': 'CLOSED',
                'scope': 'production_paths_and_readiness_interleavings',
            }
            and reconciliation.get('gaps') == []
            and reconciliation.get(
                'production_path_reconciliation_complete') is True
            and reconciliation.get('model_graph_complete') is False
            and reconciliation.get('production_graph_complete') is False
            and all(reconciliation.get(field) is False for field in (
                'retained_owner_authentication', 'chronology_attested',
                'capture_authenticated', 'host_execution_custody',
                'controller_continuation_authorized', 'execution_attested',
                'complete_campaign', 'release_authorized',
                'qualification_authorized',
            ))
            and graph['path_reconciliation_sha256']
            == frozen_reconciliation.digest()
            and reconciliation.get('reconciliation_sha256')
            == values.canonical_digest({
                key: value for key, value in reconciliation.items()
                if key != 'reconciliation_sha256'
            })
            and reconciliation.get('source_evidence', {}).get(
                'evidence_sha256') == frozen_prefix.digest()
            and reconciliation.get('source_evidence', {}).get(
                'source_inventory_sha256')
            == prefix.get('source_inventory_sha256')
            and reconciliation.get('source_evidence', {}).get(
                'input_sha256s_sha256')
            == values.canonical_digest(prefix.get('input_sha256s')),
            'production_graph_reconciliation_binding',
        )
        production_graph_evidence._reconciliation_evidence_plain(
            frozen_prefix)
        _require(
            frozen_reconciliation
            == production_graph_evidence._reconcile_validated_evidence(
                frozen_prefix),
            'production_graph_reconciliation_readback',
        )
        _require(all(path in runtime_python_hashes for path in
                     production_graph_evidence.SOURCE_PATHS),
                 'production_graph_source_binding')
        direct_source_hashes = {
            path: runtime_python_hashes[path]
            for path in production_graph_evidence.SOURCE_PATHS
        }
        _require(lifecycle['runtime_source_inventory_sha256']
                 == values.canonical_digest(runtime_hashes)
                 and prefix['source_inventory_sha256']
                 == values.canonical_digest(runtime_python_hashes)
                 and prefix['source_hashes'] == direct_source_hashes,
                 'production_graph_source_binding')
        production_graph_evidence.validate_evidence(
            graph_evidence, lifecycle_inputs['sources'],
            production_graph_inputs['observations'])
        source_binding = {
            'schema':
                'orch-dork/production-graph-runtime-source-binding/v1',
            'runtime_source_inventory_sha256':
                lifecycle['runtime_source_inventory_sha256'],
            'runtime_python_source_inventory_sha256':
                values.canonical_digest(runtime_python_hashes),
            'production_graph_source_inventory_sha256':
                prefix['source_inventory_sha256'],
            'production_graph_direct_source_hashes_sha256':
                values.canonical_digest(direct_source_hashes),
        }
        reconciled_coverage = rv.freeze(coverage).to_plain()
        derivation = reconciled_coverage['obligations'].get(
            'derivation:reachable_states_and_interleavings'
        )
        _require(type(derivation) is dict
                 and derivation.get('status') == 'PENDING',
                 'production_graph_derivation_pending')
        derivation.update(
            status='CLOSED',
            evidence_schema=production_graph_evidence.RECONCILIATION_SCHEMA,
            evidence_sha256=graph['path_reconciliation_sha256'],
            scope='production_paths_and_readiness_interleavings',
        )
        reconciled_coverage['pending_obligation_count'] = sum(
            row.get('status') == 'PENDING'
            for row in reconciled_coverage['obligations'].values())
        result.update(
            schema='orch-dork/development-integrated-manifest/v8',
            coverage=reconciled_coverage,
            complete_campaign=False,
            production_graph_reconciliation_complete=True,
            production_graph_evidence=graph,
            production_graph_evidence_sha256=values.canonical_digest(graph),
            production_graph_runtime_source_binding=source_binding,
        )
    return rv.freeze(result)


def validate_joined_manifest(manifest, plan, cases, **inputs):
    """Rebuild both components from their complete separately retained inputs."""
    _require(type(manifest) is rv.FrozenValue
             and manifest == build_joined_manifest(plan, cases, **inputs), 'joined_manifest_binding')


def build_completion_manifest(evidence, *, sources, registry_components,
                              host_runs=None, consumption_anchor=None):
    """Build the aggregate while preserving older limited manifest semantics."""
    from lifecycle_conformance import completion_gate
    return completion_gate.build_completion_report(
        evidence, sources=sources, registry_components=registry_components,
        host_runs=host_runs, consumption_anchor=consumption_anchor)


def validate_completion_manifest(manifest, evidence, *, sources, registry_components,
                                 host_runs=None, consumption_anchor=None):
    """Validate the aggregate through the same independent rebuild contract."""
    from lifecycle_conformance import completion_gate
    completion_gate.validate_completion_report(
        manifest, evidence, sources=sources, registry_components=registry_components,
        host_runs=host_runs, consumption_anchor=consumption_anchor)
