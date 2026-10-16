"""Fail-closed Issue 170 campaign-completion and consumption contract.

The gate distinguishes a validated component from a completed requirement.
Historical development manifests remain useful inputs with their original
false authority intact. Future production evidence must gain a fixed,
repository-owned reader here before it can contribute closure facts.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from lifecycle_conformance import reference_values as rv, values


EVIDENCE_SCHEMA = 'orch-dork/lifecycle-campaign-completion-evidence/v1'
REPORT_SCHEMA = 'orch-dork/lifecycle-campaign-completion/v1'
COMPONENT_SCHEMA = 'orch-dork/lifecycle-campaign-component/v1'
CASE_PREFIX = 'i170-case:'
_SHA = re.compile(r'[0-9a-f]{64}')

# Fixed repository readers. Entries marked integration-required are declared
# root touchpoints, not callable extension hooks.
COMPONENT_VALIDATORS = {
    'integrated_campaign': 'campaign.validate_integrated_campaign',
    'development_coverage_manifest': 'coverage_manifest.validate_manifest',
    'development_registry_manifest': 'coverage_manifest.validate_registry_manifest',
    'development_joined_manifest': 'coverage_manifest.validate_joined_manifest',
    'public_pair_evidence': 'public_pair_evidence.validate_evidence',
    'public_pair_registry': 'public_pair_registry.validate_registry',
    'supporting_source_roles': 'public_pair_registry.validate_supporting_imports',
    'model_graph_coverage': 'cartesian.walk_contexts + explorer.validate_coverage',
    'injection_campaign': 'injection_campaign.run/readback',
    'injection_matrix_readback': 'cartesian.walk_contexts + matrix_readback.validate_output_integrity',
    'production_campaign': 'production_campaign.validate_production_campaign + completion_facts',
    'host_attested_campaign': 'host_attestation.readback + completion_facts',
    'source_scope_closure': 'source_scope_closure.validate_complete_scope',
    'test_run_attestation': 'host_attestation.readback + validate_test_run_set',
    'candidate_identity_transition': 'candidate_identity.validate_cachebuster_identity_transition + consumption.read_store',
    'release_consumption': 'release_execution.release_report + completion_facts',
    'live_attempt_consumption': 'live_attempt_consumption.validate_campaign_consumption + consumption.read_store',
}
_IMPLEMENTED_KINDS = frozenset({
    'integrated_campaign', 'development_coverage_manifest',
    'development_registry_manifest', 'development_joined_manifest',
    'public_pair_evidence', 'public_pair_registry', 'supporting_source_roles',
    'model_graph_coverage', 'injection_campaign', 'injection_matrix_readback',
    'host_attested_campaign', 'test_run_attestation', 'candidate_identity_transition',
    'source_scope_closure', 'live_attempt_consumption', 'release_consumption',
    'production_campaign',
})
_FACT_PRODUCERS = frozenset({
    'development_registry_manifest', 'development_joined_manifest',
    'model_graph_coverage', 'injection_matrix_readback',
    'host_attested_campaign', 'test_run_attestation', 'candidate_identity_transition',
    'source_scope_closure', 'live_attempt_consumption', 'release_consumption',
    'production_campaign',
})
_FRESH_KINDS = frozenset({'host_attested_campaign', 'test_run_attestation',
                          'candidate_identity_transition', 'live_attempt_consumption',
                          'release_consumption', 'production_campaign'})
# These records describe effects that occur only after the consumption store
# retained its pre-effect campaign receipt.  They remain fixed, fresh
# components and are fully validated above before reconstruction excludes them.
_POST_STORE_COMPONENT_KINDS = frozenset({
    'candidate_identity_transition', 'release_consumption', 'live_attempt_consumption',
})
_REGISTRY_COMPONENTS = frozenset({
    'replays', 'host_fixtures', 'host_mcp_fixtures', 'injection_sites', 'injection_schedule',
})
# Fixed transitive source boundary for the reference walker and its reducers.
# These are implementation files, not a caller-selectable model/profile.
_MODEL_SOURCES = (
    'cartesian', 'explorer', 'failure_injection', 'fragment', 'injection_oracle',
    'injection_sites', 'model', 'protocol', 'reference_model', 'reference_values',
    'registries', 'values',
)

# Facts are finer-grained than reports. A limited report cannot be relabelled
# as proof of a whole ticket criterion.
REQUIREMENTS = (
    ('production_graph', ('model_graph_complete',
                          'production_graph_reconciliation_complete',
                          'production_graph_complete'),
     'Every reachable state and relevant two-lane interleaving must agree in the pure model and production.'),
    ('injection_cartesian', ('applicable_injection_complete', 'production_injection_complete'),
     'Every applicable before/after injection must run across the declared state/site Cartesian product.'),
    ('replay_host_mapping', ('all_replays_bound', 'all_host_fixtures_bound', 'host_model_mapping_complete'),
     'All historical replays and host fixtures must map exactly once to current model identifiers.'),
    ('public_semantic_families', ('public_inventory_complete', 'public_pass_partitions_complete',
                                  'legacy_public_pairs_complete'),
     'Every exported lifecycle constructor/validator PASS partition, including legacy pairs, must execute.'),
    ('source_export_effect_scope', ('source_scope_complete', 'exports_classified', 'effects_classified'),
     'The complete frozen source inventory must classify exports, aliases, bindings, and effects.'),
    ('canonical_coverage', ('coverage_union_complete', 'external_boundaries_exact'),
     'The canonical manifest must bind every finite obligation to validated executed evidence.'),
    ('negative_gaps_and_shards', ('negative_gap_matrix_complete', 'shard_union_complete'),
     'Planted gaps, stale/changed/duplicate evidence, and shard-union negatives must be observed.'),
    ('host_custody', ('host_attestation_valid', 'runtime_identity_attested',
                      'source_custody_complete', 'output_custody_complete',
                      'exit_custody_complete', 'cleanup_custody_complete'),
     'The fixed host reader must bind source, output, exit, and cleanup custody for all executed cases.'),
    ('identical_runtime_tests', ('focused_tests_same_runtime', 'rehearsal_same_runtime',
                                 'full_suite_same_runtime'),
     'Focused, rehearsal, and full-suite host receipts must bind identical pre-cachebuster runtime bytes.'),
    ('candidate_transition', ('candidate_identity_transition_valid', 'candidate_consumed_once'),
     'One cachebuster-only transition must bind distinct exact pre/post package identities.'),
    ('release_install_consumption', ('release_host_consumed', 'install_parity_mcp_consumed'),
     'Release host, sole install, projected parity, and MCP checks must consume the campaign once.'),
    ('live_attempt_consumption', ('fresh_live_attempt_consumed_once', 'terminal_live_result_preserved'),
     'One fresh qualification must consume the candidate and preserve its terminal result without retry.'),
)
PROVIDER_FREE_REQUIREMENTS = tuple(row[0] for row in REQUIREMENTS[:9])
_ALL_FACTS = frozenset(fact for _, facts, _ in REQUIREMENTS for fact in facts)
FACT_COMPONENTS = {
    'model_graph_complete': ('model_graph_coverage',),
    'production_graph_reconciliation_complete':
        ('development_joined_manifest',),
    'production_graph_complete': ('production_campaign',),
    'applicable_injection_complete': ('injection_matrix_readback',),
    'production_injection_complete': ('production_campaign',),
    'all_replays_bound': ('development_registry_manifest',),
    'all_host_fixtures_bound': ('development_registry_manifest',),
    'host_model_mapping_complete': ('production_campaign',),
    'public_inventory_complete': ('source_scope_closure',),
    'public_pass_partitions_complete': ('production_campaign',),
    'legacy_public_pairs_complete': ('production_campaign',),
    'source_scope_complete': ('source_scope_closure',),
    'exports_classified': ('source_scope_closure',),
    'effects_classified': ('source_scope_closure',),
    'coverage_union_complete': ('production_campaign', 'source_scope_closure'),
    'external_boundaries_exact': ('production_campaign',),
    'negative_gap_matrix_complete': ('production_campaign',),
    'shard_union_complete': ('production_campaign',),
    'host_attestation_valid': ('host_attested_campaign',),
    'runtime_identity_attested': ('host_attested_campaign',),
    'source_custody_complete': ('host_attested_campaign',),
    'output_custody_complete': ('host_attested_campaign',),
    'exit_custody_complete': ('host_attested_campaign',),
    'cleanup_custody_complete': ('host_attested_campaign',),
    'focused_tests_same_runtime': ('test_run_attestation',),
    'rehearsal_same_runtime': ('test_run_attestation',),
    'full_suite_same_runtime': ('test_run_attestation',),
    'candidate_identity_transition_valid': ('candidate_identity_transition',),
    'candidate_consumed_once': ('candidate_identity_transition',),
    'release_host_consumed': ('release_consumption',),
    'install_parity_mcp_consumed': ('release_consumption',),
    'fresh_live_attempt_consumed_once': ('live_attempt_consumption',),
    'terminal_live_result_preserved': ('live_attempt_consumption',),
}
_require_fact_mapping_complete = set(FACT_COMPONENTS) == set(_ALL_FACTS)


def _require(condition, reason):
    if condition is not True:
        raise values.LifecycleContractError('completion_gate:' + reason)


def _plain(value):
    return value.to_plain() if type(value) is rv.FrozenValue else value


def _digest(value):
    return values.canonical_digest(_plain(value))


def _frozen(value):
    return value if type(value) is rv.FrozenValue else rv.freeze(value)


def case_identity(kind, material):
    """Return the stable content-derived identity of one preserved case."""
    _require(type(kind) is str and kind in COMPONENT_VALIDATORS, 'component_kind')
    _require(type(material) is dict, 'component_material')
    return CASE_PREFIX + values.canonical_digest({'kind': kind, 'material': material})


def _source_identity(sources, runtime):
    _require(type(sources) is dict and bool(sources), 'sources')
    _require(type(runtime) is dict and set(runtime) == {
        'runtime_entry_hashes', 'python_source_hashes', 'runtime_inventory_sha256',
        'manifest_sha256', 'package_digest_before_cachebuster',
        'version_before_cachebuster'}, 'runtime_shape')
    expected = {}
    for path, source in sources.items():
        _require(type(path) is str and path and type(source) is str, 'source_entry')
        expected[path] = hashlib.sha256(source.encode('utf-8')).hexdigest()
    python_hashes = runtime['python_source_hashes']
    _require(type(python_hashes) is dict and bool(python_hashes)
             and all(expected.get(path) == digest for path, digest in python_hashes.items()),
             'runtime_source_hashes')
    entries = runtime['runtime_entry_hashes']
    _require(type(entries) is dict and bool(entries)
             and set(python_hashes) == {p for p in entries if type(p) is str and p.endswith('.py')},
             'runtime_entry_scope')
    for path, digest in entries.items():
        _require(type(path) is str and path and type(digest) is str
                 and _SHA.fullmatch(digest) is not None, 'runtime_entry')
    _require(all(entries[path] == digest for path, digest in python_hashes.items()),
             'runtime_python_entry_binding')
    if set(expected) != set(python_hashes):
        # Broader plugin sources are a distinct inventory, never additions to
        # the runtime allowlist or a caller-selected subset of source scope.
        from lifecycle_conformance import source_scope_closure
        snapshot = source_scope_closure.read_source_snapshot()
        _require(sources == snapshot['sources'] and runtime == snapshot['runtime'],
                 'complete_source_snapshot_binding')
    _require(runtime['runtime_inventory_sha256'] == values.canonical_digest(entries),
             'runtime_inventory')
    _require(entries.get('.codex-plugin/plugin.json') == runtime['manifest_sha256'],
             'runtime_manifest_entry')
    for field in ('manifest_sha256', 'package_digest_before_cachebuster'):
        _require(type(runtime[field]) is str and _SHA.fullmatch(runtime[field]) is not None,
                 'runtime_digest')
    _require(type(runtime['version_before_cachebuster']) is str
             and bool(runtime['version_before_cachebuster']), 'runtime_version')
    return expected


def _component_shape(record):
    _require(type(record) is dict and set(record) == {
        'schema', 'case_id', 'kind', 'material', 'originals'}, 'component_shape')
    _require(record['schema'] == COMPONENT_SCHEMA, 'component_schema')
    _require(record['case_id'] == case_identity(record['kind'], record['material']),
             'case_identity')
    _require(type(record['originals']) is dict, 'component_originals')


def _component_generation(record, sources, runtime, registry_components):
    """Bind the retained generation before any reader can contribute facts.

    Fact-producing component originals require ``generation`` containing whole
    sources, runtime and registry_components, sealed by generation_sha256 in
    material (and hence the content-derived case ID). This supplies equality
    and freshness bindings, not host authenticity. Host custody stays separate.
    """
    generation = record['originals'].get('generation')
    _require(type(generation) is dict and set(generation) == {
        'sources', 'runtime', 'registry_components'}, 'component_generation_required')
    _require(record['material'].get('generation_sha256') == _digest(generation),
             'component_generation_digest')
    _require(_frozen(generation['sources']) == _frozen(sources), 'component_source_binding')
    _require(_frozen(generation['runtime']) == _frozen(runtime), 'component_runtime_binding')
    _require(_frozen(generation['registry_components']) == _frozen(registry_components),
             'component_registry_binding')
    # The existing package reader derives version, file modes/sizes and package
    # digest from this reader's checkout and its fixed runtime allowlist. No
    # caller profile or path can substitute another package. This is read-only;
    # it neither stages nor installs, and adds no host-execution attestation.
    import orch_dork_runtime_package as package
    entries, version, _ = package._projectable_source_entries(
        Path(__file__).resolve().parents[4], package.RUNTIME_ALLOWLIST)
    hashes = {entry['path']: entry['sha256'] for entry in entries}
    package_identity = package._report(version, entries)
    _require(runtime['runtime_entry_hashes'] == hashes
             and runtime['manifest_sha256'] == hashes[package.MANIFEST_PATH]
             and runtime['version_before_cachebuster'] == version
             and runtime['package_digest_before_cachebuster'] == package_identity['package_digest'],
             'component_runtime_package_binding')
    _require(set(registry_components) == _REGISTRY_COMPONENTS
             and all(type(rows) is dict and bool(rows) for rows in registry_components.values()),
             'component_registry_scope')
    # Readback executes these fixed modules. Claims about different source bytes
    # cannot acquire facts by relabelling the component's generation envelope.
    model_sources = {}
    for name in _MODEL_SOURCES:
        path = 'skills/orch-dork/scripts/lifecycle_conformance/' + name + '.py'
        actual = (Path(__file__).parent / (name + '.py')).read_bytes()
        _require(path in sources and sources[path].encode('utf-8') == actual,
                 'component_model_source_binding:' + path)
        model_sources[path] = hashlib.sha256(actual).hexdigest()
    from lifecycle_conformance import explorer, injection_sites, protocol, reference_model
    sites = injection_sites.site_registry()
    _require(_frozen(registry_components['injection_sites']) == injection_sites.inventory(sites)
             and _frozen(registry_components['injection_schedule']) == _frozen({
                 row['id']: row for row in injection_sites.schedule(sites).to_plain()}),
             'component_injection_registry_binding')
    scope = {'source_hashes': model_sources,
             'initial_state_sha256': reference_model.initial_state(explorer.GRAPH_CASE).digest(),
             'vocabulary_sha256': values.vocabulary_digest(),
             'stages_sha256': protocol.STAGES.digest()}
    # Component readers retain their original schemas; the generation envelope
    # is checked here, never forwarded as a caller-supplied closure assertion.
    reader_record = {**record,
        'material': {k: v for k, v in record['material'].items() if k != 'generation_sha256'},
        'originals': {k: v for k, v in record['originals'].items() if k != 'generation'}}
    return reader_record, {'generation_sha256': _digest(generation),
                          'registry_sha256': _digest(registry_components),
                          'model_scope': scope}


def _validate_integrated(record, sources, registries):
    from lifecycle_conformance import campaign
    material, original = record['material'], record['originals']
    _require(set(material) == {'profile', 'report_sha256', 'frames_sha256'}, 'integrated_material')
    _require(set(original) == {'report', 'frames'}, 'integrated_originals')
    _require(_digest(original['report']) == material['report_sha256']
             and _digest(original['frames']) == material['frames_sha256'], 'integrated_digest')
    campaign.validate_integrated_campaign(_frozen(original['report']), original['frames'],
        sources=sources, registry_components=registries, profile=material['profile'])
    report = _plain(original['report'])
    _require(report['acceptance']['complete_coverage'] == 'BLOCKED'
             and report['release_authorized'] is False
             and report['qualification_authorized'] is False, 'historical_false_authority')
    return (), {'scope': 'validated_limited_profile', 'profile': material['profile']}


def _validate_development_manifest(record, kind, sources, runtime, registry_components):
    """Re-execute a development manifest against the runtime-python subset.

    Two distinct source inventories meet in this reader. sources is the gate's
    COMPLETE inventory: every runtime-allowlisted .py plus the non-allowlisted
    repository scripts. That is the map the chain which mints a candidate
    always builds, and action_host asserts the superset relation before
    building the gate. The manifest readers in coverage_manifest bind a
    narrower map: they build their coverage checklist FROM the sources they
    are given and require exactly the runtime .py subset, because the
    obligation table they rebuild is defined over the runtime package alone.

    The manifest therefore binds to that subset. It is derived here from the
    gate's already-bound runtime and the gate's own bytes, never from the
    record: the equality below exists to prove the retained inputs are this
    generation's, so taking either side of it from the record would relaunder
    exactly what it refuses. Widening the record to the complete inventory
    does not become acceptable, because the comparand is the subset rather
    than whatever map the gate happens to hold.
    """
    from lifecycle_conformance import coverage_manifest
    material, original = record['material'], record['originals']
    _require(set(material) == {'report_sha256'}, 'manifest_material')
    _require(_digest(original.get('report')) == material['report_sha256'], 'manifest_digest')
    report = _frozen(original['report'])
    kwargs = original.get('inputs')
    _require(type(kwargs) is dict, 'manifest_inputs')
    # _source_identity has already proven every runtime python path is present
    # in sources with a matching hash, so a validated gate cannot reach this
    # refusal. It is named rather than left to raise KeyError out of the
    # selection below, so an unvalidated caller still gets a reason.
    _require(all(path in sources for path in runtime['python_source_hashes']),
             'manifest_source_scope')
    expected_sources = {path: sources[path] for path in runtime['python_source_hashes']}
    _require(_frozen(kwargs.get('sources')) == _frozen(expected_sources), 'manifest_source_binding')
    _require(_frozen(kwargs.get('runtime_source_hashes')) == _frozen(runtime['runtime_entry_hashes']),
             'manifest_runtime_binding')
    _require(_frozen(kwargs.get('registry_components')) == _frozen(registry_components),
             'manifest_registry_binding')
    if kind == 'development_coverage_manifest':
        _require(set(original) == {'report', 'plan', 'cases', 'inputs'}, 'manifest_originals')
        coverage_manifest.validate_manifest(report, _frozen(original['plan']), original['cases'], **kwargs)
    elif kind == 'development_registry_manifest':
        _require(set(original) == {'report', 'inputs'}, 'registry_manifest_originals')
        coverage_manifest.validate_registry_manifest(report, **kwargs)
    else:
        _require(set(original) == {'report', 'plan', 'cases', 'inputs'}, 'joined_manifest_originals')
        coverage_manifest.validate_joined_manifest(report, _frozen(original['plan']), original['cases'], **kwargs)
    data = report.to_plain()
    _require(data['registry_sha256'] == _digest(registry_components)
             and data['runtime_source_inventory_sha256'] == runtime['runtime_inventory_sha256'],
             'manifest_aggregate_binding')
    _require(data['execution_attested'] is False and data['release_authorized'] is False
             and data['qualification_authorized'] is False, 'historical_false_authority')
    facts = ()
    if kind == 'development_registry_manifest':
        # These readers re-execute the exact complete registered replay and
        # fixture inventories. Their reports still deny host/model closure.
        facts = ('all_replays_bound', 'all_host_fixtures_bound')
    if (kind == 'development_joined_manifest'
            and data['schema']
            == 'orch-dork/development-integrated-manifest/v8'):
        _require(data.get('production_graph_reconciliation_complete') is True
                 and data.get('complete_campaign') is False,
                 'manifest_graph_reconciliation_scope')
        facts = ('production_graph_reconciliation_complete',)
    return facts, {'scope': 'validated_limited_manifest', 'schema': data['schema']}


def _validate_public(record, kind, sources):
    from lifecycle_conformance import public_pair_evidence, public_pair_registry
    material, original = record['material'], record['originals']
    _require(set(material) == {'report_sha256'}, 'public_material')
    _require(_digest(original.get('report')) == material['report_sha256'], 'public_digest')
    report = _frozen(original['report'])
    if kind == 'public_pair_evidence':
        _require(set(original) == {'report', 'observations'}, 'public_evidence_originals')
        public_pair_evidence.validate_evidence(report, sources, original['observations'])
    elif kind == 'public_pair_registry':
        _require(set(original) == {'report', 'observations', 'modules'}, 'public_registry_originals')
        public_pair_registry.validate_registry(report, sources, original['observations'], modules=original['modules'])
    else:
        _require(set(original) == {'report'}, 'supporting_roles_originals')
        public_pair_registry.validate_supporting_imports(report, sources)
    return (), {'scope': 'validated_classification_or_selected_pairs'}


def _validate_source_scope(record, sources, runtime, registries):
    from lifecycle_conformance import source_scope_closure
    material, original = record['material'], record['originals']
    _require(set(material) == {'report_sha256'}, 'scope_material')
    _require(set(original) == {'report', 'scope_originals'}, 'scope_originals')
    _require(_digest(original['report']) == material['report_sha256'], 'scope_digest')
    report = _frozen(original['report'])
    source_scope_closure.validate_complete_scope(report, sources=sources, runtime=runtime,
        registry_components=registries, originals=original['scope_originals'])
    data = report.to_plain()
    allowed = {'public_inventory_complete', 'exports_classified',
               'effects_classified', 'source_scope_complete'}
    _require(set(data['facts']).issubset(allowed), 'scope_fact_boundary')
    _require(data['execution_attested'] is False and data['release_authorized'] is False
             and data['qualification_authorized'] is False, 'scope_execution_authority')
    return tuple(data['facts']), {'scope': 'validated_source_classification_only',
        'schema': data['schema'], 'report_sha256': report.digest(),
        'source_inventory_sha256': data['source_inventory_sha256'],
        'remaining_requirements': data['remaining_requirements']}


def _reference_graph(registry):
    """Construct only the fixed walker's data holder, with no execution claim."""
    from lifecycle_conformance import explorer
    _require(type(registry) is rv.FrozenValue, 'model_registry_type')
    return explorer.Exploration(rv.freeze({}), registry, rv.freeze({}), rv.freeze([]), rv.freeze({}))


def _closed_model_contexts(registry):
    """Exhaust the fixed walker, including its trailing no-orphan closure check.

    It starts at reference_model.initial_state(explorer.GRAPH_CASE), validates
    each actual outgoing transition and successor, and rejects any extra state
    or edge. The returned context index is derived, never inferred from a total.
    """
    from lifecycle_conformance import cartesian
    index = {}
    for context in cartesian.walk_contexts(_reference_graph(registry)):
        data = context.to_plain()
        _require(data['id'] not in index, 'model_duplicate_context')
        index[data['id']] = {'context': data['id'], 'sha256': context.digest(),
                             'cases': len(data['instances'])}
    return rv.freeze([index[key] for key in sorted(index)])


def _validate_model_graph(record):
    from lifecycle_conformance import explorer, registries
    material, original = record['material'], record['originals']
    _require(set(material) == {'coverage_sha256', 'cases_sha256', 'events_sha256', 'registry_sha256'},
             'model_material')
    _require(set(original) == {'coverage', 'store', 'cases', 'events'}, 'model_originals')
    _require(type(original['store']) is registries.RegistryStore, 'model_store_type')
    _require(_digest(original['coverage']) == material['coverage_sha256']
             and _digest(original['cases']) == material['cases_sha256']
             and _digest(original['events']) == material['events_sha256']
             and original['store'].digest() == material['registry_sha256'], 'model_digest')
    store = original['store']
    # Keep both kinds even when empty so a toy graph fails against the actual
    # initial state/outgoings, not merely because its empty edge key was absent.
    _require(not any(store.items_of(kind) for kind in store.kinds()
                     if kind not in ('lc-state', 'lc-trans')), 'model_registry_kinds')
    registry = rv.freeze({kind: store.items_of(kind) for kind in ('lc-state', 'lc-trans')})
    contexts = _closed_model_contexts(registry)
    explorer.validate_coverage(original['coverage'], store, original['cases'], original['events'])
    return ('model_graph_complete',), {'scope': 'complete_pure_model_graph',
        'reference_graph_sha256': registry.digest(), 'context_index_sha256': contexts.digest()}


def _validate_injection(record):
    from lifecycle_conformance import injection_campaign
    material, original = record['material'], record['originals']
    _require(set(material) == {'report_sha256', 'shard_index', 'shard_count'}, 'injection_material')
    _require(set(original) == {'report', 'store'}, 'injection_originals')
    rebuilt = injection_campaign.run(shard_index=material['shard_index'],
        shard_count=material['shard_count'], store=original['store'])
    _require(_digest(original['report']) == material['report_sha256']
             and rv.freeze(original['report']) == rv.freeze(rebuilt), 'injection_binding')
    return (), {'scope': 'minimal_state_injection_registry',
                   'site_count': rebuilt['site_count'], 'matrix_count': rebuilt['matrix_count'],
                   'production_seams_bound': rebuilt['boundary']['production_seams_bound']}


def _sequence_digest(values_):
    _require(type(values_) is list and all(isinstance(row, rv.FrozenValue) for row in values_),
             'matrix_frozen_values')
    return values.canonical_digest([row.digest() for row in values_])


def _validate_injection_matrix(record):
    from lifecycle_conformance import matrix_readback
    material, original = record['material'], record['originals']
    _require(set(material) == {'expected_index_sha256', 'case_inventory_sha256',
        'contexts_sha256', 'outputs_sha256', 'report_sha256', 'shard_index',
        'shard_count', 'graph_registry_sha256'}, 'matrix_material')
    _require(set(original) == {'expected_index', 'contexts', 'outputs', 'report', 'graph_registry'},
             'matrix_originals')
    _require(type(material['shard_index']) is int and type(material['shard_count']) is int
             and material['shard_index'] == 0 and material['shard_count'] == 1,
             'matrix_not_unsharded')
    _require(isinstance(original['expected_index'], rv.FrozenValue)
             and isinstance(original['report'], rv.FrozenValue), 'matrix_frozen_inputs')
    _require(original['expected_index'].digest() == material['expected_index_sha256']
             and _sequence_digest(original['contexts']) == material['contexts_sha256']
             and _sequence_digest(original['outputs']) == material['outputs_sha256']
             and original['report'].digest() == material['report_sha256'], 'matrix_input_digest')
    _require(type(original['graph_registry']) is rv.FrozenValue
             and original['graph_registry'].digest() == material['graph_registry_sha256'],
             'matrix_graph_digest')
    expected = _closed_model_contexts(original['graph_registry'])
    _require(expected == original['expected_index'], 'matrix_reference_context_union')
    checked = matrix_readback.validate_output_integrity(
        original['contexts'], original['outputs'], original['report'],
        expected_index=original['expected_index'],
        expected_index_sha256=material['expected_index_sha256'],
        expected_case_inventory_sha256=material['case_inventory_sha256'],
        shard_index=0, shard_count=1)
    report = checked.to_plain()
    _require(report['case_inventory_sha256'] == material['case_inventory_sha256']
             and report['physical_dispatches'] == 0
             and report['qualification_authorized'] is False, 'matrix_report_scope')
    return ('applicable_injection_complete',), {
        'scope': 'full_state_site_timing_failure_matrix_output_integrity',
        'reference_graph_sha256': original['graph_registry'].digest(),
        'context_index_sha256': expected.digest(),
        'context_count': len(original['contexts']), 'case_count': report['case_count'],
        'original_traces_replayed': False, 'host_execution_attested': False}


def _read_host(original, host_runs, runtime, profile):
    from lifecycle_conformance import host_attestation as host
    _require(type(original) is dict and set(original) == {
        'source_root', 'artifact_root', 'invocation_id', 'report'}, 'host_original')
    _require(all(type(original[key]) is str for key in ('source_root', 'artifact_root')),
             'host_root_paths')
    identity = original['invocation_id']
    _require(type(identity) is str and _SHA.fullmatch(identity) is not None, 'host_invocation')
    run = host_runs.get(identity)
    _require(type(run) is host.HostRun, 'fresh_host_run_required')
    _require(str(run.artifact_root) == original['artifact_root'], 'host_artifact_binding')
    checked = host.readback(source_root=original['source_root'],
        artifact_root=original['artifact_root'], witness=run.witness,
        expected_invocation_id=identity)
    _require(checked.report == _frozen(original['report']), 'host_report_binding')
    data = checked.report.to_plain()
    _require(data['profile'] == profile, 'host_profile_binding')
    _require(data['runtime_identity'] == {k: v for k, v in runtime.items()
                                         if k != 'python_source_hashes'}, 'host_runtime_binding')
    return checked


def _validate_host_component(record, runtime, host_runs):
    from lifecycle_conformance import host_attestation as host
    material, original = record['material'], record['originals']
    _require(set(material) == {'report_sha256'}, 'host_material')
    if record['kind'] == 'host_attested_campaign':
        _require(set(original) == {'run'}, 'campaign_host_originals')
        checked = _read_host(original['run'], host_runs, runtime, 'campaign')
        report = checked.report
        facts = host.completion_facts(checked)
        source_root = original['run']['source_root']
    else:
        _require(set(original) == {'runs', 'report'} and type(original['runs']) is dict
                 and set(original['runs']) == {'focused', 'rehearsal', 'full_suite'},
                 'test_host_originals')
        checked = {profile: _read_host(run, host_runs, runtime, profile)
                   for profile, run in original['runs'].items()}
        report = host.validate_test_run_set(checked)
        roots = {run['source_root'] for run in original['runs'].values()}
        _require(len(roots) == 1, 'test_source_root_binding')
        source_root = next(iter(roots))
        _require(report == _frozen(original['report']), 'test_set_report_binding')
        facts = tuple(report.to_plain()['facts'])
    _require(report.digest() == material['report_sha256'], 'host_report_digest')
    return facts, {'scope': 'host_custody_only',
                   'source_root': source_root,
                   'source_generation_sha256': report.to_plain()['source_generation_sha256'],
                   'report_sha256': report.digest()}


def _validate_candidate(record, runtime):
    from lifecycle_conformance import candidate_identity
    material, original = record['material'], record['originals']
    _require(set(material) == {'report_sha256'} and set(original) == {
        'report', 'original_root', 'candidate_root'}, 'candidate_originals')
    report = _frozen(original['report'])
    _require(report.digest() == material['report_sha256'], 'candidate_report_digest')
    candidate_identity.validate_cachebuster_identity_transition(
        original['original_root'], original['candidate_root'], report)
    data = report.to_plain()
    pre = data['original']['project_runtime_source_report']
    post = data['candidate']['project_runtime_source_report']
    _require(pre['package_digest'] == runtime['package_digest_before_cachebuster']
             and pre['version'] == runtime['version_before_cachebuster']
             and {row['path']: row['sha256'] for row in data['original']['inventory']}
                 == runtime['runtime_entry_hashes'], 'candidate_pre_runtime_binding')
    # These become facts only after the durable candidate outcome is read back.
    return (), {'scope': 'source_backed_metadata_transition',
                'original_root': str(original['original_root']),
                'transition_sha256': report.digest(), 'pre_runtime': pre, 'post_runtime': post}


def _campaign_transport(raw):
    _require(type(raw) is str, 'campaign_transport')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, 'duplicate_campaign_key')
            result[key] = value
        return result
    try:
        return rv.freeze(json.loads(raw, object_pairs_hook=unique))
    except (ValueError, TypeError) as error:
        raise values.LifecycleContractError('completion_gate:campaign_transport') from error


def _read_consumption(anchor, evidence, pre_campaign, candidate):
    """Read one retained chain; stored transport success is never action proof."""
    from lifecycle_conformance import consumption
    import orch_dork_runtime_package as package
    _require(type(anchor) is dict and set(anchor) == {
        'root', 'initial_receipt', 'latest_receipt', 'campaign_receipt_json'},
        'consumption_anchor')
    initial, latest = anchor['initial_receipt'], anchor['latest_receipt']
    _require(type(initial) is rv.FrozenValue and type(latest) is rv.FrozenValue,
             'consumption_original_receipts')
    raw = anchor['campaign_receipt_json']
    retained_campaign = _campaign_transport(raw)
    entries, version, _ = package._projectable_source_entries(
        Path(__file__).resolve().parents[4], package.RUNTIME_ALLOWLIST)
    pre = package._report(version, entries)
    binding = {'campaign_receipt_sha256': hashlib.sha256(raw.encode()).hexdigest(),
               'pre_runtime': pre, 'post_runtime': None, 'transition_sha256': None}
    first, last = initial.to_plain(), latest.to_plain()
    initial_binding = binding
    if candidate is not None:
        binding = {**binding, 'post_runtime': candidate['post_runtime'],
                   'transition_sha256': candidate['transition_sha256']}
    checked = consumption.read_store(anchor['root'], latest, expected_binding=binding)
    expected_first = {**last, 'binding': initial_binding, 'sequence': 0,
                      'tip_sha256': last['store']['anchor_sha256'],
                      'phase': 'candidate', 'status': 'READY', 'claim': None}
    _require(first == expected_first, 'consumption_initial_binding')
    _require(last['phase'] in ('candidate', 'release_install', 'live_attempt'), 'consumption_phase')
    _require(evidence['consumption'] == {
        phase: last if phase == last['phase'] else None
        for phase in ('candidate', 'release_install', 'live_attempt')}, 'consumption_latest_binding')
    if candidate is not None:
        _require(last['sequence'] >= 2 and (last['phase'] != 'candidate'
                 or last['status'] == 'SUCCEEDED'), 'candidate_outcome_required')
    _require(retained_campaign == pre_campaign, 'consumption_campaign_binding')
    _require(pre_campaign.to_plain()['campaign_authorized'] is True,
             'consumption_campaign_incomplete')
    return {'scope': 'durable_bookkeeping_only', 'root': str(anchor['root']),
            'initial_receipt_sha256': initial.digest(), 'latest_receipt_sha256': checked.digest(),
            'phase': last['phase'], 'status': last['status'],
            'physical_action_facts': []}


def _validate_live_attempt(record):
    """Re-derive the one live attempt from its durable originals.

    The reader owns the decision. This gate supplies no fact of its own: it
    hands the retained originals back to the module that issued them and
    returns exactly the facts that module grants. A caller-built report cannot
    reseal itself, because validate_campaign_consumption rebuilds from the
    on-disk chain and compares.
    """
    from lifecycle_conformance import live_attempt_consumption as live
    material, original = record['material'], record['originals']
    _require(set(material) == {'report_sha256'} and set(original) == {
        'report', 'store_root', 'claim_receipt', 'latest_receipt',
        'expected_binding', 'outcome_receipt', 'receipt_path'}, 'live_attempt_originals')
    report = _frozen(original['report'])
    _require(report.digest() == material['report_sha256'], 'live_attempt_report_digest')
    validated = live.validate_campaign_consumption(
        original['store_root'], report,
        claim_receipt=original['claim_receipt'],
        latest_receipt=original['latest_receipt'],
        expected_binding=original['expected_binding'],
        outcome_receipt=original['outcome_receipt'],
        receipt_path=original['receipt_path'])
    facts = live.completion_facts(validated)
    data = report.to_plain()
    # A terminal failure still consumes the attempt and preserves its result,
    # so both facts are granted. Promotion stays closed elsewhere, through the
    # durable phase and status check, not by withholding these facts.
    return facts, {'scope': 'durable_live_attempt_consumption',
                   'phase': data['phase'], 'status': data['status'],
                   'terminal_outcome': data.get('terminal_outcome'),
                   'report_sha256': report.digest()}


def _validate_release(record):
    """Re-derive the one physical release from its retained original.

    The reader owns the decision. This gate supplies no fact of its own: it
    hands the retained original back to the module that issued it and returns
    exactly the facts that module grants.

    Release custody is same-process rather than durable. release_execution
    retains the opaque entry-point return inside a PID-bound issued registry,
    so the original here is the live ReleaseExecution itself, as host custody
    keeps live HostRun witnesses. A serialized or caller-rebuilt record carries
    a mapping instead of that type and is refused, and release_report
    independently refuses any object its own registry did not issue or whose
    retained content has since changed.
    """
    from lifecycle_conformance import release_execution as release
    material, original = record['material'], record['originals']
    _require(set(material) == {'report_sha256'} and set(original) == {
        'execution', 'report'}, 'release_originals')
    execution = original['execution']
    _require(type(execution) is release.ReleaseExecution, 'fresh_release_execution_required')
    # Recomputed here, never read from the record. release_report re-verifies
    # its own source pins and the retained fingerprint, so a mutated, foreign
    # or self-sealed original is refused by the issuing module.
    report = release.release_report(execution)
    _require(report == _frozen(original['report']), 'release_report_binding')
    _require(report.digest() == material['report_sha256'], 'release_report_digest')
    facts = release.completion_facts(execution)
    data = report.to_plain()
    # The issuing module is asked twice and must agree with itself. A report
    # that names facts its own completion_facts withholds, or the reverse, is
    # refused rather than reconciled here.
    _require(tuple(data['facts']) == facts, 'release_fact_binding')
    # Facts come from the issuing module alone. It grants none while the
    # release entry point returns a plain mapping and no physical-result
    # validator exists, so this requirement stays BLOCKED on missing physical
    # evidence rather than on a missing reader.
    return facts, {'scope': 'same_process_release_custody',
                   'status': data['status'],
                   'physical_execution_validated': data['physical_execution_validated'],
                   'source_unchanged': data['source_unchanged'],
                   'post_effect_capture': data['post_effect_capture'],
                   'report_sha256': report.digest()}


def _validate_production_campaign(record, sources, runtime, registry_components):
    """Re-derive the one production campaign from its durable originals.

    The reader owns the decision. This gate supplies no fact of its own: it
    hands the retained originals back to the module that issued them and
    returns exactly the facts that module grants. A caller-built report cannot
    reseal itself, because validate_production_campaign rebuilds the obligation
    table from the store on disk and compares before it returns.

    Campaign custody is durable rather than same-process. The evidence is
    written by a separate child dispatch and read back later in a different
    interpreter, so the original here is a store root, as the live-attempt
    reader takes one, not a live issued object the release reader can type-check.

    The generation is rebuilt here from the gate's own already-bound inputs
    rather than taken from the record. _component_generation has just proved
    those three values equal the retained envelope sealed by the case identity,
    and it strips that envelope before this reader runs, so passing the gate's
    copy binds the reader to the same generation without reintroducing a
    caller-supplied one.

    The anchor is caller-retained and this gate cannot yet witness where it came
    from. A caller that mints its own anchor and seals its own store satisfies
    every check below, so these facts are earned against an anchor whose custody
    is asserted rather than proved. The cross-check that closes that gap binds
    the anchor to a dispatch this gate itself spawned; it is not implemented
    here, and until it is, the store's authorship rests on the caller.
    """
    from lifecycle_conformance import production_campaign as production
    material, original = record['material'], record['originals']
    _require(set(material) == {'report_sha256'} and set(original) == {
        'report', 'store_root', 'anchor'}, 'production_campaign_originals')
    report = _frozen(original['report'])
    _require(report.digest() == material['report_sha256'],
             'production_campaign_report_digest')
    generation = _frozen({'sources': sources, 'runtime': runtime,
                          'registry_components': registry_components})
    validated = production.validate_production_campaign(
        original['store_root'], report, generation=generation,
        anchor=_frozen(original['anchor']))
    facts = production.completion_facts(validated)
    data = report.to_plain()
    # The issuing module is asked twice and must agree with itself. A report
    # that names facts its own completion_facts withholds, or the reverse, is
    # refused rather than reconciled here.
    _require(tuple(data['completion_facts']) == facts,
             'production_campaign_fact_binding')
    # The reading names the run it verified. The gate publishes that identity
    # so a later cross-check against a gate-owned dispatch record has the exact
    # value to compare, and so two readings from one store are distinguishable.
    return facts, {'scope': 'durable_production_campaign',
                   'status': data['status'],
                   'execution_sha256': data['execution_sha256'],
                   'store_sha256': data['store_sha256'],
                   'closure_sha256': data['closure_sha256'],
                   'obligation_counts': data['obligation_counts'],
                   'withheld_facts': data['withheld_facts'],
                   'anchor_custody': 'caller_retained_unwitnessed',
                   'report_sha256': report.digest()}

def _validate_component(record, sources, runtime, registries, host_runs):
    kind = record['kind']
    _require(kind in _IMPLEMENTED_KINDS, 'component_reader_missing:' + kind)
    if kind == 'integrated_campaign':
        return _validate_integrated(record, sources, registries)
    if kind.startswith('development_'):
        return _validate_development_manifest(record, kind, sources, runtime, registries)
    if kind in ('public_pair_evidence', 'public_pair_registry', 'supporting_source_roles'):
        return _validate_public(record, kind, sources)
    if kind == 'source_scope_closure':
        return _validate_source_scope(record, sources, runtime, registries)
    if kind == 'model_graph_coverage':
        return _validate_model_graph(record)
    if kind == 'injection_matrix_readback':
        return _validate_injection_matrix(record)
    if kind in ('host_attested_campaign', 'test_run_attestation'):
        return _validate_host_component(record, runtime, host_runs)
    if kind == 'candidate_identity_transition':
        return _validate_candidate(record, runtime)
    if kind == 'live_attempt_consumption':
        return _validate_live_attempt(record)
    if kind == 'release_consumption':
        return _validate_release(record)
    if kind == 'production_campaign':
        return _validate_production_campaign(
            record, sources, runtime, registries)
    return _validate_injection(record)


def _requirement_rows(facts):
    rows, remaining = {}, []
    for identity, required, description in REQUIREMENTS:
        missing = [fact for fact in required if fact not in facts]
        rows[identity] = {'status': 'PASS' if not missing else 'BLOCKED',
                          'required_facts': list(required), 'missing_facts': missing,
                          'required_components': sorted({kind for fact in missing
                                                         for kind in FACT_COMPONENTS[fact]}),
                          'description': description}
        if missing:
            remaining.append({'requirement': identity, 'missing_facts': missing,
                              'description': description})
    return rows, remaining


def build_completion_report(evidence, *, sources, registry_components,
                            host_runs=None, consumption_anchor=None):
    """Re-read originals; keep HostRun witnesses alive through this call.

    host_runs maps invocation IDs to the original process-local HostRun objects.
    consumption_anchor supplies root, initial_receipt, latest_receipt and the
    exact campaign_receipt_json retained by the caller. Neither input is a
    validator callback or serialized grant. This function performs no effects.
    """
    host_runs = {} if host_runs is None else host_runs
    _require(type(host_runs) is dict, 'host_runs')
    _require(type(evidence) is dict and set(evidence) == {
        'schema', 'runtime', 'components', 'consumption'}, 'evidence_shape')
    _require(evidence['schema'] == EVIDENCE_SCHEMA, 'evidence_schema')
    _require(_require_fact_mapping_complete, 'fact_component_mapping')
    source_hashes = _source_identity(sources, evidence['runtime'])
    _require(type(registry_components) is dict and bool(registry_components), 'registries')
    _require(type(evidence['components']) is list, 'components')
    _require(type(evidence['consumption']) is dict and set(evidence['consumption']) == {
        'candidate', 'release_install', 'live_attempt'}, 'consumption_shape')

    facts, components, seen, missing_readers = set(), {}, set(), []
    fresh_components = {}
    for record in evidence['components']:
        _component_shape(record)
        identity, kind = record['case_id'], record['kind']
        _require(identity not in seen, 'duplicate_component')
        seen.add(identity)
        if kind in _FRESH_KINDS:
            _require(kind not in fresh_components, 'duplicate_fixed_component:' + kind)
            fresh_components[kind] = identity
        if kind not in _IMPLEMENTED_KINDS:
            missing_readers.append({'case_id': identity, 'kind': kind,
                                    'validator': COMPONENT_VALIDATORS[kind]})
            components[identity] = {'kind': kind, 'status': 'BLOCKED',
                'validator': COMPONENT_VALIDATORS[kind], 'facts': [],
                'detail': {'reason': 'independent_component_reader_missing'}}
            continue
        generation_binding = {}
        reader_record = record
        if kind in _FACT_PRODUCERS:
            reader_record, generation_binding = _component_generation(
                record, sources, evidence['runtime'], registry_components)
        contributed, detail = _validate_component(
            reader_record, sources, evidence['runtime'], registry_components, host_runs)
        _require(not contributed or kind in _FACT_PRODUCERS, 'unbound_fact_producer')
        _require(set(contributed).issubset(_ALL_FACTS), 'unknown_fact')
        _require(all(kind in FACT_COMPONENTS[fact] for fact in contributed),
                 'fact_component_owner')
        facts.update(contributed)
        components[identity] = {'kind': kind, 'status': 'VALIDATED_LIMITED',
            'validator': COMPONENT_VALIDATORS[kind], 'facts': list(contributed),
            'detail': {**detail, **generation_binding}}

    custody = [(components[fresh_components[kind]]['detail']['source_root'],
                components[fresh_components[kind]]['detail']['source_generation_sha256'])
               for kind in ('host_attested_campaign', 'test_run_attestation')
               if kind in fresh_components]
    _require(len(set(custody)) <= 1, 'campaign_test_source_generation_binding')
    candidate_id = fresh_components.get('candidate_identity_transition')
    candidate = components[candidate_id]['detail'] if candidate_id is not None else None
    _require(candidate is None or consumption_anchor is not None, 'candidate_consumption_required')
    if candidate is not None:
        _require('host_attested_campaign' in fresh_components and 'test_run_attestation' in fresh_components,
                 'candidate_host_campaign_required')
        _require(candidate['original_root'] == custody[0][0], 'candidate_pre_source_root_binding')
    durable = None
    if consumption_anchor is not None:
        # Rebuild the pre-effect campaign with the SAME fresh witnesses. A
        # caller's PASS JSON cannot authorize its self-created consumption
        # store. The three exact effect records below are necessarily absent
        # from the retained pre-store receipt; all other submitted components
        # remain bound into the reconstructed campaign.
        pre_evidence = {**evidence,
            'components': [row for row in evidence['components']
                           if row['kind'] not in _POST_STORE_COMPONENT_KINDS],
            'consumption': {phase: None for phase in evidence['consumption']}}
        pre_campaign = build_completion_report(pre_evidence, sources=sources,
            registry_components=registry_components, host_runs=host_runs)
        durable = _read_consumption(consumption_anchor, evidence, pre_campaign, candidate)
        if candidate is not None:
            contributed = ['candidate_identity_transition_valid', 'candidate_consumed_once']
            components[candidate_id]['facts'] = contributed
            facts.update(contributed)

    requirements, remaining = _requirement_rows(facts)
    provider_free_pass = all(requirements[item]['status'] == 'PASS'
                             for item in PROVIDER_FREE_REQUIREMENTS)
    candidate_transition_pass = requirements['candidate_transition']['status'] == 'PASS'
    release_consumption_pass = requirements['release_install_consumption']['status'] == 'PASS'
    live_consumption_pass = requirements['live_attempt_consumption']['status'] == 'PASS'
    for name, value in evidence['consumption'].items():
        if value is not None and durable is None:
            remaining.append({'requirement': name + '_consumption_reader',
                'missing_facts': ['independent_consumption_validation'],
                'description': 'Submitted consumption evidence is inert until its root-owned reader validates it.'})

    runtime = evidence['runtime']
    return rv.freeze({
        'schema': REPORT_SCHEMA, 'status': 'PASS' if provider_free_pass else 'BLOCKED',
        'registry_sha256': _digest(registry_components),
        'campaign_status': 'PASS' if provider_free_pass else 'BLOCKED',
        'consumption_status': ('COMPLETE' if candidate_transition_pass and release_consumption_pass
                               and live_consumption_pass else 'PENDING'),
        'campaign_authorized': provider_free_pass,
        'candidate_authorized': (provider_free_pass and (durable is None or
            durable['phase'] == 'candidate' and durable['status'] == 'READY')),
        'release_authorized': (provider_free_pass and candidate_transition_pass
                              and durable['phase'] == 'candidate' and durable['status'] == 'SUCCEEDED'),
        'live_attempt_authorized': (provider_free_pass and candidate_transition_pass
                                    and release_consumption_pass and durable['phase'] == 'release_install'
                                    and durable['status'] == 'SUCCEEDED'),
        'qualification_authorized': (provider_free_pass and candidate_transition_pass
                                     and release_consumption_pass and durable['phase'] == 'release_install'
                                     and durable['status'] == 'SUCCEEDED'),
        'promotion_authorized': (provider_free_pass and candidate_transition_pass
                                 and release_consumption_pass and live_consumption_pass
                                 and durable['phase'] == 'live_attempt' and durable['status'] == 'SUCCEEDED'),
        'source_inventory_hashes': source_hashes,
        'runtime_identity': {'phase': 'pre_cachebuster',
            'python_source_hashes': runtime['python_source_hashes'],
            'runtime_entry_hashes': runtime['runtime_entry_hashes'],
            'runtime_inventory_sha256': runtime['runtime_inventory_sha256'],
            'manifest_sha256': runtime['manifest_sha256'],
            'package_digest_before_cachebuster': runtime['package_digest_before_cachebuster'],
            'version_before_cachebuster': runtime['version_before_cachebuster']},
        'candidate_transition_contract': {
            'validator': COMPONENT_VALIDATORS['candidate_identity_transition'],
            'required_changes': ['manifest_version', 'manifest_sha256', 'package_digest'],
            'changed_runtime_paths_exact': ['.codex-plugin/plugin.json'],
            'forbidden_changes': ['all_other_runtime_entry_hashes'],
            'required_receipt_fields': [
                'root', 'initial_receipt', 'latest_receipt', 'campaign_receipt_json'],
            'pre_package_digest': runtime['package_digest_before_cachebuster'],
            'pre_manifest_sha256': runtime['manifest_sha256'],
            'pre_runtime_inventory_sha256': runtime['runtime_inventory_sha256'],
            'post_package_digest': candidate['post_runtime']['package_digest'] if candidate else None,
            'durable_consumption': durable, 'same_package_digest_permitted': False,
            'single_consumption_required': True},
        'validated_components': components, 'missing_component_readers': missing_readers,
        'facts': sorted(facts), 'requirements': requirements,
        'remaining_requirements': remaining,
        'evidence_sha256': values.canonical_digest({'schema': evidence['schema'],
            'registry_sha256': _digest(registry_components),
            'runtime': evidence['runtime'], 'component_case_ids': sorted(seen),
            'consumption': evidence['consumption']})})


def validate_completion_report(report, evidence, *, sources, registry_components,
                               host_runs=None, consumption_anchor=None):
    """Rebuild a report; changed originals, gaps, or consumption cannot reseal it."""
    _require(type(report) is rv.FrozenValue
             and report == build_completion_report(evidence, sources=sources,
                 registry_components=registry_components, host_runs=host_runs,
                 consumption_anchor=consumption_anchor),
             'report_binding')


def missing_components(*, sources, registry_components, runtime):
    """Return the useful empty-campaign baseline for integration planning."""
    evidence = {'schema': EVIDENCE_SCHEMA, 'runtime': runtime, 'components': [],
                'consumption': {'candidate': None, 'release_install': None, 'live_attempt': None}}
    return build_completion_report(evidence, sources=sources,
                                   registry_components=registry_components)


__all__ = ['EVIDENCE_SCHEMA', 'REPORT_SCHEMA', 'COMPONENT_SCHEMA',
           'COMPONENT_VALIDATORS', 'REQUIREMENTS', 'PROVIDER_FREE_REQUIREMENTS',
           'FACT_COMPONENTS',
           'case_identity', 'build_completion_report',
           'validate_completion_report', 'missing_components']
