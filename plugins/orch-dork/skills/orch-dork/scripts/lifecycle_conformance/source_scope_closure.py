"""Read complete source scope while retaining the limits of captured evidence.

Source classification is not execution. Fixed repository readers validate the
original inventories and observations; reviewed policy selects work only. No
caller decision, callback, rationale or status can discharge an unknown role.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

from lifecycle_conformance import coverage_manifest, public_inventory
from lifecycle_conformance import public_pair_evidence, public_pair_registry
from lifecycle_conformance import reference_values as rv, values


SCHEMA = 'orch-dork/source-scope-closure/v1'
ORIGINALS_SCHEMA = 'orch-dork/source-scope-originals/v1'
SOURCE_ROOTS = ('hooks', 'scripts', 'skills/orch-dork/scripts')
CLASSIFICATION_PATH = 'skills/orch-dork/runtime/lifecycle-conformance/source-scope-classifications-v1.json'
CLASSIFICATION_SCHEMA = 'orch-dork/source-scope-classifications/v1'
SEMANTIC_BASES_SHA256 = '671ae474e56f8ad1da0dc0cceb7ba7804a82355e95d380d2fd2cc7d33930a1c2'
_SEMANTIC_SEAL_SOURCE = 'skills/orch-dork/scripts/lifecycle_conformance/source_scope_closure.py'
# Fixed source policies, subject to independent source review with this change.
# These hashes bind semantic bases, not this reader or its packaged JSON. Unknown
# families remain residuals; a caller cannot introduce a new supporting policy.
_FAMILY_BASES = {
    'canonical-data': {
        'path': 'skills/orch-dork/scripts/lifecycle_conformance/values.py',
        'source_sha256': '438c943aa8c6a59e219118b762a298d5303495a7699a0996dc1eb4ec3ce5e495',
        'route': 'SUPPORTING_CONTRACT',
        'semantics': 'Closed vocabulary, identifier grammar, bounded canonical JSON and content digests. '
                     'Regex compilation and library imports initialize data machinery; exception fields, '
                     'local containers and caller data protocols are ordinary contract effects. '
                     'No function constructs a native lifecycle admission, report or action.'},
    'immutable-data': {
        'path': 'skills/orch-dork/scripts/lifecycle_conformance/reference_values.py',
        'source_sha256': '413ea20d8699ee65466028a82e87b13ef941e8f4a00f0aa765b7b2a35a68a781',
        'route': 'SUPPORTING_CONTRACT',
        'semantics': 'Canonical JSON-backed immutable values, fresh decoding, equality and hashing. '
                     'object.__new__/__setattr__ initialize the newly allocated frozen value; '
                     'ordinary mutation and direct construction refuse. Imports and re-exports bind '
                     'the canonical-data contract; lifecycle execution and authority are not implemented.'},
    'checkpoint-accounting': {
        'path': 'skills/orch-dork/scripts/orch_dork_qualification_budget.py',
        'source_sha256': '5bfaced6797846aea4f06254be88fa65baf221913751df160a665b9f7771ab5f',
        'route': 'LIFECYCLE_SEMANTICS',
        'semantics': 'Public policy, checkpoint/admission and completion budget constructors and validators '
                     'consume whole native reports, frozen limits and caller-supplied trusted clocks. '
                     'Canonicalization, imported report readers, source-cut joins, copied-container updates '
                     'and refusals belong to this lifecycle family. All successful alternatives and '
                     'required negative handoffs still require execution and host/source custody.'},
}
# Review artifacts, not proof counts. A changed policy requires a fresh review.
REVIEWED_FILES = {
    'docs/agents/issue170-source-scope.md': '807fccded2721f2574ee906e07e8d48a529f45d99d07b2741fe894a61bda7106',
    'tests/fixtures/issue170_source_scope.json': '7331d82e71ae6d2f201abf4c171ca11e480dc17f992e048127b31a790d70eb00',
    'skills/orch-dork/scripts/lifecycle_conformance/scope_policy.py': '2495f53b42d6af2886cc41b3181b17d9a1e603b54c6223493a20e78c4ad92c2a',
    'skills/orch-dork/scripts/lifecycle_conformance/source_coverage_backlog.py': 'a1cf8a8d7aebc5fabcf194ce73642998062a1463ecd824eadf6359a160ddd4ac',
}
_ROOT = Path(__file__).resolve().parents[4]
_MODULE_BASIS_CACHE = {}


def _require(condition, reason):
    if condition is not True:
        raise values.LifecycleContractError('source_scope_closure:' + reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _digest(value):
    return values.canonical_digest(value.to_plain() if type(value) is rv.FrozenValue else value)


def _read(path):
    target = _ROOT / path
    _require(not target.is_symlink() and target.resolve().is_relative_to(_ROOT), 'source_path:' + path)
    return target.read_bytes()


def read_source_snapshot():
    """Read this checkout's fixed package and broader plugin Python roots.

    Runtime identity uses the gate's exact pre-cachebuster fields. Broader
    source hashes are separate: an unallowlisted script never disappears and
    is never silently incorporated into the runtime package digest.
    """
    import orch_dork_runtime_package as package
    entries, version, _ = package._projectable_source_entries(_ROOT, package.RUNTIME_ALLOWLIST)
    hashes = {row['path']: row['sha256'] for row in entries}
    python = {path: sha for path, sha in hashes.items() if path.endswith('.py')}
    paths = set(python)
    for directory in SOURCE_ROOTS:
        paths.update(str(path.relative_to(_ROOT)) for path in (_ROOT / directory).rglob('*.py'))
    sources = {path: _read(path).decode('utf-8') for path in sorted(paths)}
    _require(all(_sha(sources[path].encode()) == sha for path, sha in python.items()), 'source_read_drift')
    return {'sources': sources, 'runtime': {
        'runtime_entry_hashes': hashes, 'python_source_hashes': python,
        'runtime_inventory_sha256': values.canonical_digest(hashes),
        'manifest_sha256': hashes[package.MANIFEST_PATH],
        'package_digest_before_cachebuster': package._report(version, entries)['package_digest'],
        'version_before_cachebuster': version}}


def _review_files():
    return {path: _read(path) for path in (*REVIEWED_FILES, CLASSIFICATION_PATH)}


def _policy_readers(originals):
    _require(type(originals) is dict and set(originals) == set(REVIEWED_FILES) | {CLASSIFICATION_PATH},
             'policy_originals')
    for path, expected in REVIEWED_FILES.items():
        _require(type(originals[path]) is bytes and _sha(originals[path]) == expected
                 and _read(path) == originals[path], 'policy_source_binding:' + path)
    # These runtime readers are intentionally not replaceable by parameters.
    # Deployment without the reviewed resources must refuse, never infer policy.
    from lifecycle_conformance import source_coverage_backlog, scope_policy
    for module in (source_coverage_backlog, scope_policy):
        path = str(Path(module.__file__).resolve().relative_to(_ROOT))
        _require(path in REVIEWED_FILES, 'policy_reader_origin')
    return source_coverage_backlog, scope_policy


def _classification_original(originals, runtime):
    raw = originals.get(CLASSIFICATION_PATH)
    _require(type(raw) is bytes and raw == _read(CLASSIFICATION_PATH)
             and runtime['runtime_entry_hashes'].get(CLASSIFICATION_PATH) == _sha(raw),
             'classification_package_binding')
    return _parse_classifications(raw)


def _parse_classifications(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, 'classification_duplicate_key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def _classification_groups(sources, inventory, discovery):
    """Group whole independent source records, without rewriting accepted proofs."""
    obligations = public_inventory.describe_source_obligations(sources).to_plain()['obligations']
    by_path = {path: {} for path in sources}
    for identity, row in obligations.items():
        by_path[row['path']][identity] = row
    result = {}
    for path, module in inventory.to_plain()['modules'].items():
        local_effects = public_pair_registry._local_bindings(sources[path], module['exports'])[1]
        kinds = {'exports': module['exports'], **{kind: discovery[path][kind]
                 for kind in ('bindings', 'aliases', 'effects')},
                 'source_obligations': by_path[path],
                 'module_effects': {'module': module['unresolved_module_effects'],
                     'classes': {name: row['unresolved_class_effects'] for name, row in module['exports'].items()
                                 if row['kind'] == 'class'}, 'bindings': local_effects}}
        for kind, members in kinds.items():
            binding = {'path': path, 'source_sha256': module['source_sha256'], 'kind': kind,
                       'member_count': len(members), 'member_sha256': _digest(members)}
            identity = 'classification-group:' + _digest(binding)
            result[identity] = {**binding, 'members': sorted(members)}
    return result


def _review_source_sha256(path, source):
    """Hash behavior-bearing source without making this module self-referential.

    Every classified module uses its exact bytes.  This reader alone replaces
    the value token of its fixed semantic-bases seal before hashing: changing
    the seal is how a reviewed source change is accepted, so including that
    value in the digest it stores would require an impossible hash fixed point.
    All other bytes, including the assignment target and validation code, stay
    in the reviewed source identity.
    """
    raw = source.encode('utf-8')
    if path != _SEMANTIC_SEAL_SOURCE:
        return _sha(raw)
    tree = ast.parse(source, filename=path)
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)
        and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == 'SEMANTIC_BASES_SHA256']
    _require(len(assignments) == 1, 'semantic_seal_assignment')
    bindings = [node for node in ast.walk(tree) if isinstance(node, ast.Name)
                and node.id == 'SEMANTIC_BASES_SHA256'
                and isinstance(node.ctx, (ast.Store, ast.Del))]
    _require(bindings == assignments[0].targets, 'semantic_seal_assignment')
    value = assignments[0].value
    _require(isinstance(value, ast.Constant) and type(value.value) is str
             and len(value.value) == 64 and set(value.value) <= set('0123456789abcdef'),
             'semantic_seal_value')
    _require(value.value == SEMANTIC_BASES_SHA256, 'semantic_seal_source_binding')
    lines = raw.splitlines(keepends=True)
    start = sum(len(line) for line in lines[:value.lineno - 1]) + value.col_offset
    end = sum(len(line) for line in lines[:value.end_lineno - 1]) + value.end_col_offset
    _require(0 <= start < end <= len(raw), 'semantic_seal_span')
    return _sha(raw[:start] + b"'reviewed-semantic-bases-sha256'" + raw[end:])


def _review_api_sha256(path, source, module):
    return _digest({**module, 'source_sha256': _review_source_sha256(path, source)})


def _module_basis(path, sources, inventory, inventory_modules=None, cache_key=None):
    """Exact API, call/effect syntax and import/dependency cut for source review.

    This records dependencies rather than guessing purity from call spelling.
    The complete source baseline also binds transitive dependencies and shadows.
    The contract identity also binds the classified module's own path and each
    local dependency's path: a reviewed disposition belongs to one exact source
    location, so copying, relocating or re-rooting a module cannot inherit it.
    """
    source = sources[path]
    key = (cache_key, path)
    if cache_key is not None and key in _MODULE_BASIS_CACHE:
        return _MODULE_BASIS_CACHE[key]
    tree = ast.parse(source, filename=path)
    imports, calls, effects = [], set(), {}
    inventory_modules = (inventory.to_plain()['modules'] if inventory_modules is None
                         else inventory_modules)
    module = inventory_modules[path]
    review_source_sha256 = _review_source_sha256(path, source)
    review_api_sha256 = _review_api_sha256(path, source, module)
    def source_span(node):
        text = ast.get_source_segment(source, node)
        return {'first_line': node.lineno, 'last_line': node.end_lineno,
                'text_sha256': _sha(text.encode())}
    def bindings(node):
        if isinstance(node, ast.Import):
            return [{'bound': item.asname or item.name.split('.')[0], 'target': item.name}
                    for item in node.names]
        prefix = '.' * node.level + (node.module or '')
        separator = '' if not prefix or prefix.endswith('.') else '.'
        return [{'bound': item.asname or item.name,
                 'target': prefix + separator + item.name} for item in node.names]
    def effect(kind, node):
        effects.setdefault(kind, []).append({**source_span(node),
            'syntax_sha256': _sha(ast.dump(node, include_attributes=False).encode())})
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imports.append({'syntax': ast.get_source_segment(source, node),
                            'bindings': bindings(node), **source_span(node)})
            effect('dependency-import', node)
        if isinstance(node, ast.Call):
            calls.add(ast.unparse(node.func))
            effect('call', node)
        elif isinstance(node, ast.Await): effect('await', node)
        elif isinstance(node, (ast.Yield, ast.YieldFrom)): effect('yield', node)
        elif isinstance(node, ast.Raise): effect('raise', node)
        elif isinstance(node, (ast.AugAssign, ast.Delete)): effect('state-mutation', node)
        elif (isinstance(node, (ast.Attribute, ast.Subscript))
              and isinstance(node.ctx, (ast.Store, ast.Del))): effect('state-mutation', node)
    dependency_bindings = sorted({(row['bound'], row['target']) for item in imports
                                  for row in item['bindings']})
    module_index = {}
    for candidate in sources:
        if candidate.startswith('skills/orch-dork/scripts/'):
            name = candidate.removeprefix('skills/orch-dork/scripts/').removesuffix('.py').replace('/', '.')
        elif candidate.startswith('scripts/'):
            name = candidate.removeprefix('scripts/').removesuffix('.py').replace('/', '.')
        elif candidate.startswith('hooks/'):
            name = candidate.removeprefix('hooks/').removesuffix('.py').replace('/', '.')
        else:
            continue
        if name.endswith('.__init__'): name = name.removesuffix('.__init__')
        module_index[name] = candidate
    local_dependencies = {}
    for bound, target in dependency_bindings:
        matches = [(name, candidate) for name, candidate in module_index.items()
                   if target == name or target.startswith(name + '.')]
        if not matches:
            continue
        name, candidate = max(matches, key=lambda row: len(row[0]))
        row = local_dependencies.setdefault(candidate, {'module': name,
            'path': candidate,
            'source_sha256': _sha(sources[candidate].encode()),
            'review_source_sha256': _review_source_sha256(candidate, sources[candidate]),
            'api_sha256': _digest(inventory_modules[candidate]),
            'review_api_sha256': _review_api_sha256(
                candidate, sources[candidate], inventory_modules[candidate]), 'bindings': []})
        row['bindings'].append([bound, target])
    local_dependencies = [{**row, 'bindings': sorted(row['bindings'])}
                          for _, row in sorted(local_dependencies.items())]
    api_bindings = sorted((name, row['kind']) for name, row in module['exports'].items())
    effect_spans = [{'kind': kind, 'count': len(rows),
                     'first_line': min(row['first_line'] for row in rows),
                     'last_line': max(row['last_line'] for row in rows),
                     'members_sha256': _digest(rows)} for kind, rows in sorted(effects.items())]
    dependency_contracts = [{key: row[key] for key in ('path', 'module', 'review_source_sha256',
                            'review_api_sha256', 'bindings')} for row in local_dependencies]
    contract_identity = _digest({'path': path, 'review_source_sha256': review_source_sha256,
        'review_api_sha256': review_api_sha256, 'api_bindings': api_bindings,
        'imports': sorted(imports, key=lambda row: (row['first_line'], row['syntax'])),
        'dependency_bindings': dependency_bindings, 'local_dependencies': dependency_contracts,
        'call_targets': sorted(calls), 'effect_spans': effect_spans})
    result = {'source_sha256': _sha(source.encode()),
            'review_source_sha256': review_source_sha256,
            'source_span_sha256': _sha(source.encode()), 'first_line': 1, 'last_line': len(source.splitlines()),
            'api_sha256': _digest(module), 'review_api_sha256': review_api_sha256,
            'api_bindings': [list(row) for row in api_bindings],
            'imports': sorted(imports, key=lambda row: (row['first_line'], row['syntax'])),
            'dependency_bindings': [list(row) for row in dependency_bindings],
            'local_dependencies': local_dependencies,
            'call_targets': sorted(calls), 'effect_spans': effect_spans,
            'contract_identity': contract_identity}
    if cache_key is not None:
        _MODULE_BASIS_CACHE[key] = result
    return result


def _inert_namespace(source):
    return all(isinstance(node, ast.Pass) or isinstance(node, ast.Expr)
               and isinstance(node.value, ast.Constant) and type(node.value.value) is str
               for node in ast.parse(source).body)


def render_classification_record(*, sources, runtime, registry_components, inventory,
                                 discovery, dispositions):
    """Render exact inventory pins from separately reviewed semantic dispositions.

    Reproducible API: callers rebuild ``sources``/``runtime`` with
    ``read_source_snapshot()``, rebuild ``inventory`` and ``discovery`` from
    those bytes, and pass a path-keyed mapping containing only policy, route and
    semantics. This function grants no classification: ``_classify_groups``
    independently requires the fixed ``SEMANTIC_BASES_SHA256``.
    """
    discovery = discovery.to_plain() if type(discovery) is rv.FrozenValue else discovery
    groups = _classification_groups(sources, inventory, discovery)
    inventory_modules = inventory.to_plain()['modules']
    cache_key = (_digest({p: _sha(text.encode()) for p, text in sources.items()}), inventory.digest())
    _require(type(dispositions) is dict and set(dispositions) <= set(sources),
             'classification_dispositions')
    families, assigned = [], set()
    for path, disposition in sorted(dispositions.items()):
        _require(type(disposition) is dict and set(disposition) == {'policy', 'route', 'semantics'},
                 'classification_disposition_shape')
        members = sorted(key for key, row in groups.items() if row['path'] == path)
        assigned.update(members)
        families.append({'policy': disposition['policy'], 'path': path,
            'route': disposition['route'],
            'basis': {**_module_basis(path, sources, inventory, inventory_modules, cache_key),
                      'semantics': disposition['semantics']}, 'groups': members})
    return {'schema': CLASSIFICATION_SCHEMA,
        'source_hashes': {p: _sha(s.encode()) for p, s in sources.items()},
        'python_source_hashes': runtime['python_source_hashes'],
        'registry_sha256': _digest(registry_components),
        'source_inventory_sha256': inventory.digest(),
        'policy_sha256': REVIEWED_FILES['docs/agents/issue170-source-scope.md'],
        'groups': {key: {k: v for k, v in row.items() if k != 'members'}
                   for key, row in groups.items()},
        'families': families, 'residual_groups': sorted(set(groups) - assigned)}


def _classify_groups(records, *, sources, runtime, registry_components, inventory, groups, lifecycle_paths):
    """Validate fixed family dispositions; missing source bases remain exact gaps.

    This is not a registration API. Production records come only from the exact
    package entry via _classification_original. The family semantics below are
    fixed repository implementations; JSON rationales cannot widen them.
    """
    _require(type(records) is dict and set(records) == {'schema', 'source_hashes', 'python_source_hashes',
        'registry_sha256', 'source_inventory_sha256', 'policy_sha256', 'groups', 'families', 'residual_groups'},
        'classification_shape')
    _require(records['schema'] == CLASSIFICATION_SCHEMA, 'classification_schema')
    _require(records['source_hashes'] == {p: _sha(s.encode()) for p, s in sources.items()}
        and records['python_source_hashes'] == runtime['python_source_hashes']
        and records['source_inventory_sha256'] == inventory.digest()
        and records['registry_sha256'] == _digest(registry_components)
        and records['policy_sha256'] == REVIEWED_FILES['docs/agents/issue170-source-scope.md'],
        'classification_baseline')
    expected = {key: {k: v for k, v in row.items() if k != 'members'} for key, row in groups.items()}
    _require(_digest(records['groups']) == _digest(expected), 'classification_group_inventory')
    _require(type(records['families']) is list and type(records['residual_groups']) is list,
             'classification_partition_shape')
    assigned, families, paths, semantic_bases = set(), {}, {}, {}
    inventory_modules = inventory.to_plain()['modules']
    cache_key = (_digest(records['source_hashes']), inventory.digest())
    for family in records['families']:
        _require(type(family) is dict and set(family) == {'policy', 'path', 'route', 'basis', 'groups'},
                 'classification_family_shape')
        path, policy = family['path'], family['policy']
        _require(type(path) is str and path in sources and path not in paths
                 and type(policy) is str, 'classification_family_identity')
        if policy == 'inert-namespace':
            _require(_inert_namespace(sources[path]), 'classification_namespace_effect')
            route, semantics = 'SUPPORTING_CONTRACT', 'Only a module docstring and/or pass; no exported API, alias, call or state effect.'
        elif policy in _FAMILY_BASES:
            fixed = _FAMILY_BASES.get(policy)
            _require(fixed is not None and fixed['path'] == path
                     and fixed['source_sha256'] == _sha(sources[path].encode()), 'classification_source_policy')
            route, semantics = fixed['route'], fixed['semantics']
        else:
            _require(family['route'] in ('LIFECYCLE_SEMANTICS', 'SUPPORTING_CONTRACT',
                                        'SEPARATE_FEATURE'), 'classification_disposition')
            route, semantics = family['route'], family['basis'].get('semantics')
            _require(type(semantics) is str and bool(semantics), 'classification_source_policy')
        _require(family['route'] == route, 'classification_disposition')
        _require(route == 'LIFECYCLE_SEMANTICS' or path not in lifecycle_paths,
                 'classification_lifecycle_conflict')
        if policy in ('canonical-data', 'immutable-data'):
            # These two reviewed contracts import only fixed stdlib primitives
            # and the canonical-data module under one inert package initializer.
            shadows = {p.rsplit('/', 1)[-1].removesuffix('.py') for p in sources}
            shadows.update(p.split('/')[-2] for p in sources if p.endswith('/__init__.py'))
            _require(not shadows.intersection({'hashlib', 'json', 'math', 're', '__future__'}),
                     'classification_dependency_shadow')
            if policy == 'immutable-data':
                dependency = _FAMILY_BASES['canonical-data']
                package = dependency['path'].removesuffix('values.py') + '__init__.py'
                _require(_sha(sources[dependency['path']].encode()) == dependency['source_sha256']
                         and _inert_namespace(sources[package])
                         and [p for p in sources if p.endswith('/lifecycle_conformance/__init__.py')] == [package]
                         and not any(p.rsplit('/', 1)[-1] == 'lifecycle_conformance.py' for p in sources)
                         and [p for p in sources if p.endswith('/lifecycle_conformance/values.py')] == [dependency['path']],
                         'classification_dependency_binding')
        basis = {**_module_basis(path, sources, inventory, inventory_modules, cache_key),
                 'semantics': semantics}
        _require(_digest(family['basis']) == _digest(basis), 'classification_source_basis')
        semantic = {'policy': policy, 'route': route, 'semantics': semantics}
        identity = basis['contract_identity']
        _require(identity not in semantic_bases or semantic_bases[identity] == semantic,
                 'classification_contract_identity')
        semantic_bases[identity] = semantic
        members = family['groups']
        _require(type(members) is list and members == sorted(key for key, row in groups.items() if row['path'] == path),
                 'classification_family_members')
        _require(not assigned.intersection(members), 'classification_duplicate_group')
        assigned.update(members)
        identity = 'source-family:' + _digest(family)
        families[identity] = family
        paths[path] = {'family': identity, 'route': route, 'groups': members}
    _require(_digest(semantic_bases) == SEMANTIC_BASES_SHA256, 'classification_semantic_bases')
    residual = records['residual_groups']
    _require(all(type(key) is str for key in residual) and len(residual) == len(set(residual))
             and not assigned.intersection(residual) and set(residual) | assigned == set(groups),
             'classification_partition_union')
    classified = {key: {**row, 'status': 'SOURCE_CLASSIFIED' if key in assigned else 'SOURCE_REVIEW_REQUIRED',
                       'disposition': paths.get(row['path'])} for key, row in groups.items()}
    return {'status': 'PASS' if not residual else 'PARTIAL', 'groups': classified,
            'families': families, 'paths': paths, 'residual_groups': sorted(residual),
            'complete': not residual, 'record_sha256': _digest(records),
            'independent_source_review_required': True,
            'execution_attested': False, 'qualification_authorized': False}


def _registry_binding(components):
    from lifecycle_conformance import host_fixtures, host_mcp_fixtures, injection_sites, replays
    def records(report):
        return {key: row for rows in report['registry'].values() for key, row in rows.items()}
    sites = injection_sites.site_registry()
    expected = {'replays': records(replays.replay()), 'host_fixtures': records(host_fixtures.replay()),
        'host_mcp_fixtures': records(host_mcp_fixtures.replay()),
        'injection_sites': injection_sites.inventory(sites).to_plain(),
        'injection_schedule': {row['id']: row for row in injection_sites.schedule(sites).to_plain()}}
    _require(type(components) is dict and rv.freeze(components) == rv.freeze(expected), 'registry_binding')


def _discovery(sources):
    """Supplement public discovery with lexical bindings/aliases/effect candidates.

    A call is an effect candidate, not a separate required test. Records are
    grouped by module and owner; unresolved semantics stay review work.
    """
    modules = {}
    for path, source in sorted(sources.items()):
        rows = {'bindings': {}, 'aliases': {}, 'effects': {}}
        source_sha = _sha(source.encode())
        def add(kind, node, owner, detail):
            row = {'owner': owner, 'line': node.lineno, 'column': node.col_offset,
                   'end_line': node.end_lineno, 'end_column': node.end_col_offset,
                   'syntax': type(node).__name__,
                   'syntax_sha256': _sha(ast.dump(node, include_attributes=False).encode()), **detail}
            identity = 'scope-item:' + _digest({'path': path, 'source_sha256': source_sha,
                                               'kind': kind, **row})
            rows[kind][identity] = row
        def visit(node, owner):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                add('bindings', node, owner, {'name': node.name})
                owner = owner + '.' + node.name if owner else node.name
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                add('bindings', node, owner, {'name': node.id})
            elif isinstance(node, ast.arg):
                add('bindings', node, owner, {'name': node.arg})
            elif isinstance(node, ast.alias):
                bound = node.asname or node.name.split('.')[0]
                add('bindings', node, owner, {'name': bound})
                add('aliases', node, owner, {'target': node.name, 'bound': bound})
            elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
                add('bindings', node, owner, {'name': node.name})
            elif isinstance(node, ast.MatchMapping) and node.rest:
                add('bindings', node, owner, {'name': node.rest})
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                add('bindings', node, owner, {'names': node.names})
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and isinstance(
                    node.value, (ast.Name, ast.Attribute, ast.Subscript, ast.Lambda)):
                add('aliases', node, owner, {'target': ast.unparse(node.value)})
            if (isinstance(node, (ast.Call, ast.Await, ast.Yield, ast.YieldFrom, ast.Raise,
                                  ast.Import, ast.ImportFrom, ast.AugAssign, ast.Delete))
                    or isinstance(node, (ast.Attribute, ast.Subscript))
                    and isinstance(node.ctx, (ast.Store, ast.Del))):
                add('effects', node, owner, {'kind': type(node).__name__})
            for child in ast.iter_child_nodes(node):
                visit(child, owner)
        visit(ast.parse(source, filename=path), '')
        modules[path] = {'source_sha256': source_sha, **rows}
    return rv.freeze(modules)


def build_originals(sources, registry_components, observations, *, semantic_cases=()):
    """Construct originals to preserve, without execution or closure authority."""
    evidence = public_pair_evidence.build_evidence(sources, observations)
    coverage = coverage_manifest._classified_checklist(sources, registry_components)
    if evidence.to_plain()['pairs']:
        coverage, _ = coverage_manifest._paired_checklist(
            {'public_pair_evidence': evidence.to_plain(), 'coverage': coverage}, sources, observations)
    return {'schema': ORIGINALS_SCHEMA, 'reviewed_files': _review_files(),
        'inventory': public_inventory.build_inventory(sources),
        'discovery': _discovery(sources),
        'supporting_imports': public_pair_registry.classify_supporting_imports(sources),
        'pair_evidence': evidence,
        'pair_registry': public_pair_registry.build_registry(sources, observations, modules=sorted(sources)),
        'coverage': rv.freeze(coverage), 'observations': observations,
        'case_index': {row['case']: _digest(row) for row in observations},
        'semantic_cases': list(semantic_cases)}


def _semantic_bindings(cases, evidence, observations, sources):
    """Check exact capture references; semantic applicability remains reviewed work.

    A label supplied here never declares the full PASS or failure partition set.
    Required negatives are retained independently of successful handoffs.
    """
    _require(type(cases) is list, 'semantic_cases')
    originals = {row['case']: row for row in observations}
    result = {}
    for row in cases:
        _require(type(row) is dict and set(row) == {
            'partition', 'pair', 'case', 'producer_sequence', 'validator_sequence', 'negatives'},
            'semantic_case_shape')
        _require(type(row['pair']) is str and type(row['case']) is str
                 and type(row['producer_sequence']) is int and row['producer_sequence'] >= 0,
                 'semantic_case_identity')
        partition = row['partition']
        _require(type(partition) is dict and set(partition) == {
            'path', 'source_sha256', 'first_line', 'last_line', 'text_sha256'}, 'partition_shape')
        path, first, last = partition['path'], partition['first_line'], partition['last_line']
        _require(type(path) is str and path in sources and type(first) is int and type(last) is int
                 and 1 <= first <= last <= len(sources[path].splitlines()), 'partition_source')
        text = '\n'.join(sources[path].splitlines()[first - 1:last])
        _require(partition['source_sha256'] == _sha(sources[path].encode())
                 and partition['text_sha256'] == _sha(text.encode()), 'partition_binding')
        pair = evidence['pairs'].get(row['pair'])
        _require(type(pair) is dict and row['case'] in originals, 'semantic_pair_case')
        outputs = [item for item in pair['outputs'] if item['case'] == row['case']
                   and item['producer_sequence'] == row['producer_sequence']]
        _require(len(outputs) == 1 and not outputs[0]['enclosing_validator_sequences']
                 and type(row['validator_sequence']) is int
                 and row['validator_sequence'] in outputs[0]['validator_sequences'], 'original_consumer')
        _require(path == pair['declaration']['producer']['path'], 'partition_producer_source')
        _require(type(row['negatives']) is list, 'negative_cases')
        seen = set()
        for negative in row['negatives']:
            _require(type(negative) is dict and set(negative) == {'case', 'validator_sequence'}, 'negative_shape')
            key = (negative['case'], negative['validator_sequence'])
            _require(type(key[0]) is str and type(key[1]) is int and key not in seen
                     and key[0] in originals, 'negative_original')
            seen.add(key)
            events = originals[key[0]]['events']
            _require(0 <= key[1] < len(events), 'negative_original')
            event = events[key[1]]
            _require(event['role'] == 'validator' and event['accepted'] is False
                     and event['pair'] == pair['declaration']['name'], 'negative_acceptance')
        identity = 'scope-partition:' + _digest(row)
        _require(identity not in result, 'duplicate_partition')
        result[identity] = {'original': row, 'observation_sha256': _digest(originals[row['case']]),
            'whole_output_sha256': outputs[0]['value_sha256'],
            'consumer_result_sha256': originals[row['case']]['events'][row['validator_sequence']]['result_sha256'],
            'status': 'CAPTURE_BINDINGS_VALIDATED', 'semantic_partition_reviewed': False,
            'required_negatives_complete': False, 'execution_attested': False}
    return result


def build_scope_report(*, sources, runtime, registry_components, originals):
    """Rebuild source scope, retaining exact unresolved groups and evidence limits."""
    snapshot = read_source_snapshot()
    _require(type(sources) is dict and sources == snapshot['sources'], 'complete_source_binding')
    _require(type(runtime) is dict and rv.freeze(runtime) == rv.freeze(snapshot['runtime']), 'runtime_binding')
    _registry_binding(registry_components)
    _require(type(originals) is dict and set(originals) == {
        'schema', 'reviewed_files', 'inventory', 'discovery', 'supporting_imports', 'pair_evidence',
        'pair_registry', 'coverage', 'observations', 'case_index', 'semantic_cases'}, 'originals_shape')
    _require(originals['schema'] == ORIGINALS_SCHEMA, 'originals_schema')
    backlog_reader, policy_reader = _policy_readers(originals['reviewed_files'])
    classification_records = _classification_original(originals['reviewed_files'], runtime)
    observations = originals['observations']
    public_inventory.validate_inventory(originals['inventory'], sources)
    _require(type(originals['discovery']) is rv.FrozenValue and originals['discovery'] == _discovery(sources),
             'discovery_binding')
    public_pair_registry.validate_supporting_imports(originals['supporting_imports'], sources)
    public_pair_evidence.validate_evidence(originals['pair_evidence'], sources, observations)
    public_pair_registry.validate_registry(originals['pair_registry'], sources, observations, modules=sorted(sources))
    _require(originals['case_index'] == {row['case']: _digest(row) for row in observations}, 'case_union')
    pairs = originals['pair_evidence'].to_plain()
    coverage = coverage_manifest._classified_checklist(sources, registry_components)
    if pairs['pairs']:
        coverage, _ = coverage_manifest._paired_checklist(
            {'public_pair_evidence': pairs, 'coverage': coverage}, sources, observations)
    _require(type(originals['coverage']) is rv.FrozenValue and originals['coverage'] == rv.freeze(coverage),
             'classification_binding')
    semantic = _semantic_bindings(originals['semantic_cases'], pairs, observations, sources)
    raw = backlog_reader.build_backlog(sources, registry_components, accepted_coverage=coverage)
    work = policy_reader.build_worklist(sources, registry_components,
        policy_source=originals['reviewed_files']['tests/fixtures/issue170_source_scope.json'],
        accepted_coverage=coverage)
    groups = {key: {**row, 'work': work['groups'][key]} for key, row in raw['groups'].items()}
    discovery = originals['discovery'].to_plain()
    classification_groups = _classification_groups(sources, originals['inventory'], discovery)
    lifecycle_paths = {reference['path'] for pair in pairs['pairs'].values()
                       for reference in (pair['declaration']['producer'], pair['declaration']['validator'])}
    lifecycle_paths.update(row['path'] for row in coverage['obligations'].values()
                          if row['status'] in ('CLASSIFIED_DECLARED_LIFECYCLE_ROLE', 'CLASSIFIED_SEEDED_LIFECYCLE_ROLE'))
    classifications = _classify_groups(classification_records, sources=sources, runtime=runtime,
        registry_components=registry_components, inventory=originals['inventory'],
        groups=classification_groups, lifecycle_paths=lifecycle_paths)
    dispositions = classifications['paths']
    supplemental = {}
    for path, module in discovery.items():
        for kind in ('bindings', 'aliases', 'effects'):
            owners = {}
            for identity, row in module[kind].items():
                owners.setdefault(row['owner'], []).append(identity)
            for owner, members in sorted(owners.items()):
                identity = 'scope-group:' + _digest({'path': path, 'owner': owner, 'kind': kind})
                supplemental[identity] = {'path': path, 'owner': owner, 'kind': kind,
                    'members': sorted(members), 'member_sha256': _digest({i: module[kind][i] for i in members}),
                    'status': 'SOURCE_CLASSIFIED' if path in dispositions else
                              'ENUMERATED' if kind == 'bindings' else 'SOURCE_REVIEW_REQUIRED'}
    remaining = [
        {'kind': ({'LIFECYCLE_SEMANTICS': 'lifecycle_semantic_evidence',
                   'SUPPORTING_CONTRACT': 'supporting_contract_evidence',
                   'SEPARATE_FEATURE': 'separate_feature_evidence'}[
                       dispositions[row['scope']]['route']]) if row['scope'] in dispositions else 'source_group',
         'group': key, 'work_kind': row['work']['work_kind'],
         'pending_obligation_ids': row['pending_obligation_ids']}
        for key, row in groups.items() if row['pending_obligation_ids']]
    remaining += [{'kind': 'source_classification', 'group': key,
                   'path': classification_groups[key]['path'], 'members': classification_groups[key]['members']}
                  for key in classifications['residual_groups']]
    remaining += [{'kind': 'source_' + row['kind'], 'group': key, 'members': row['members']}
                  for key, row in supplemental.items() if row['status'] == 'SOURCE_REVIEW_REQUIRED']
    if not work['reviewed_baseline_matches'] and not classifications['complete']:
        remaining.append({'kind': 'reviewed_policy_baseline_stale',
            'required': 'Fresh source-backed scope review of the complete source and registry baseline.'})
    remaining += [{'kind': 'semantic_partition_and_required_negative_review', 'pair': key,
                   'required': 'Reviewed successful alternatives and required failures; whole original handoffs and host custody.'}
                  for key in sorted(pairs['pairs'])]
    remaining += [{'kind': 'independent_pair_gap', 'gap': gap} for gap in pairs['gaps']]
    nonruntime = sorted(set(sources) - set(runtime['python_source_hashes']))
    if nonruntime:
        remaining.append({'kind': 'broader_source_scope', 'paths': nonruntime,
            'required': 'Retain scope classification separately from runtime package membership.'})
    remaining.append({'kind': 'execution_custody',
        'required': 'Source decisions and captured pair matches do not attest executed semantic closure.'})
    roles = originals['pair_registry'].to_plain()
    binding_effects = {path: row['effects'] for path, row in roles['modules'].items()
                      if any(row['effects'].values())}
    remaining += [{'kind': 'source_binding_effects', 'path': path, 'effects': effects}
                  for path, effects in binding_effects.items() if path not in dispositions]
    unresolved_kinds = {classification_groups[key]['kind'] for key in classifications['residual_groups']}
    exports_classified = 'exports' not in unresolved_kinds
    effects_classified = not unresolved_kinds.intersection({'effects', 'module_effects'})
    aliases_classified = 'aliases' not in unresolved_kinds
    scope_complete = classifications['complete']
    # Source-only facts are derived separately from execution and semantic facts.
    facts = ['public_inventory_complete']
    for fact, established in (('exports_classified', exports_classified),
                              ('effects_classified', effects_classified),
                              ('source_scope_complete', scope_complete)):
        if established:
            facts.append(fact)
    return rv.freeze({'schema': SCHEMA, 'status': 'BLOCKED' if remaining else 'PASS',
        'facts': facts, 'source_roots': list(SOURCE_ROOTS),
        'runtime': runtime, 'source_hashes': {p: _sha(s.encode()) for p, s in sources.items()},
        'source_inventory_sha256': originals['inventory'].digest(),
        'registry_sha256': _digest(registry_components),
        'reviewed_file_sha256': {p: _sha(b) for p, b in originals['reviewed_files'].items()},
        'original_sha256': {k: _digest(v) for k, v in originals.items() if k != 'reviewed_files'},
        'inventory': originals['inventory'].to_plain(), 'discovery': discovery,
        'binding_effects': binding_effects,
        'source_classification': classifications,
        'groups': groups, 'supplemental_groups': supplemental, 'worklist': work,
        'coverage': coverage, 'pair_evidence': pairs, 'semantic_bindings': semantic,
        'remaining_requirements': remaining,
        'exports_classified': exports_classified, 'effects_classified': effects_classified,
        'aliases_classified': aliases_classified,
        'source_scope_complete': scope_complete, 'pass_branches_closed': False,
        'execution_attested': False, 'release_authorized': False, 'qualification_authorized': False})


def validate_complete_scope(report, **inputs):
    """Validate exact report readback; callers must inspect facts and remaining gaps."""
    _require(type(report) is rv.FrozenValue and report == build_scope_report(**inputs), 'report_binding')


__all__ = ['SCHEMA', 'ORIGINALS_SCHEMA', 'read_source_snapshot', 'build_originals',
           'render_classification_record', 'build_scope_report', 'validate_complete_scope']
