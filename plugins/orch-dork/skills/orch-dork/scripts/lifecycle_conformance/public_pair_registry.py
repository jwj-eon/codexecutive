"""Rebuild selected public roles and seed witnesses from source and observations.

This is a source classification, not an execution attestation. Literal bindings
describe syntax; they do not certify a module's imported runtime state. All pair
evidence gaps survive, including internal builds and unproved PASS branches.
"""
from __future__ import annotations

import ast

from lifecycle_conformance import public_inventory, public_pair_evidence, reference_values as rv, values

__all__ = ['build_registry', 'validate_registry', 'classify_supporting_imports',
           'validate_supporting_imports']
_SCHEMA = 'orch-dork/source-bound-public-pair-registry/v2'

# Closed source-role policy. These imported library APIs are supporting tools;
# local lifecycle functions that use them keep every branch/return obligation.
# This list is independent of the interpreter's ambient import search path.
_SUPPORT_MODULES = ('ast', 'dis', 'errno', 'hashlib', 'json', 'multiprocessing',
                    'os', 'pty', 'select', 'signal', 'socket', 'stat', 'subprocess',
                    'sys', 'tempfile', 'threading', 'time', 'types')
_SUPPORT_MEMBERS = {'bisect': ('bisect_left',),
                    'concurrent.futures': ('ProcessPoolExecutor',), 'pathlib': ('Path',)}


def _refuse(reason):
    raise values.LifecycleContractError('public_pair_registry:' + reason)


def _passive(expression):
    """Conservatively recognize local binding syntax without evaluating it."""
    if expression is None or isinstance(expression, (ast.Constant, ast.Name)):
        return True
    if isinstance(expression, (ast.Tuple, ast.List)):
        return all(_passive(item) for item in expression.elts)
    if isinstance(expression, ast.Set):
        # Literal strings use built-in hashing; names could invoke user code.
        return all(isinstance(item, ast.Constant) and type(item.value) is str for item in expression.elts)
    # Dicts and other set expressions remain pending, including bare names.
    return False


def _local_bindings(source, exports):
    tree = ast.parse(source)
    deferred = any(isinstance(node, ast.ImportFrom) and node.module == '__future__'
                   and any(alias.name == 'annotations' for alias in node.names) for node in tree.body)
    literals, effects = {}, []
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if (len(targets) == 1 and isinstance(targets[0], ast.Name)
                    and isinstance(node.value, ast.Constant) and type(node.value.value) is str):
                name = targets[0].id
                if exports.get(name) == {'kind': 'value', 'line': node.lineno}:
                    literals[name] = {'kind': 'literal_string_binding', 'line': node.lineno,
                                      'value': node.value.value}
            if (not all(isinstance(target, ast.Name) for target in targets) or not _passive(node.value)
                    or (isinstance(node, ast.AnnAssign) and not deferred and not _passive(node.annotation))):
                effects.append({'line': node.lineno, 'kind': 'dynamic_binding_expression'})
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
            annotations = [arg.annotation for arg in arguments] + [node.returns]
            annotations += [arg.annotation for arg in (node.args.vararg, node.args.kwarg) if arg]
            if (node.decorator_list or getattr(node, 'type_params', [])
                    or not all(_passive(item) for item in (*node.args.defaults, *node.args.kw_defaults))
                    or (not deferred and not all(_passive(item) for item in annotations))):
                effects.append({'line': node.lineno, 'kind': 'dynamic_function_binding'})
        elif isinstance(node, ast.ClassDef):
            # Class bodies and metaclasses require a separate explicit classification.
            effects.append({'line': node.lineno, 'kind': 'class_binding_classification_pending'})
    return literals, effects


def build_registry(sources: dict[str, str], observations: list[dict], *, modules: list[str]) -> rv.FrozenValue:
    """Account for an explicit module subset while retaining every other module."""
    inventory = public_inventory.build_inventory(sources)
    inventory_data = inventory.to_plain()['modules']
    if (type(modules) is not list or not 1 <= len(modules) <= len(inventory_data)
            or any(type(path) is not str or path not in inventory_data for path in modules)
            or len(set(modules)) != len(modules)):
        _refuse('modules')
    evidence = public_pair_evidence.build_evidence(sources, observations)
    data = evidence.to_plain()
    selected = set(modules)
    symbols_by_module = {path: {} for path in selected}
    pairs_by_symbol, seeds = {}, {}
    for pair_id, pair in sorted(data['pairs'].items()):
        relevant = False
        for role in ('producer', 'validator'):
            reference = pair['declaration'][role]
            if reference['path'] in selected:
                symbol = reference['path'] + '#' + reference['name']
                pairs_by_symbol.setdefault(symbol, {}).setdefault(role, []).append(pair_id)
                relevant = True
        if relevant:
            witnesses = [output for output in pair['outputs'] if output['validator_sequences']
                         and not output['enclosing_validator_sequences']]
            seeds[pair_id] = {'witnesses': witnesses, 'seed_present': bool(witnesses)}
    for symbol, info in data['symbols'].items():
        path = symbol.split('#', 1)[0]
        if path in selected:
            symbols_by_module[path][symbol] = info
    pending = sorted(set(inventory_data) - selected)
    gaps = [{'kind': 'module_classification_pending', 'path': path} for path in pending]
    rows = {}
    for path in sorted(selected):
        module = inventory_data[path]
        literals, local_effects = _local_bindings(sources[path], module['exports'])
        effects = {'inventory': data['source_effects'].get(path), 'local_bindings': local_effects}
        accounted = not any(effects.values())
        if not accounted:
            gaps.append({'kind': 'source_role_effects_pending', 'path': path})
        symbols, pair_ids = {}, set()
        for symbol, info in sorted(symbols_by_module[path].items()):
            name = symbol.split('#', 1)[1]
            roles = pairs_by_symbol.get(symbol)
            if info['kind'] == 'function' and roles:
                symbols[symbol] = {'kind': 'paired_function', 'roles': roles}
                pair_ids.update(pair_id for role_pairs in roles.values() for pair_id in role_pairs)
            elif name in literals:
                symbols[symbol] = literals[name]
            else:
                symbols[symbol] = {'kind': 'unclassified', 'source_kind': info['kind']}
                gaps.append({'kind': 'public_role_unclassified', 'symbol': symbol})
                accounted = False
        missing = sorted(pair_id for pair_id in pair_ids if not seeds[pair_id]['seed_present'])
        gaps.extend({'kind': 'pair_seed_missing', 'path': path, 'pair': pair_id} for pair_id in missing)
        rows[path] = {'source_sha256': module['source_sha256'], 'symbols': symbols, 'effects': effects,
                      'roles_accounted': accounted, 'seed_pairs_complete': not missing,
                      'pair_ids': sorted(pair_ids)}
    return rv.freeze({'schema': _SCHEMA, 'status': 'SOURCE_ROLES_BOUND_GAPS_REMAIN',
                      'inventory_sha256': inventory.digest(), 'evidence_sha256': evidence.digest(),
                      'modules': rows, 'pending_modules': pending, 'pair_seeds': seeds, 'role_gaps': gaps,
                      'evidence_gaps': data['gaps'],
                      'selected_modules_accounted': all(row['roles_accounted'] and row['seed_pairs_complete']
                                                       for row in rows.values()),
                      'module_selection_verified': False, 'execution_attested': False,
                      'pass_branches_closed': False, 'qualification_authorized': False})


def validate_registry(registry: rv.FrozenValue, sources: dict[str, str], observations: list[dict],
                      *, modules: list[str]) -> None:
    """Rebuild from original inputs; a self-sealed role or seed omission fails."""
    if type(registry) is not rv.FrozenValue or registry != build_registry(sources, observations, modules=modules):
        _refuse('registry_binding')


def _local_namespace_source(sources, modules, node, name):
    """Locate declared module source, without claiming a runtime import result."""
    # Private names can select built-in package attributes such as __init__.
    if node.module != 'lifecycle_conformance' or node.level != 0 or name.startswith('_'):
        return None
    packages = [path for path in sources if path == 'lifecycle_conformance/__init__.py'
                or path.endswith('/lifecycle_conformance/__init__.py')]
    if len(packages) != 1 or any(path.rsplit('/', 1)[-1] == 'lifecycle_conformance.py' for path in sources):
        return None
    package = packages[0]
    initializer = ast.parse(sources[package]).body
    if not all(isinstance(row, ast.Pass) or isinstance(row, ast.Expr)
               and isinstance(row.value, ast.Constant) and type(row.value.value) is str for row in initializer):
        return None
    target = package.removesuffix('__init__.py') + name + '.py'
    if target not in modules:
        return None
    return {'package_path': package, 'package_sha256': modules[package]['source_sha256'],
            'module_path': target, 'module_sha256': modules[target]['source_sha256']}


def classify_supporting_imports(sources: dict[str, str]) -> rv.FrozenValue:
    """Resolve only unambiguous implicit supporting-import source roles.

    Explicit API exports, module effects, dynamic definitions, relative imports,
    unlisted library members and possible source shadows remain decisions.
    Local module namespaces require one source package with an inert initializer
    and an inventoried child module. Its callable and effect obligations remain
    separate, including whether that module can actually be imported. This source
    classification neither imports code nor proves runtime namespace custody.
    """
    inventory = public_inventory.build_inventory(sources)
    modules = inventory.to_plain()['modules']
    source_names = {path.split('/')[-2] if path.endswith('/__init__.py')
                    else path.rsplit('/', 1)[-1].removesuffix('.py') for path in sources}
    decisions, deferred = {}, {}
    for path, module in modules.items():
        imports = {name: row for name, row in module['exports'].items() if row['kind'] == 'import'}
        if not imports:
            continue
        blocked = ('explicit_public_export' if module['export_mode'] != 'public_names' else
                   'unresolved_module_effects' if module['unresolved_module_effects'] else None)
        if blocked is None and _local_bindings(sources[path], module['exports'])[1]:
            blocked = 'dynamic_binding_effects'
        nodes = {}
        if not blocked:
            for node in ast.parse(sources[path], filename=path).body:
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        bound = alias.asname or (alias.name.split('.')[0] if isinstance(node, ast.Import) else alias.name)
                        nodes[(node.lineno, bound)] = node
        for name, export in imports.items():
            identity = path + '#' + name + ':role'
            # Derive only the import-role row. Manifest consumption compares
            # this exact digest with the independently discovered obligation.
            obligation = {'path': path, 'source_sha256': module['source_sha256'],
                'line': export['line'], 'exported': True, 'kind': 'symbol_role', 'status': 'PENDING',
                'reason': 'Import syntax; possible public re-export remains unclassified.'}
            binding = {'path': path, 'source_sha256': module['source_sha256'],
                       'line': export['line'], 'name': name,
                       'obligation_sha256': values.canonical_digest(obligation)}
            if blocked:
                deferred[identity] = {**binding, 'reason': blocked}
                continue
            node = nodes[(export['line'], name)]
            origin, imported_module, namespace = None, None, None
            if isinstance(node, ast.Import):
                alias = next(item for item in node.names if (item.asname or item.name.split('.')[0]) == name)
                imported_module = alias.name
                if imported_module in _SUPPORT_MODULES:
                    origin = imported_module
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                alias = next(item for item in node.names if (item.asname or item.name) == name)
                imported_module = node.module
                if alias.name in _SUPPORT_MEMBERS.get(imported_module, ()):
                    origin = imported_module + '.' + alias.name
                else:
                    namespace = _local_namespace_source(sources, modules, node, alias.name)
                    if namespace is not None:
                        origin = imported_module + '.' + alias.name
            reason = ('unlisted_import_origin' if origin is None else
                      'possible_source_shadow' if namespace is None
                      and set(imported_module.split('.')) & source_names else None)
            if reason:
                deferred[identity] = {**binding, 'reason': reason}
                continue
            decisions[identity] = {**binding, 'status': 'CLASSIFIED_SUPPORTING_SOURCE',
                'role': 'supporting_standard_library_import', 'origin': origin,
                'import_syntax': ast.get_source_segment(sources[path], node),
                'rationale': 'Implicit standard-library support import under the closed source policy; '
                             'local callable, PASS-branch and runtime-custody obligations remain separate.'}
            if namespace is not None:
                decisions[identity].update(role='supporting_local_module_namespace', namespace_source=namespace,
                    rationale='Implicit local module namespace with unique package and child source; '
                              'the target APIs, import-time effects, PASS branches and runtime namespace custody '
                              'remain independently inventoried obligations.')
    return rv.freeze({'schema': 'orch-dork/supporting-source-role-classification/v2',
        'source_inventory_sha256': inventory.digest(),
        'decisions': decisions, 'deferred_imports': deferred,
        'classified_roles': len(decisions), 'pending_import_roles': len(deferred),
        'runtime_namespace_verified': False, 'module_selection_verified': False,
        'pass_branches_closed': False, 'execution_attested': False, 'qualification_authorized': False})


def validate_supporting_imports(report: rv.FrozenValue, sources: dict[str, str]) -> None:
    """Rebuild every source decision; changed source/effects invalidate readback."""
    if type(report) is not rv.FrozenValue or report != classify_supporting_imports(sources):
        _refuse('supporting_role_binding')
