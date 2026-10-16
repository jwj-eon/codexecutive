"""Inventory a supplied lifecycle source snapshot without importing its code.

This is source discovery, not executed pair or PASS-branch coverage. The campaign
must own the complete module selection and classify every export, including
aliases and values whose callable nature cannot be resolved statically.
"""
from __future__ import annotations

import ast
import hashlib
import re

from lifecycle_conformance import reference_values as rv, values

SCHEMA = "orch-dork/public-lifecycle-source-inventory/v1"
_PATH = re.compile(r"(?:[a-zA-Z_][a-zA-Z_0-9-]*/)*[a-zA-Z_][a-zA-Z_0-9]*\.py\Z")
MAX_MODULES = 256
MAX_MODULE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 16_000_000


def _refuse(reason):
    raise values.LifecycleContractError("public_inventory:" + reason)


def _names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for item in target.elts for name in _names(item)]
    return []


def _returns(node):
    """Return sites owned by this function, excluding nested callable bodies."""
    sites = []

    def visit(child):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return
        if isinstance(child, ast.Return):
            sites.append({"line": child.lineno, "column": child.col_offset,
                          "end_line": child.end_lineno, "end_column": child.end_col_offset})
        for nested in ast.iter_child_nodes(child):
            visit(nested)

    for child in node.body:
        visit(child)
    return sorted(sites, key=lambda site: (site["line"], site["column"]))


def _module(source, path):
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, RecursionError):
        _refuse("source_syntax")
    bindings, declared, unresolved = {}, None, []
    for node in tree.body:
        names = []
        kind = "value"
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [name for target in targets for name in _names(target)]
            if "__all__" in names:
                if declared is not None:
                    _refuse("reassigned_exports")
                try:
                    declared = ast.literal_eval(node.value)
                except (ValueError, TypeError, RecursionError):
                    _refuse("dynamic_exports")
                if (type(declared) not in (list, tuple)
                        or any(type(name) is not str or not name.isidentifier() for name in declared)
                        or len(declared) != len(set(declared))):
                    _refuse("export_names")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                continue
            kind = "import"
            names = [item.asname or (item.name.split(".")[0] if isinstance(node, ast.Import) else item.name)
                     for item in node.names]
            if "*" in names:
                unresolved.append({"line": node.lineno, "kind": "star_import"})
                names.remove("*")
        elif isinstance(node, (ast.If, ast.Try, ast.With, ast.For, ast.While, ast.Match, ast.TryStar)):
            # Conditional declarations and mutations need explicit closure by
            # the owning campaign; they cannot disappear from the inventory.
            unresolved.append({"line": node.lineno, "kind": "module_control_flow"})
        elif isinstance(node, (ast.AugAssign, ast.Delete)):
            unresolved.append({"line": node.lineno, "kind": "module_binding_mutation"})
        elif isinstance(node, ast.Expr) and not isinstance(node.value, ast.Constant):
            unresolved.append({"line": node.lineno, "kind": "module_expression"})
        elif not isinstance(node, (ast.Expr, ast.Pass)):
            unresolved.append({"line": node.lineno, "kind": "module_statement"})
        for name in names:
            if name in bindings:
                unresolved.append({"line": node.lineno, "kind": "rebound_name", "name": name})
            bindings[name] = (kind, node)

    exports = sorted(declared if declared is not None else (name for name in bindings if not name.startswith("_")))
    rows = {}
    for name in exports:
        if name not in bindings:
            rows[name] = {"kind": "unresolved_export", "line": None}
            continue
        kind, node = bindings[name]
        row = {"kind": kind, "line": node.lineno}
        if kind == "function":
            row["return_sites"] = _returns(node)
        elif kind == "class":
            effects = []
            if node.bases:
                effects.append({"line": node.lineno, "kind": "inherited_members"})
            if node.decorator_list:
                effects.append({"line": node.lineno, "kind": "decorated_class"})
            seen = set()
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if member.name in seen:
                        effects.append({"line": member.lineno, "kind": "rebound_method", "name": member.name})
                    seen.add(member.name)
                    if member.decorator_list:
                        effects.append({"line": member.lineno, "kind": "decorated_method", "name": member.name})
                elif isinstance(member, (ast.Assign, ast.AnnAssign)):
                    targets = member.targets if isinstance(member, ast.Assign) else [member.target]
                    for bound in (name for target in targets for name in _names(target)):
                        if bound in seen:
                            effects.append({"line": member.lineno, "kind": "rebound_class_member", "name": bound})
                        seen.add(bound)
                elif not isinstance(member, (ast.Assign, ast.AnnAssign, ast.Pass)) and not (
                    isinstance(member, ast.Expr) and isinstance(member.value, ast.Constant)
                ):
                    effects.append({"line": member.lineno, "kind": "class_body_effect"})
            row["methods"] = {
                method.name: {"line": method.lineno, "return_sites": _returns(method)}
                for method in node.body
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                and (not method.name.startswith("_") or method.name in ("__init__", "__new__"))
            }
            row["unresolved_class_effects"] = effects
        rows[name] = row
    return {"export_mode": "declared" if declared is not None else "public_names",
            "exports": rows, "unresolved_module_effects": unresolved}


def build_inventory(sources: dict[str, str]) -> rv.FrozenValue:
    """Bind exact source bytes and all visible exports, with no import or IO."""
    if type(sources) is not dict or not 1 <= len(sources) <= MAX_MODULES:
        _refuse("sources")
    encoded, total = {}, 0
    for path, source in sources.items():
        if type(path) is not str or _PATH.fullmatch(path) is None or type(source) is not str:
            _refuse("source_entry")
        try:
            raw = source.encode("utf-8")
        except UnicodeError:
            _refuse("source_encoding")
        total += len(raw)
        if len(raw) > MAX_MODULE_BYTES or total > MAX_TOTAL_BYTES:
            _refuse("source_size")
        encoded[path] = raw
    modules = {path: {"source_sha256": hashlib.sha256(encoded[path]).hexdigest(),
                      **_module(sources[path], path)} for path in sorted(sources)}
    return rv.freeze({"schema": SCHEMA, "modules": modules,
                      "status": "DISCOVERY_NOT_CLOSED", "module_selection_verified": False,
                      "pairs_executed": False, "pass_branches_closed": False,
                      "qualification_authorized": False})


def validate_inventory(inventory: rv.FrozenValue, sources: dict[str, str]) -> None:
    """Rebuild from the whole source snapshot; a resealed omission is invalid."""
    if type(inventory) is not rv.FrozenValue or inventory != build_inventory(sources):
        _refuse("source_binding")


def describe_source_obligations(sources: dict[str, str]) -> rv.FrozenValue:
    """Classify syntax without declaring a helper or PASS branch executed.

    An import can re-export a lifecycle function, and a public definition can
    be missing from __all__. Both stay explicit decisions. Literal metadata is
    the only automatically discharged role; callable bodies retain all return
    sites and control-flow alternatives for semantic PASS-branch classification.
    """
    inventory = build_inventory(sources)
    symbols, obligations = {}, {}
    for path, module in inventory.to_plain()['modules'].items():
        tree = ast.parse(sources[path], filename=path)
        definitions = {node.name: node for node in tree.body
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        assignments = {target.id: node.value for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))
                       for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
                       if isinstance(target, ast.Name)}
        exports = module['exports']
        names = sorted(set(exports) | {name for name in definitions if not name.startswith('_')})
        for name in names:
            node, export = definitions.get(name), exports.get(name)
            base = path + '#' + name
            binding = {'path': path, 'source_sha256': module['source_sha256'],
                       'line': export['line'] if export else node.lineno,
                       'exported': export is not None}
            role = 'role_decision_required'
            reason = 'Public binding requires an explicit lifecycle or supporting-role decision.'
            if export and export['kind'] == 'import':
                role, reason = 'import_binding', 'Import syntax; possible public re-export remains unclassified.'
            elif export and export['kind'] == 'value' and isinstance(assignments.get(name), ast.Constant):
                role, reason = 'literal_metadata', 'An exact AST Constant defines this non-callable binding.'
            elif isinstance(node, ast.ClassDef):
                role, reason = 'class_definition', 'Class construction, public methods and body effects need review.'
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                role, reason = 'function_definition', 'Function syntax alone cannot distinguish constructors, validators and helpers.'
            symbols[base] = {**binding, 'role': role, 'reason': reason}
            if role != 'literal_metadata':
                obligations[base + ':role'] = {**binding, 'kind': 'symbol_role', 'status': 'PENDING', 'reason': reason}
            if export is None:
                obligations[base + ':export'] = {**binding, 'kind': 'undeclared_public_definition', 'status': 'PENDING',
                    'reason': 'Public definition omitted from __all__; decide API scope before pairing.'}
            functions = [(name, node)] if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else (
                [(name + '.' + child.name, child) for child in node.body
                 if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and (not child.name.startswith('_') or child.name in ('__init__', '__new__'))]
                if isinstance(node, ast.ClassDef) else [])
            for qualified, function in functions:
                symbol = path + '#' + qualified
                if qualified != name:
                    symbols[symbol] = {**binding, 'line': function.lineno, 'role': 'method_definition',
                                       'reason': 'Public method requires its own role and branch decision.'}
                    obligations[symbol + ':role'] = {**binding, 'line': function.lineno, 'kind': 'symbol_role',
                                                     'status': 'PENDING', 'reason': symbols[symbol]['reason']}
                for site in _returns(function):
                    identity = symbol + ':return:' + str(site['line']) + ':' + str(site['column'])
                    obligations[identity] = {**binding, **site, 'kind': 'return_site', 'status': 'PENDING',
                        'reason': 'Classify successful/failed return and bind actual accepting-consumer execution.'}
                pending = list(function.body)
                while pending:
                    child = pending.pop()
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                        continue
                    if isinstance(child, (ast.If, ast.IfExp, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.TryStar, ast.Match)):
                        identity = symbol + ':branch:' + str(child.lineno) + ':' + str(child.col_offset)
                        obligations[identity] = {**binding, 'line': child.lineno, 'column': child.col_offset,
                            'end_line': child.end_lineno, 'syntax': type(child).__name__,
                            'kind': 'control_flow_classification', 'status': 'PENDING',
                            'reason': 'Enumerate feasible successful alternatives; a return line alone does not prove branch closure.'}
                    pending.extend(ast.iter_child_nodes(child))
        for index, effect in enumerate(module['unresolved_module_effects']):
            obligations[path + '#module-effect:' + str(index)] = {
                'path': path, 'source_sha256': module['source_sha256'], **effect, 'status': 'PENDING',
                'reason': 'Dynamic module binding or effect requires explicit source review.'}
    return rv.freeze({'schema': 'orch-dork/source-obligation-inventory/v1',
        'source_inventory_sha256': inventory.digest(), 'symbols': symbols, 'obligations': obligations,
        'semantic_branch_inventory_complete': False, 'qualification_authorized': False})
