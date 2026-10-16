"""Bind observed public pairs to source without claiming campaign execution.

This reader independently checks immutable snapshots and declared acceptance.
Host test exits, complete lifecycle role classification and PASS-branch coverage
remain separate requirements. A self-consistent input cannot authorize release.
"""
from __future__ import annotations

import ast
from bisect import bisect_left
import dis
import hashlib
import json
import types

from lifecycle_conformance import public_inventory, reference_values as rv, values

SCHEMA = 'orch-dork/source-bound-public-pair-evidence/v5'
OBSERVATION_SCHEMA = 'orch-dork/declared-public-pair-observations/v2'
BOOLEAN_OBSERVATION_SCHEMA = 'orch-dork/declared-public-pair-observations/v3'
TUPLE_OBSERVATION_SCHEMA = 'orch-dork/declared-public-pair-observations/v4'
NESTED_OBSERVATION_SCHEMA = 'orch-dork/declared-public-pair-observations/v5'
MAX_REPORTS = 256
MAX_EVENTS = 40_000
MAX_CALLS = 20_000
MAX_SYMBOLS = 20_000
MAX_VALUE_BYTES = 4_000_000
MAX_TOTAL_BYTES = 64_000_000
MAX_MATCHES = 100_000
_REPORT_FIELDS = {'schema', 'status', 'case', 'declarations', 'sources', 'snapshots',
                  'events', 'matches', 'calls', 'scope', 'branch_coverage_complete',
                  'qualification_authorized'}
_EVENT_FIELDS = {'sequence', 'call', 'pair', 'role', 'value_sha256', 'accepted',
                 'result_sha256', 'result_encoding', 'return_site'}


def _refuse(reason):
    raise values.LifecycleContractError('public_pair_evidence:' + reason)


def _shape(value, fields, reason):
    if type(value) is not dict or set(value) != fields:
        _refuse(reason)


def _codes(code):
    yield code
    for child in code.co_consts:
        if type(child) is types.CodeType:
            yield from _codes(child)


def _coordinates(position):
    return {'line': position.lineno, 'column': position.col_offset,
            'end_line': position.end_lineno, 'end_column': position.end_col_offset}


def _source_symbols(sources, inventory):
    symbols, functions = {}, {}
    for path, module in inventory['modules'].items():
        try:
            code = compile(sources[path], path, 'exec', dont_inherit=True)
        except (SyntaxError, ValueError, RecursionError):
            _refuse('source_compilation')
        compiled = {c.co_qualname: c for c in _codes(code)}
        tree = ast.parse(sources[path])
        nodes = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            nodes.update({cls.name + '.' + n.name: n for n in cls.body
                          if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))})
        for name, export in module['exports'].items():
            symbol = path + '#' + name
            symbols[symbol] = {'kind': export['kind'], 'source_sha256': module['source_sha256']}
            if len(symbols) > MAX_SYMBOLS:
                _refuse('symbol_limit')
            members = {name: export} if export['kind'] == 'function' else {
                name + '.' + method: data for method, data in export.get('methods', {}).items()}
            for qualified, data in members.items():
                symbol = path + '#' + qualified
                symbols[symbol] = {'kind': 'function', 'source_sha256': module['source_sha256']}
                node, compiled_function = nodes[qualified], compiled[qualified]
                functions[symbol] = {
                    'reference': {'path': path, 'name': qualified,
                                  'first_line': compiled_function.co_firstlineno,
                                  'source_sha256': module['source_sha256']},
                    'parameters': [a.arg for a in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)],
                    'return_sites': data['return_sites'],
                    'return_spans': [_coordinates(i.positions) for i in dis.get_instructions(compiled_function)
                                     if i.opname in ('RETURN_VALUE', 'RETURN_CONST')],
                }
                if len(symbols) > MAX_SYMBOLS:
                    _refuse('symbol_limit')
    return symbols, functions


def _function(reference, functions):
    _shape(reference, {'path', 'name', 'first_line', 'source_sha256'}, 'function_reference')
    if type(reference['path']) is not str or type(reference['name']) is not str:
        _refuse('function_reference')
    symbol = reference['path'] + '#' + reference['name']
    function = functions.get(symbol)
    if function is None or rv.freeze(reference) != rv.freeze(function['reference']):
        _refuse('function_source_binding')
    return symbol, function


def _declarations(rows, functions, *, boolean_profile=False, tuple_profile=False, nested_profile=False):
    if type(rows) is not list or not 1 <= len(rows) <= 256:
        _refuse('declarations')
    declarations, paths = {}, {}
    for row in rows:
        _shape(row, {'name', 'producer', 'validator', 'parameter', 'acceptance'}, 'declaration_shape')
        name = row['name']
        if type(name) is not str or not name or len(name) > 256 or name in declarations:
            _refuse('declaration_name')
        producer, producer_info = _function(row['producer'], functions)
        validator, validator_info = _function(row['validator'], functions)
        tuple_pair = type(row['parameter']) is list
        nested_pair = type(row['parameter']) is dict
        if nested_pair:
            if not nested_profile:
                _refuse('parameter_binding')
            _shape(row['parameter'], {'name', 'path'}, 'nested_parameter')
            path = row['parameter']['path']
            if (type(path) is not list or not 1 <= len(path) <= 8
                    or any(type(key) is not str or not 1 <= len(key) <= 128 for key in path)):
                _refuse('nested_path')
            parameters = [row['parameter']['name']]
        else:
            parameters = row['parameter'] if tuple_pair else [row['parameter']]
        if (not 1 <= len(parameters) <= 8 or any(type(p) is not str for p in parameters)
                or len(set(parameters)) != len(parameters)
                or any(p not in validator_info['parameters'] for p in parameters)
                or (tuple_pair and (not tuple_profile or len(parameters) < 2))):
            _refuse('parameter_binding')
        acceptance = row['acceptance']
        if type(acceptance) is not dict:
            _refuse('acceptance')
        if tuple_pair and acceptance.get('kind') != 'boolean_true':
            _refuse('acceptance')
        if nested_pair and acceptance.get('kind') != 'json_field':
            _refuse('acceptance')
        if acceptance.get('kind') == 'json_field':
            _shape(acceptance, {'kind', 'field', 'value'}, 'acceptance')
            expected = {'valid': True, 'status': 'PASS'}.get(acceptance['field']) if type(acceptance['field']) is str else None
            if expected is None or rv.freeze(acceptance['value']) != rv.freeze(expected):
                _refuse('acceptance')
        elif acceptance.get('kind') == 'boolean_true' and boolean_profile:
            _shape(acceptance, {'kind'}, 'acceptance')
        elif acceptance.get('kind') == 'artifact_report':
            _shape(acceptance, {'kind', 'type'}, 'acceptance')
            _shape(acceptance['type'], {'module', 'name'}, 'artifact_type')
            artifact = acceptance['type']
            if (type(artifact['module']) is not str or not artifact['module']
                    or type(artifact['name']) is not str
                    or row['validator']['name'].rsplit('.', 1)[0] != artifact['name']):
                _refuse('artifact_type')
        else:
            _refuse('acceptance')
        declarations[name] = (row, producer, producer_info, validator, validator_info)
        for reference in (row['producer'], row['validator']):
            paths[reference['path']] = reference['source_sha256']
    return declarations, paths


def _snapshots(snapshots, remaining):
    if type(snapshots) is not dict or len(snapshots) > MAX_CALLS * 3:
        _refuse('snapshots')
    decoded = {}
    for digest, text in snapshots.items():
        if type(digest) is not str or type(text) is not str or len(text) > MAX_VALUE_BYTES:
            _refuse('snapshot_size')
        try:
            raw = text.encode('ascii')
        except UnicodeError:
            _refuse('snapshot_encoding')
        remaining -= len(raw)
        if remaining < 0:
            _refuse('total_size')
        try:
            data = json.loads(text)
            canonical = values.canonical_json(data)
        except (ValueError, RecursionError):
            _refuse('snapshot_encoding')
        if hashlib.sha256(raw).hexdigest() != digest or canonical != text:
            _refuse('snapshot_binding')
        decoded[digest] = data
    return decoded, remaining


def _events(report, declarations, decoded):
    events, calls = report['events'], report['calls']
    if (type(events) is not list or len(events) > MAX_EVENTS
            or type(calls) is not int or not 0 <= calls <= MAX_CALLS):
        _refuse('events')
    seen, call_bindings = set(), {}
    for index, event in enumerate(events):
        nested_validator = (type(event) is dict and type(event.get('pair')) is str
                            and event['pair'] in declarations and event.get('role') == 'validator'
                            and type(declarations[event['pair']][0]['parameter']) is dict)
        _shape(event, _EVENT_FIELDS | ({'container_sha256'} if nested_validator else set()), 'event_shape')
        if (type(event['sequence']) is not int or event['sequence'] != index
                or type(event['call']) is not int or not 1 <= event['call'] <= calls
                or type(event['pair']) is not str or event['pair'] not in declarations
                or event['role'] not in ('producer', 'validator')):
            _refuse('event_identity')
        key = event['pair'], event['role'], event['call']
        if key in seen:
            _refuse('duplicate_event')
        seen.add(key)
        for field in ('value_sha256', 'result_sha256'):
            if type(event[field]) is not str or event[field] not in decoded:
                _refuse('event_snapshot')
        row, producer_symbol, producer, validator_symbol, validator = declarations[event['pair']]
        if nested_validator:
            digest = event['container_sha256']
            if type(digest) is not str or digest not in decoded:
                _refuse('container_snapshot')
            selected = decoded[digest]
            for key in row['parameter']['path']:
                if type(selected) is not dict or key not in selected:
                    _refuse('container_path')
                selected = selected[key]
            if rv.freeze(selected) != rv.freeze(decoded[event['value_sha256']]):
                _refuse('container_value_binding')
        function = producer if event['role'] == 'producer' else validator
        # CPython can assign a whole try/finally span to RETURN_VALUE. Preserve
        # that ambiguity; it is not an AST Return identity or PASS-branch proof.
        if rv.freeze(event['return_site']) not in [rv.freeze(span) for span in function['return_spans']]:
            _refuse('return_span_binding')
        call_binding = (producer_symbol if event['role'] == 'producer' else validator_symbol,
                        rv.freeze(event['return_site']))
        if call_bindings.setdefault(event['call'], call_binding) != call_binding:
            _refuse('call_frame_binding')
        result = decoded[event['result_sha256']]
        tuple_pair = type(row['parameter']) is list
        if tuple_pair:
            value = decoded[event['value_sha256']]
            _shape(value, {'tuple_items'}, 'tuple_projection')
            if type(value['tuple_items']) is not list or len(value['tuple_items']) != len(row['parameter']):
                _refuse('tuple_projection')
        if event['role'] == 'producer':
            encoding = 'tuple_items_projection' if tuple_pair else 'json'
            if (event['accepted'] is not None or event['result_encoding'] != encoding
                    or event['result_sha256'] != event['value_sha256']):
                _refuse('producer_result')
            continue
        acceptance = row['acceptance']
        if acceptance['kind'] == 'json_field':
            if event['result_encoding'] != 'json':
                _refuse('result_encoding')
            value = result.get(acceptance['field']) if type(result) is dict else None
            expected = acceptance['value']
            accepted = type(value) is type(expected) and value == expected
        elif acceptance['kind'] == 'boolean_true':
            if event['result_encoding'] != 'json':
                _refuse('result_encoding')
            accepted = result is True
        else:
            if event['result_encoding'] != 'artifact_report_projection':
                _refuse('result_encoding')
            _shape(result, {'artifact_type', 'report'}, 'artifact_result')
            if rv.freeze(result['artifact_type']) != rv.freeze(acceptance['type']):
                _refuse('artifact_type')
            accepted = values.canonical_json(result['report']) == report['snapshots'][event['value_sha256']]
        if type(event['accepted']) is not bool or event['accepted'] is not accepted:
            _refuse('acceptance_result')
    return events


def _check_match_shape(matches):
    if type(matches) is not list or len(matches) > MAX_EVENTS:
        _refuse('match_limit')
    count = 0
    for match in matches:
        _shape(match, {'producer_sequence', 'validator_sequences'}, 'match_shape')
        if type(match['producer_sequence']) is not int or type(match['validator_sequences']) is not list:
            _refuse('match_shape')
        count += len(match['validator_sequences'])
        if count > MAX_MATCHES:
            _refuse('match_limit')
        if any(type(sequence) is not int for sequence in match['validator_sequences']):
            _refuse('match_shape')


def _enclosing_validators(events, remaining):
    """Retain nested reconstruction context without counting it as a handoff.

    Every declared validator counts, including validators of other pairs. Group
    aliases and producer/consumer roles from one returned frame before pushing
    it, so a frame cannot enclose itself. Reverse return order lets each frame
    enter and leave the stack once; contexts share the aggregate match ceiling.
    """
    stack, enclosed, seen_calls = [], {}, set()
    index = len(events) - 1
    while index >= 0:
        call, frame = events[index]['call'], []
        if call in seen_calls:
            _refuse('call_frame_reopened')
        seen_calls.add(call)
        while index >= 0 and events[index]['call'] == call:
            frame.append(events[index])
            index -= 1
        while stack and stack[-1][0] >= call:
            stack.pop()
        producers = [event for event in frame if event['role'] == 'producer']
        if producers:
            remaining -= sum(len(sequences) for _, sequences in stack) * len(producers)
            if remaining < 0:
                _refuse('match_limit')
            contexts = sorted(sequence for _, sequences in stack for sequence in sequences)
            for event in producers:
                enclosed[event['sequence']] = contexts
        validators = sorted(event['sequence'] for event in frame if event['role'] == 'validator')
        if validators:
            stack.append((call, validators))
    return enclosed, remaining


def build_evidence(sources: dict[str, str], observations: list[dict]) -> rv.FrozenValue:
    """Recompute source-bound matches and preserve every unresolved coverage gap."""
    inventory = public_inventory.build_inventory(sources)
    inventory_data = inventory.to_plain()
    symbols, functions = _source_symbols(sources, inventory_data)
    if type(observations) is not list or len(observations) > MAX_REPORTS:
        _refuse('observations')
    cases, pairs, observed_roles, names = {}, {}, {}, {}
    remaining, event_count, match_count = MAX_TOTAL_BYTES, 0, 0
    for report in observations:
        _shape(report, _REPORT_FIELDS, 'report_shape')
        nested_profile = report['schema'] == NESTED_OBSERVATION_SCHEMA
        tuple_profile = nested_profile or report['schema'] == TUPLE_OBSERVATION_SCHEMA
        boolean_profile = tuple_profile or report['schema'] == BOOLEAN_OBSERVATION_SCHEMA
        expected_scope = ('declared_json_nested_tuple_boolean_and_artifact_report_pairs_in_one_owned_test_case'
                          if nested_profile else 'declared_json_tuple_boolean_and_artifact_report_pairs_in_one_owned_test_case'
                          if tuple_profile else 'declared_json_boolean_and_artifact_report_pairs_in_one_owned_test_case'
                          if boolean_profile else 'declared_json_and_artifact_report_pairs_in_one_owned_test_case')
        if (report['schema'] not in (OBSERVATION_SCHEMA, BOOLEAN_OBSERVATION_SCHEMA, TUPLE_OBSERVATION_SCHEMA, NESTED_OBSERVATION_SCHEMA)
                or report['status'] != 'OBSERVED_NOT_CLOSED' or report['scope'] != expected_scope
                or report['branch_coverage_complete'] is not False or report['qualification_authorized'] is not False
                or type(report['case']) is not str or not report['case'] or len(report['case']) > 1024
                or report['case'] in cases):
            _refuse('report_identity')
        declarations, paths = _declarations(report['declarations'], functions,
                                            boolean_profile=boolean_profile, tuple_profile=tuple_profile,
                                            nested_profile=nested_profile)
        if rv.freeze(report['sources']) != rv.freeze(paths):
            _refuse('source_binding')
        decoded, remaining = _snapshots(report['snapshots'], remaining)
        events = _events(report, declarations, decoded)
        _check_match_shape(report['matches'])
        event_count += len(events)
        if event_count > MAX_EVENTS:
            _refuse('total_events')
        enclosed, remaining_matches = _enclosing_validators(events, MAX_MATCHES - match_count)
        match_count = MAX_MATCHES - remaining_matches
        matches, consumer_index, producer_index, validator_index = [], {}, {}, {}
        for event in events:
            if event['role'] == 'producer':
                producer_index.setdefault(event['pair'], []).append(event)
            else:
                validator_index.setdefault(event['pair'], []).append(event)
                if event['accepted'] is True:
                    consumer_index.setdefault((event['pair'], event['value_sha256']), []).append(
                        (event['call'], event['sequence']))
        for consumers in consumer_index.values():
            consumers.sort()
        for name, (row, producer, producer_info, validator, _) in declarations.items():
            pair_id = 'lc-pair:issue-170-public:' + values.canonical_digest(row)
            if name in names and names[name] != pair_id:
                _refuse('pair_redefinition')
            names[name] = pair_id
            pair = pairs.setdefault(pair_id, {'declaration': row, 'outputs': [],
                                              'declared_return_sites': producer_info['return_sites']})
            if type(row['parameter']) is dict:
                pair.setdefault('validator_containers', []).extend(
                    {'case': report['case'], 'sequence': event['sequence'], 'accepted': event['accepted'],
                     'container_sha256': event['container_sha256'], 'value_sha256': event['value_sha256']}
                    for event in validator_index.get(name, []))
            observed_roles.setdefault(producer, set()).add('producer')
            observed_roles.setdefault(validator, set()).add('validator')
            for event in producer_index.get(name, []):
                consumers = consumer_index.get((name, event['value_sha256']), [])
                start = bisect_left(consumers, (event['call'], -1))
                match_count += len(consumers) - start
                if match_count > MAX_MATCHES:
                    _refuse('match_limit')
                consumed = sorted(sequence for _, sequence in consumers[start:])
                matches.append({'producer_sequence': event['sequence'], 'validator_sequences': consumed})
                pair['outputs'].append({'case': report['case'], 'producer_sequence': event['sequence'],
                                        'value_sha256': event['value_sha256'], 'return_instruction_span': event['return_site'],
                                        'enclosing_validator_sequences': enclosed[event['sequence']],
                                        'validator_sequences': consumed})
        matches.sort(key=lambda match: match['producer_sequence'])
        if rv.freeze(matches) != rv.freeze(report['matches']):
            _refuse('matches_binding')
        cases[report['case']] = {'observation_sha256': values.canonical_digest(report), 'matches': matches}
    gaps = [{'kind': 'unclassified_public_symbol', 'symbol': symbol}
            for symbol in sorted(set(symbols) - set(observed_roles))]
    source_effects = {}
    for path, module in inventory_data['modules'].items():
        classes = {name: row['unresolved_class_effects'] for name, row in module['exports'].items()
                   if row.get('unresolved_class_effects')}
        if classes or module['unresolved_module_effects']:
            source_effects[path] = {'module': module['unresolved_module_effects'], 'classes': classes}
            gaps.append({'kind': 'source_effect_classification_pending', 'path': path})
    for pair_id, pair in sorted(pairs.items()):
        pair['outputs'].sort(key=lambda row: (row['case'], row['producer_sequence']))
        if 'validator_containers' in pair:
            pair['validator_containers'].sort(key=lambda row: (row['case'], row['sequence']))
        gaps.append({'kind': 'pass_branch_classification_pending', 'pair': pair_id})
        spans = {values.canonical_json(output['return_instruction_span']) for output in pair['outputs']}
        sites = {values.canonical_json(site) for site in pair['declared_return_sites']}
        for site in pair['declared_return_sites']:
            if values.canonical_json(site) not in spans:
                gaps.append({'kind': 'return_site_without_exact_observation', 'pair': pair_id, 'site': site})
        if not pair['outputs']:
            gaps.append({'kind': 'producer_not_observed', 'pair': pair_id})
        for output in pair['outputs']:
            if output['enclosing_validator_sequences']:
                gaps.append({'kind': 'validation_internal_build_classification_pending', 'pair': pair_id,
                             'case': output['case'], 'sequence': output['producer_sequence']})
            if values.canonical_json(output['return_instruction_span']) not in sites:
                gaps.append({'kind': 'return_span_ambiguous', 'pair': pair_id,
                             'case': output['case'], 'sequence': output['producer_sequence']})
            if not output['validator_sequences']:
                gaps.append({'kind': 'producer_output_unmatched', 'pair': pair_id,
                             'case': output['case'], 'sequence': output['producer_sequence']})
    return rv.freeze({'schema': SCHEMA, 'status': 'EVIDENCE_BOUND_GAPS_REMAIN',
                      'inventory_sha256': inventory.digest(), 'symbols': symbols, 'pairs': pairs,
                      'source_effects': source_effects,
                      'observed_roles': {symbol: sorted(roles) for symbol, roles in observed_roles.items()},
                      'cases': cases, 'gaps': gaps, 'module_selection_verified': False,
                      'execution_attested': False, 'pass_branches_closed': False,
                      'qualification_authorized': False})


def validate_evidence(evidence: rv.FrozenValue, sources: dict[str, str], observations: list[dict]) -> None:
    if type(evidence) is not rv.FrozenValue or evidence != build_evidence(sources, observations):
        _refuse('evidence_binding')
