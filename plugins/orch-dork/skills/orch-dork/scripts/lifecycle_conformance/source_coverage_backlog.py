"""Source-backed classification of the complete, still-open coverage inventory.

Literal metadata and retained source-role decisions have explicit evidence.
Other callable, import, class and effect semantics remain decisions to make.
Categorization never changes an obligation's acceptance status.
"""
from collections import Counter
from copy import deepcopy
from lifecycle_conformance import campaign, values

SCHEMA = 'orch-dork/source-coverage-backlog/v1'
_DECISIONS = {
    'CLASSIFIED_DECLARED_LIFECYCLE_ROLE': 'public_pair_role_classification',
    'CLASSIFIED_SUPPORTING_SOURCE': 'source_role_classification',
    'OBSERVED_ACCEPTED_RETURN_SITE': 'paired_return_site_classification',
    'EXECUTED_SOURCE_BRANCHES': 'source_branch_classification',
    'CLASSIFIED_SEEDED_LIFECYCLE_ROLE': 'seeded_public_role_classification',
    'EXECUTED_SOURCE_RETURN_SITE': 'executed_source_return_classification',
}
_NEEDS = {
    'symbol_role': 'Review the source binding, runtime aliases and effects; declare lifecycle pairs or justify a supporting role.',
    'undeclared_public_definition': 'Decide whether this definition is public and bind that decision to the export inventory.',
    'return_site': 'Classify successful and failed returns; bind each applicable whole output to its actual accepting consumer.',
    'control_flow_classification': 'Enumerate feasible successful alternatives and link each to an executed case or reviewed source-backed exclusion.',
    'module_control_flow': 'Review import-time control flow and effects, including CLI guards and runtime-dependent bindings.',
    'rebound_name': 'Resolve the final runtime binding and any aliases before assigning a public role.',
    'lifecycle_stage': 'Execute applicable observations, orders and failure/cleanup outcomes for this exact lifecycle stage.',
    'replays': 'Bind this preserved replay to executed cases and current model identifiers without changing its original outcome.',
    'host_fixtures': 'Prove this host fixture applies at each required model boundary and retain its host-custody limits.',
    'host_mcp_fixtures': 'Bind the MCP host fixture to executed boundary cases and its unresolved authentication and ownership obligations.',
    'injection_sites': 'Bind this exact source injection site to its applicable current states and failure-closure checks.',
    'injection_schedule': 'Execute this registered injection job across all applicable current states and retain exact successor evidence.',
    'integration_gate': 'Complete and verify this named derivation or release prerequisite against the final source and executed inventory.',
}


def _same(left, right):
    return values.canonical_json(left) == values.canonical_json(right)


def _retained(checklist, accepted):
    original = checklist['obligations']
    if accepted is None:
        return deepcopy(original)
    if (type(accepted) is not dict or type(accepted.get('obligations')) is not dict
            or accepted.get('qualification_authorized') is not False
            or not _same(accepted.get('source_inventory'), checklist['source_inventory'])
            or accepted.get('registry_sha256') != checklist['registry_sha256']
            or set(accepted['obligations']) != set(original)):
        raise ValueError('source_backlog:accepted_inventory')
    ignored = {'status', 'reason', 'classification_sha256'}
    for identity, prior in original.items():
        row = accepted['obligations'][identity]
        if type(row) is not dict or type(row.get('status')) is not str:
            raise ValueError('source_backlog:accepted_shape')
        if row['status'] == 'PENDING':
            if not _same(row, prior):
                raise ValueError('source_backlog:pending_changed')
            continue
        key = _DECISIONS.get(row['status'])
        container = accepted.get(key) if key else None
        decisions = container.get('decisions') if type(container) is dict else None
        decision = decisions.get(identity) if type(decisions) is dict else None
        if (type(decision) is not dict
                or not _same({k: v for k, v in row.items() if k not in ignored},
                             {k: v for k, v in prior.items() if k not in ignored})
                or decision.get('status') != row['status']
                or decision.get('obligation_sha256') != values.canonical_digest(prior)
                or row.get('classification_sha256') != values.canonical_digest(decision)):
            raise ValueError('source_backlog:accepted_decision')
        kind = ('control_flow_classification' if row['status'] == 'EXECUTED_SOURCE_BRANCHES' else
                'return_site' if row['status'] == 'OBSERVED_ACCEPTED_RETURN_SITE' or row['status'] == 'EXECUTED_SOURCE_RETURN_SITE' else 'symbol_role')
        if prior['kind'] != kind:
            raise ValueError('source_backlog:accepted_kind')
        if row['status'] in ('EXECUTED_SOURCE_BRANCHES', 'CLASSIFIED_SEEDED_LIFECYCLE_ROLE', 'EXECUTED_SOURCE_RETURN_SITE'):
            proofs = container.get('proofs')
            if proofs is not None and type(proofs) is not dict:
                raise ValueError('source_backlog:branch_proof_inventory')
            if row['status'] in ('CLASSIFIED_SEEDED_LIFECYCLE_ROLE', 'EXECUTED_SOURCE_RETURN_SITE') and proofs is None:
                raise ValueError('source_backlog:seeded_role_proof_inventory')
            proof = proofs.get(decision.get('group')) if proofs is not None else container.get('proof')
            if (type(proof) is not dict or proof.get('group') != decision.get('group')
                    or proof.get('source_sha256') != prior['source_sha256']
                    or decision.get('proof_sha256') != values.canonical_digest(proof)):
                raise ValueError('source_backlog:branch_proof')
    for status, key in _DECISIONS.items():
        container = accepted.get(key, {})
        decisions = container.get('decisions', {}) if type(container) is dict else None
        expected = {identity for identity, row in accepted['obligations'].items() if row['status'] == status}
        if type(decisions) is not dict or set(decisions) != expected:
            raise ValueError('source_backlog:unexplained_decision')
        if status in ('CLASSIFIED_SEEDED_LIFECYCLE_ROLE', 'EXECUTED_SOURCE_RETURN_SITE') and container:
            if (set(container) != {'schema', 'decisions', 'proofs', 'runtime_role_verified',
                    'execution_attested', 'pass_branches_closed', 'qualification_authorized'}
                    or container['schema'] != ('orch-dork/seeded-public-role-classification/v1' if status == 'CLASSIFIED_SEEDED_LIFECYCLE_ROLE' else 'orch-dork/executed-source-return-classification/v1')
                    or any(container[key] is not False for key in ('runtime_role_verified',
                        'execution_attested', 'pass_branches_closed', 'qualification_authorized'))):
                raise ValueError('source_backlog:seeded_role_scope')
        if status in ('EXECUTED_SOURCE_BRANCHES', 'CLASSIFIED_SEEDED_LIFECYCLE_ROLE', 'EXECUTED_SOURCE_RETURN_SITE') and 'proofs' in container:
            proofs = container['proofs']
            if ('proof' in container or type(proofs) is not dict
                    or set(proofs) != {row['group'] for row in decisions.values()}):
                raise ValueError('source_backlog:branch_proof_inventory')
    return deepcopy(accepted['obligations'])


def _symbol_fact(identity, source, obligations):
    role = obligations.get(identity + ':role', {}).get('status')
    if role in ('CLASSIFIED_DECLARED_LIFECYCLE_ROLE', 'CLASSIFIED_SEEDED_LIFECYCLE_ROLE'):
        if source['role'] == 'role_decision_required':
            return ('lifecycle_behavior', 'retained_lifecycle_role',
                    'A retained source-bound decision identifies this exported lifecycle metadata binding; its separately inventoried effects and runtime custody remain open.')
        return ('lifecycle_behavior', 'retained_lifecycle_role',
                'A retained source-bound constructor/consumer decision identifies this lifecycle function; its branch and effect obligations remain separate.')
    if role == 'CLASSIFIED_SUPPORTING_SOURCE':
        return ('supporting_code', 'retained_supporting_role',
                'A retained source-bound import or namespace decision identifies supporting code; this does not exclude target APIs or import-time effects.')
    if source['role'] == 'literal_metadata':
        return ('supporting_code', 'ast_literal_metadata',
                'The current source inventory proves an exact AST Constant defines this non-callable binding.')
    return ('missing_evidence', 'unresolved_' + source['role'],
            source['reason'] + ' A name, private/public spelling or module location is not evidence of semantic scope.')


def _symbol_owner(identity, symbols):
    # Obligation suffixes are fixed by the source inventory, not guessed from
    # function naming conventions or source-module filenames.
    for marker in (':role', ':export', ':return:', ':branch:'):
        candidate = identity.rsplit(marker, 1)[0]
        if candidate in symbols:
            return candidate
    return None


def build_backlog(sources, registry_components, *, accepted_coverage=None):
    """Partition every source symbol and obligation without discharging any."""
    checklist = campaign.build_coverage_checklist(sources, registry_components).to_plain()
    originals = checklist['source_inventory']['symbols']
    obligations = _retained(checklist, accepted_coverage)
    symbols, classified, groups = {}, {}, {}

    def place(identity, category, scope, kind, code, reason, need, *, source=None, obligation=None):
        group_key = {'category': category, 'scope': scope, 'kind': kind}
        group_id = 'coverage-group:' + values.canonical_digest(group_key)
        group = groups.setdefault(group_id, {**group_key, 'symbol_ids': [], 'obligation_ids': [],
            'pending_obligation_ids': [], 'reason_codes': [], 'required_evidence': []})
        for key, value in (('reason_codes', code), ('required_evidence', need)):
            if value not in group[key]:
                group[key].append(value)
        row = {'category': category, 'group': group_id, 'reason_code': code,
               'rationale': reason, 'required_evidence': need}
        if source is not None:
            row['source'] = deepcopy(source)
            row['binding_sha256'] = values.canonical_digest(source)
            group['symbol_ids'].append(identity)
            symbols[identity] = row
        else:
            row['obligation'] = deepcopy(obligation)
            row['binding_sha256'] = values.canonical_digest(obligation)
            group['obligation_ids'].append(identity)
            if obligation['status'] == 'PENDING':
                group['pending_obligation_ids'].append(identity)
            classified[identity] = row

    for identity, source in sorted(originals.items()):
        category, code, reason = _symbol_fact(identity, source, obligations)
        need = (_NEEDS['symbol_role'] if category == 'missing_evidence' else
                'Retain this source-role evidence; all separately listed callable, branch, return and effect obligations still apply.')
        place(identity, category, source['path'], 'symbol_role', code, reason, need, source=source)
    for identity, obligation in sorted(obligations.items()):
        kind = obligation['kind']
        owner = _symbol_owner(identity, originals)
        if owner is not None:
            category, code, reason = _symbol_fact(owner, originals[owner], obligations)
            scope = originals[owner]['path']
        elif kind == 'lifecycle_stage':
            category, code, reason = ('lifecycle_behavior', 'registered_lifecycle_stage',
                'The current protocol stage registry binds this exact stage; applicable behavior remains to be covered.')
            scope = identity
        else:
            category, code, reason = ('missing_evidence', 'unresolved_' + kind, obligation['reason'])
            scope = obligation.get('path', identity if kind == 'integration_gate' else 'registry:' + kind)
        need = _NEEDS.get(kind, obligation['reason'])
        if obligation['status'] != 'PENDING':
            need = 'Retain the exact existing decision and witness bindings; this categorization supplies no additional execution evidence.'
        place(identity, category, scope, kind, code, reason, need, obligation=obligation)
    for group in groups.values():
        for key in ('symbol_ids', 'obligation_ids', 'pending_obligation_ids', 'reason_codes', 'required_evidence'):
            group[key].sort()
    groups = dict(sorted(groups.items()))
    counts = {'symbols': len(symbols), 'obligations': len(classified), 'groups': len(groups),
        'pending_obligations': sum(row['status'] == 'PENDING' for row in obligations.values()),
        'pending_groups': sum(bool(group['pending_obligation_ids']) for group in groups.values()),
        'symbols_by_category': dict(sorted(Counter(row['category'] for row in symbols.values()).items())),
        'obligations_by_category': dict(sorted(Counter(row['category'] for row in classified.values()).items())),
        'groups_by_category': dict(sorted(Counter(row['category'] for row in groups.values()).items())),
        'source_kinds': dict(sorted(Counter(row['role'] for row in originals.values()).items()))}
    return {'schema': SCHEMA, 'source_inventory_sha256': checklist['source_inventory']['source_inventory_sha256'],
        'registry_sha256': checklist['registry_sha256'], 'symbols': symbols, 'obligations': classified,
        'groups': groups, 'counts': counts, 'pending_group_ids': [key for key, row in groups.items() if row['pending_obligation_ids']],
        'classification_complete': True, 'complete_coverage': False,
        'release_authorized': False, 'qualification_authorized': False}


def validate_backlog(backlog, sources, registry_components, *, accepted_coverage=None):
    if not _same(backlog, build_backlog(sources, registry_components, accepted_coverage=accepted_coverage)):
        raise ValueError('source_backlog:binding')
