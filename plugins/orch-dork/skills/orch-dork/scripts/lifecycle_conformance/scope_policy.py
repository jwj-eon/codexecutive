"""Derive development work from source scope without changing accepted evidence.

The raw backlog remains the inventory of record. This view selects the next
kind of work; it neither discharges an obligation nor feeds a release gate.
Reviewed module policy applies only to the exact source and registry baseline,
and never overrides a declared lifecycle role. Source or dependency drift stays
in review, including a newly introduced shadow of a standard-library import.
"""
from collections import Counter
import hashlib
import json

from lifecycle_conformance.source_coverage_backlog import build_backlog
from lifecycle_conformance import values


SCHEMA = 'orch-dork/issue170-scope-worklist/v1'
FINITE_KINDS = frozenset({
    'host_fixtures', 'host_mcp_fixtures', 'injection_sites',
    'injection_schedule', 'replays', 'lifecycle_stage', 'integration_gate',
})
SCOPE_KINDS = frozenset({
    'symbol_role', 'module_control_flow', 'rebound_name',
    'undeclared_public_definition',
})
REQUIREMENTS = {
    'REQUIRED_CAMPAIGN_EVIDENCE': 'SPEC.md section 12; TICKETS.md Issue 170 acceptance criteria 1-12',
    'RETAIN_ACCEPTED_EVIDENCE': 'User scope-audit instruction: preserve every accepted proof',
    'RETAIN_SUPPORTING_METADATA': 'Source inventory: retain classified literal bindings',
    'SOURCE_ROLE_REVIEW': 'User instruction 2026-09-07 item 2; SPEC.md section 12 / Producer and validator closure',
    'LIFECYCLE_PASS_REVIEW': 'SPEC.md section 12 / Producer and validator closure; Issue 170 criterion 4',
    'SOURCE_SCOPE_REVIEW': 'SPEC.md section 12 / Producer and validator closure / Out of Scope',
    'SUPPORTING_CONTRACT_TESTS': 'SPEC.md section 12 / Testing Decisions',
    'SEPARATE_FEATURE_TESTS': 'SPEC.md section 12 / Finite state and event algebra / Out of Scope',
}


def parse_policy(policy_source):
    """Parse original policy bytes; shape validation alone supplies no review authority."""
    policy = json.loads(policy_source)
    if (type(policy) is not dict or policy.get('schema') != 'orch-dork/issue170-source-scope-policy/v1'
            or type(policy.get('modules')) is not dict):
        raise ValueError('scope_policy:policy_shape')
    for key in ('source_inventory_sha256', 'registry_sha256'):
        if (type(policy.get(key)) is not str or len(policy[key]) != 64
                or any(c not in '0123456789abcdef' for c in policy[key])):
            raise ValueError('scope_policy:baseline_identity')
    for path, entry in policy['modules'].items():
        if (type(path) is not str or type(entry) is not dict
                or entry.get('work_kind') not in {
                    'SUPPORTING_CONTRACT_TESTS', 'SEPARATE_FEATURE_TESTS'}
                or type(entry.get('source_sha256')) is not str
                or len(entry['source_sha256']) != 64
                or any(c not in '0123456789abcdef' for c in entry['source_sha256'])
                or not entry.get('basis') or not entry.get('requirements')):
            raise ValueError('scope_policy:module_policy')
    return policy


def _work_kind(group, sources, policy, baseline_matches):
    if group['kind'] in FINITE_KINDS:
        return 'REQUIRED_CAMPAIGN_EVIDENCE'
    if not group['pending_obligation_ids']:
        return ('RETAIN_ACCEPTED_EVIDENCE' if group['obligation_ids']
                else 'RETAIN_SUPPORTING_METADATA')
    if group['kind'] in SCOPE_KINDS:
        return 'SOURCE_ROLE_REVIEW'
    if group['category'] == 'lifecycle_behavior':
        return 'LIFECYCLE_PASS_REVIEW'
    entry = policy['modules'].get(group['scope'])
    source = sources.get(group['scope'])
    if (baseline_matches and entry is not None and source is not None
            and hashlib.sha256(source.encode()).hexdigest() == entry['source_sha256']):
        return entry['work_kind']
    return 'SOURCE_SCOPE_REVIEW'


def build_worklist(sources, registry_components, *, policy_source, accepted_coverage=None):
    """Group the unchanged inventory by next work, not by presumed proof count."""
    backlog = build_backlog(sources, registry_components,
                            accepted_coverage=accepted_coverage)
    policy = parse_policy(policy_source)
    baseline_matches = (backlog['source_inventory_sha256'] == policy['source_inventory_sha256']
                        and backlog['registry_sha256'] == policy['registry_sha256'])
    groups = {}
    pending_counts = Counter()
    for identity, group in backlog['groups'].items():
        kind = _work_kind(group, sources, policy, baseline_matches)
        pending = len(group['pending_obligation_ids'])
        pending_counts[kind] += pending
        groups[identity] = {
            'scope': group['scope'], 'inventory_kind': group['kind'],
            'work_kind': kind, 'requirement': REQUIREMENTS[kind],
            'original_group_sha256': values.canonical_digest(group),
            'obligation_count': len(group['obligation_ids']),
            'pending_count': pending,
            'retained_accepted_count': len(group['obligation_ids']) - pending,
            'symbol_count': len(group['symbol_ids']),
        }
    return {
        'schema': SCHEMA, 'policy_sha256': values.canonical_digest(policy),
        'reviewed_baseline_matches': baseline_matches,
        'backlog_sha256': values.canonical_digest(backlog),
        'source_inventory_sha256': backlog['source_inventory_sha256'],
        'registry_sha256': backlog['registry_sha256'],
        'inventory_counts': backlog['counts'], 'groups': groups,
        'pending_by_work_kind': dict(sorted(pending_counts.items())),
        'changes_obligation_statuses': False, 'complete_coverage': False,
        'release_authorized': False, 'qualification_authorized': False,
    }


def validate_worklist(worklist, sources, registry_components, *, policy_source, accepted_coverage=None):
    expected = build_worklist(sources, registry_components, policy_source=policy_source,
                             accepted_coverage=accepted_coverage)
    if values.canonical_json(worklist) != values.canonical_json(expected):
        raise ValueError('scope_policy:worklist_binding')
