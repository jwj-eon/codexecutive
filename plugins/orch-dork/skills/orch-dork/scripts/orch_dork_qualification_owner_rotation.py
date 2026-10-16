"""Read a completed predecessor's disposition from actual successor authority.

This observes a direct, already activated successor. It creates no successor,
performs no rotation, and grants no work or terminal qualification. Saved JSON
is transport evidence only; the producer reads canonical history and witnesses.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

import orch_dork_completion_settlement as settlement
import orch_dork_governed_native_controller as native
import orch_dork_qualification_owner as readiness
from orch_dork_governed_native_reports import _json, completion_waiting_authority

SCHEMA = 'orch-dork/predecessor-owner-disposition-observation/v1'
MAX_BYTES = 1_000_000


def _require(condition, issue='binding_invalid'):
    if not condition:
        raise ValueError('owner_rotation:' + issue)


def _same(a, b):
    return native._canonical(a) == native._canonical(b)


def _owner_cursor(owner, cursor):
    for value in (owner, cursor):
        _json(value)
        _require(len(native._canonical(value)) <= 4096)
    _require(type(owner) is dict and set(owner) == {
        'schema', 'controller_id', 'controller_run_id', 'activation_sha256', 'store_identity_sha256'})
    _require(owner['schema'] == native.native_grant_store.OWNER_SCHEMA)
    _require(all(native.native_grant_store._text(owner[k]) for k in ('controller_id', 'controller_run_id')))
    _require(all(settlement.capacity._digest(owner[k]) for k in ('activation_sha256', 'store_identity_sha256')))
    _require(type(cursor) is dict and set(cursor) == {'run_id', 'seq', 'event_hash'})
    _require(cursor['run_id'] == owner['controller_run_id'] and type(cursor['seq']) is int
        and cursor['seq'] >= 1 and settlement.capacity._digest(cursor['event_hash']))


def _marker(marker, owner):
    _require(type(marker) is dict and set(marker) == {
        'schema', 'controller_id', 'controller_run_id', 'activation_sha256', 'store_identity_sha256',
        'previous_controller_run_id', 'previous_marker_sha256', 'marker_sha256'})
    _require(marker['schema'] == native.native_grant_store.CONTROLLER_RUN_MARKER_SCHEMA)
    _require(all(marker[k] == owner[k] for k in ('controller_id', 'controller_run_id', 'activation_sha256', 'store_identity_sha256')))
    _require(marker['marker_sha256'] == native._sha({k:v for k,v in marker.items() if k != 'marker_sha256'}))
    previous, digest = marker['previous_controller_run_id'], marker['previous_marker_sha256']
    _require((previous is None and digest is None) or
        (native.native_grant_store._text(previous) and settlement.capacity._digest(digest)))


def _snapshot_transport(snapshot):
    _json(snapshot)
    _require(set(snapshot) == {'predecessor', 'successor', 'capacity', 'grant_inventory'})
    prior, successor = snapshot['predecessor'], snapshot['successor']
    _require(set(prior) == {'owner', 'cursor', 'activation', 'marker', 'state_sha256', 'journal_sha256',
        'stage_report_sha256', 'last_stage_time', 'terminal', 'pending_intent', 'action', 'grant_state', 'cleanup_required'})
    _require(set(successor) == {'authority', 'activation', 'marker', 'state_sha256', 'journal_sha256', 'activation_only'})
    _owner_cursor(prior['owner'], prior['cursor'])
    authority = successor['authority']
    completion_waiting_authority(authority)
    _marker(prior['marker'], prior['owner'])
    _marker(successor['marker'], authority['owner'])
    _require(prior['owner']['store_identity_sha256'] == authority['store_identity_sha256'])
    _require(successor['marker']['previous_controller_run_id'] == prior['owner']['controller_run_id']
        and successor['marker']['previous_marker_sha256'] == prior['marker']['marker_sha256'], 'not_direct_successor')
    _require(authority['owner']['controller_id'] != prior['owner']['controller_id']
        and authority['owner']['controller_run_id'] != prior['owner']['controller_run_id'])
    _require(prior['terminal'] is True and prior['cleanup_required'] is False
        and all(prior[k] is None for k in ('pending_intent', 'action', 'grant_state')))
    _require(successor['activation_only'] is True and authority['tip']['seq'] == 1)
    for row, owner in ((prior, prior['owner']), (successor, authority['owner'])):
        _require(native._sha(row['activation']) == owner['activation_sha256'])
        for key in ('state_sha256', 'journal_sha256'):
            _require(settlement.capacity._digest(row[key]))
    _require(settlement.capacity._digest(prior['stage_report_sha256']))
    settlement.observer_receipt.evidence.instant(prior['last_stage_time'])
    for key in ('attempt_id', 'run_id', 'admission_sha256'):
        a, b = prior['activation']['identity'][key], successor['activation']['identity'][key]
        _require(native.native_grant_store._text(a) and native.native_grant_store._text(b) and a != b)
    capacity = snapshot['capacity']
    _require(_same(capacity, settlement.capacity.authority_read_report(capacity['state'], store_id=capacity['store_id']))
        and capacity['status'] == 'VERIFIED' and capacity['continuity_verified'] is True
        and capacity['state']['active_lane_ids'] == [], 'capacity_unsettled')
    inventory = snapshot['grant_inventory']; counts = inventory['state_counts']
    _require(type(counts) is dict and set(counts) == set(readiness._STATES)
        and all(type(v) is int and v >= 0 for v in counts.values()))
    _require(sum(counts[k] for k in ('PROVISIONAL', 'AUTHORIZED', 'DISPATCHED', 'OUTCOME_UNKNOWN')) == 0,
        'grants_unsettled')
    _require(settlement.capacity._digest(inventory['inventory_sha256']))
    core = {'schema':'orch-dork/native-grant-inventory/v1', 'status':'VERIFIED', 'issues':[],
        'scope':'all_canonical_grants', 'owner':authority['owner'], 'store_identity_sha256':authority['store_identity_sha256'],
        'grant_count':sum(counts.values()), 'unsettled_grant_count':0, 'state_counts':counts,
        'inventory_sha256':inventory['inventory_sha256'], 'continuation_permitted':False,
        'terminal_claim_permitted':False, 'provider_free':True}
    _require(_same(inventory, {**core, 'report_sha256':native._sha(core)}))


def _snapshot(controller, predecessor_owner, predecessor_cursor):
    # canonical_authority validates all controller streams, marker ancestry,
    # external witnesses, grants and the current hook projection in SQLite.
    authority = controller.grants.canonical_authority()
    completion_waiting_authority(authority)
    old, rows = controller._state(predecessor_owner['controller_run_id'], recover_provisional=False)
    new, next_rows = controller._state(authority['owner']['controller_run_id'], recover_provisional=False)
    _require(_same(native._cursor(rows), predecessor_cursor), 'predecessor_tip_changed')
    _require(_same(native._cursor(next_rows), authority['tip']), 'successor_tip_changed')
    _require(old['action_outcome'] is None and old['stage_report'] is not None, 'predecessor_not_closed')
    _require(new['stage_report'] is None and new['action'] is None and new['pending_intent'] is None
        and new['grant_state'] is None and new['cleanup_required'] is False and new['terminal'] is False
        and new['action_outcome'] is None, 'successor_already_started')
    _require(controller._hook_runtime_matches(new['activation']['identity'])
        and controller._retained_hook_evidence_valid(new), 'successor_hooks_changed')
    events = native._controller_events(rows)
    last_intent = next(row for row in reversed(events) if row['event_type'] == 'stage_intent')
    capacity = settlement._read_capacity(controller)
    _require(_same(capacity, controller.tower.read_shared_capacity_authority()), 'capacity_store_changed')
    snapshot = {
        'predecessor':{'owner':predecessor_owner, 'cursor':predecessor_cursor, 'activation':old['activation'],
            'marker':controller.grants.controller_run_marker(predecessor_owner['controller_run_id']),
            'state_sha256':native._sha(old), 'journal_sha256':native._sha(rows),
            'stage_report_sha256':native._sha(old['stage_report']), 'last_stage_time':last_intent['payload']['evaluation_time'],
            **{k:old[k] for k in ('terminal', 'pending_intent', 'action', 'grant_state', 'cleanup_required')}},
        'successor':{'authority':authority, 'activation':new['activation'],
            'marker':controller.grants.controller_run_marker(authority['owner']['controller_run_id']),
            'state_sha256':native._sha(new), 'journal_sha256':native._sha(next_rows),
            'activation_only':len(native._controller_events(next_rows)) == 1},
        'capacity':capacity, 'grant_inventory':controller.grants.read_grant_inventory()}
    _snapshot_transport(snapshot)
    return deepcopy(snapshot)


def _report(snapshot, observed_at, issues):
    core = {'schema':SCHEMA, 'status':'REFUSED' if issues else 'OBSERVED', 'issues':issues,
        'scope':'direct_predecessor_owner_disposition', 'snapshot':snapshot, 'observed_at':observed_at,
        'owner_released':not issues, 'terminal_claim_permitted':False, 'continuation_permitted':False,
        'provider_free':True, 'model_calls':0, 'native_calls':0, 'rotation_calls':0, 'signing_key_reads':0}
    return {**core, 'report_sha256':native._sha(core)}


def observe_predecessor_owner_disposition(controller, *, predecessor_owner: Any, predecessor_cursor: Any) -> dict:
    """Observe one already completed CAS; never rotate or recover state."""
    try:
        _owner_cursor(predecessor_owner, predecessor_cursor)
        start = controller._evaluation_time()
        before = _snapshot(controller, predecessor_owner, predecessor_cursor)
        after = _snapshot(controller, predecessor_owner, predecessor_cursor)
        _require(_same(before, after), 'authority_changed')
        now = controller._evaluation_time()
        _require(now >= start and now >= settlement.observer_receipt.evidence.instant(before['predecessor']['last_stage_time']),
            'clock_regressed')
        report = _report(before, now.isoformat(), [])
        _require(len(native._canonical(report)) <= MAX_BYTES, 'report_bounds')
        return report
    except Exception:
        return _report(None, None, ['owner_rotation:unverified'])


def validate_owner_rotation_observation(report: Any) -> dict:
    """Validate the whole transport without authenticating stored JSON."""
    try:
        _json(report); _require(len(native._canonical(report)) <= MAX_BYTES)
        if report['status'] == 'OBSERVED':
            _snapshot_transport(report['snapshot'])
            _require(settlement.observer_receipt.evidence.instant(report['observed_at']) >=
                settlement.observer_receipt.evidence.instant(report['snapshot']['predecessor']['last_stage_time']))
            expected = _report(report['snapshot'], report['observed_at'], [])
        else:
            expected = _report(None, None, ['owner_rotation:unverified'])
        _require(_same(report, expected))
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return {'valid':False, 'issues':['owner_rotation:transport_invalid'], 'scope':'canonical_transport'}
    return {'valid':True, 'issues':[], 'scope':'canonical_transport'}


__all__ = ['observe_predecessor_owner_disposition', 'validate_owner_rotation_observation']
