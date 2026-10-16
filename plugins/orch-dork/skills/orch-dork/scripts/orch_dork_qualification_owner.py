"""Seal a completed controller for later owner rotation, without claiming it.

Quiescence stops this controller's stages. The canonical owner stays in place
until a separately admitted successor actually wins the existing owner CAS.
Only a host observation can establish current readiness; saved reports are
transport evidence and never authorize rotation.
"""
from __future__ import annotations
from copy import deepcopy
from typing import Any

import orch_dork_governed_attempt as attempt
import orch_dork_completion_settlement as settlement
import orch_dork_qualification_final as final
import orch_dork_qualification_closure as failure
from orch_dork_governed_native_reports import _json

SCHEMA='orch-dork/completed-owner-readiness/v1'
OBSERVATION_SCHEMA='orch-dork/current-completed-owner-readiness/v1'
_INVALID=(KeyError,IndexError,TypeError,ValueError,OverflowError,RecursionError)
_STATES=('PROVISIONAL','AUTHORIZED','DISPATCHED','POST_OBSERVED','OUTCOME_UNKNOWN',
         'TERMINAL_OUTCOME_UNKNOWN','TERMINAL_PRETOOL_DENIED','TERMINAL_NOT_DISPATCHED','STALE')


def _require(condition,issue='binding_invalid'):
    if not condition:raise ValueError('owner_readiness:'+issue)


def _same(a,b):return attempt._canonical(a)==attempt._canonical(b)


def _lifecycle(bindings):
    """The cleanup-binding proof of a closure settled from host cleanup, if any.

    Final qualification and (since rehearsals 21-22) a rejected review's
    failure closure both close from the owner's cleanup-observed settlement.
    """
    for key in ('lifecycle_final','lifecycle_failure_closure'):
        if isinstance(bindings.get(key),dict):return bindings[key]
    return None


def _closure_from_bindings(bindings,stage):
    if stage=='final_qualification':
        lifecycle=bindings.get('lifecycle_final')
        if isinstance(lifecycle,dict):
            return final._lifecycle_closed_report(
                lifecycle['cleanup_binding']['identity'],
                lifecycle['predecessor_receipt'],
                lifecycle['cleanup_binding'])
        proof=bindings['final_qualification'];program=proof['pre_spawn_program']
        return final._closed_report(program['identity'],proof['settlement_report'],program,proof['metadata'])
    _require(stage=='failure_closure')
    return failure._reconstruct(bindings)


def _closure(identity,receipt):
    for value in (identity,receipt):
        _json(value);_require(len(attempt._canonical(value))<=settlement.native.MAX_PROGRAM_BYTES)
    expected=_closure_from_bindings(receipt['bindings'],receipt['stage'])
    issues=[];bound=attempt._validate_identity(identity,issues)
    _require(not issues and expected['receipt']['identity_sha256']==attempt._sha(bound)
        and _same(receipt,expected['receipt']) and expected['next_action']=='owner_disposition','closure_invalid')
    return expected


def _settlement(prior):
    bindings=prior['receipt']['bindings']
    return (bindings['final_qualification']['settlement_report'] if prior['operation']=='final_qualification'
            else bindings['failure_closure']['checks'][0]['settlement_report'])


def _snapshot(controller,prior):
    authority=controller.grants.canonical_authority()
    settlement.completion_waiting_authority(authority)
    lifecycle=_lifecycle(prior['receipt']['bindings'])
    source=None if isinstance(lifecycle,dict) else _settlement(prior)
    authority_after=(lifecycle['cleanup_binding']['authority_after']
                     if isinstance(lifecycle,dict) else source['authority_after'])
    _require(_same(authority['owner'],authority_after['owner']),'owner_changed')
    state,rows=controller._state(authority['owner']['controller_run_id'],recover_provisional=False)
    _require(authority['owner']['activation_sha256']==attempt._sha(state['activation'])
        and _same(settlement.native._cursor(rows),authority['tip'])
        and _same(state['stage_report'],prior),'current_closure_changed')
    _require(state['terminal'] is False and state['pending_intent'] is None and state['action'] is None
        and state['grant_state'] is None and state['cleanup_required'] is False and state['action_outcome'] is None)
    _require(controller._hook_runtime_matches(state['activation']['identity'])
        and controller._retained_hook_evidence_valid(state),'hooks_changed')
    capacity=settlement._read_capacity(controller)
    inventory=controller.grants.read_grant_inventory()
    base=deepcopy({'authority':authority,'capacity':capacity,'grant_inventory':inventory,
        'state_sha256':attempt._sha(state),'journal_sha256':attempt._sha(rows),
        'closure_report_sha256':attempt._sha(prior)})
    if isinstance(_lifecycle(prior['receipt']['bindings']),dict):
        return base
    events=settlement.native._controller_events(rows)
    _require(events[-2]['event_type']=='stage_intent' and events[-1]['event_type']=='stage_result')
    return {**base,'last_stage_time':events[-2]['payload']['evaluation_time'],
        'closure_intent':events[-2],'closure_intent_cursor':settlement.native._cursor(rows[:-1]),
        'closure_result_sha256':events[-1]['event_sha256']}


def _snapshot_transport(prior,snapshot):
    authority=snapshot['authority'];receipt=prior['receipt']
    lifecycle=_lifecycle(receipt['bindings'])
    simple=isinstance(lifecycle,dict)
    source=None if simple else _settlement(prior)
    binding=lifecycle['cleanup_binding'] if simple else None
    authority_after=binding['authority_after'] if simple else source['authority_after']
    common={'authority','capacity','grant_inventory','state_sha256','journal_sha256','closure_report_sha256'}
    _require(set(snapshot)==(common if simple else common|{
        'last_stage_time','closure_intent','closure_intent_cursor','closure_result_sha256'}))
    settlement.completion_waiting_authority(authority)
    _require(_same(authority['owner'],authority_after['owner'])
        and _same(authority['identity'],authority_after['identity'])
        and authority['tip']['run_id']==authority_after['tip']['run_id']
        and type(authority['tip']['seq']) is int and authority['tip']['seq']==authority_after['tip']['seq']+2
        and snapshot['closure_report_sha256']==attempt._sha(prior))
    for name in ('state_sha256','journal_sha256'):_require(settlement.capacity._digest(snapshot[name]))
    capacity=snapshot['capacity']
    _require(_same(capacity,settlement.capacity.authority_read_report(capacity['state'],store_id=capacity['store_id']))
        and capacity['status']=='VERIFIED' and capacity['continuity_verified'] is True
        and capacity['store_id']==receipt['bindings']['capacity_authority_store_id']
        and (not simple or capacity['state_sha256']==binding['capacity_state_sha256'])
        and capacity['state']['active_lane_ids']==[],'capacity_unsettled')
    inventory=snapshot['grant_inventory'];counts=inventory['state_counts']
    _require(type(counts) is dict and set(counts)==set(_STATES)
        and all(type(v) is int and v>=0 for v in counts.values()))
    _require(sum(counts[s] for s in ('PROVISIONAL','AUTHORIZED','DISPATCHED','OUTCOME_UNKNOWN'))==0,'grants_unsettled')
    _require(settlement.capacity._digest(inventory['inventory_sha256']))
    core={'schema':'orch-dork/native-grant-inventory/v1','status':'VERIFIED','issues':[],
        'scope':'all_canonical_grants','owner':authority['owner'],'store_identity_sha256':authority['owner']['store_identity_sha256'],
        'grant_count':sum(counts.values()),'unsettled_grant_count':0,'state_counts':counts,
        'inventory_sha256':inventory['inventory_sha256'],'continuation_permitted':False,'terminal_claim_permitted':False,'provider_free':True}
    _require(_same(inventory,{**core,'report_sha256':attempt._sha(core)}),'grant_inventory_unverified')
    if simple:
        return
    if prior['operation']=='final_qualification':
        pre=receipt['bindings']['final_qualification']['pre_spawn_program']
        program=final.build_final_qualification_program(pre['identity'],source,pre)
    else:
        identity=receipt['bindings']['failure_closure']['checks'][0]['identity']
        program=failure.build_failure_closure_program(identity,source,
            pre_spawn_program=receipt['bindings']['failure_closure'].get('pre_spawn_program'))
    intent=settlement.native._event_record('stage_intent',{'operation':prior['operation'],
        'stage_program_sha256':attempt._sha(program),'evaluation_time':snapshot['last_stage_time'],'proposed_action_sha256':None})
    _require(_same(snapshot['closure_intent'],intent),'closure_intent_changed')
    cursor=snapshot['closure_intent_cursor']
    _require(set(cursor)=={'run_id','seq','event_hash'} and type(cursor['seq']) is int
        and cursor['seq']==authority['tip']['seq']-1 and cursor['run_id']==authority['tip']['run_id']
        and settlement.capacity._digest(cursor['event_hash']))
    result=settlement.native._event_record('stage_result',{'intent_cursor':cursor,'stage_report':prior,'action':None,
        'capacity_guard':None,'terminal':False,'cleanup_required':False,'terminal_evidence_sha256':None,'issues':[]})
    _require(snapshot['closure_result_sha256']==result['event_sha256'],'closure_result_changed')
    stamp=settlement.observer_receipt.evidence.instant(snapshot['last_stage_time'])
    if prior['operation']=='final_qualification':
        _require(stamp>=settlement.observer_receipt.evidence.instant(
            receipt['bindings']['final_qualification']['decision_time']))
    elif 'metadata' in receipt['bindings']['failure_closure']:
        _require(stamp>=settlement.observer_receipt.evidence.instant(
            receipt['bindings']['failure_closure']['metadata']['observed_at']))


def observe_owner_disposition_readiness(controller,receipt):
    """Bracket actual completed state and all grants; mutate no authority."""
    snapshot=None;now=None;issues=[]
    try:
        prior=_closure_from_bindings(receipt['bindings'],receipt['stage'])
        _require(_same(prior['receipt'],receipt))
        before=_snapshot(controller,prior);_snapshot_transport(prior,before)
        after=_snapshot(controller,prior);_require(_same(before,after),'state_changed')
        stamp=controller._evaluation_time()
        _require('last_stage_time' not in before or
            stamp>=settlement.observer_receipt.evidence.instant(before['last_stage_time']),'clock_regressed')
        snapshot=before;now=stamp.isoformat()
    except Exception as error:
        issues=['owner_readiness:observation_'+type(error).__name__]
    core={'schema':OBSERVATION_SCHEMA,'status':'REFUSED' if issues else 'OBSERVED','issues':issues,
        'snapshot':snapshot,'observed_at':now,'terminal_claim_permitted':False,'owner_released':False,
        'continuation_permitted':False,'model_calls':0,'native_calls':0}
    return {**core,'report_sha256':attempt._sha(core)}


def _observation(prior,observed):
    _json(observed);_snapshot_transport(prior,observed['snapshot'])
    _require('last_stage_time' not in observed['snapshot'] or
        settlement.observer_receipt.evidence.instant(observed['observed_at'])
        >=settlement.observer_receipt.evidence.instant(observed['snapshot']['last_stage_time']))
    core={'schema':OBSERVATION_SCHEMA,'status':'OBSERVED','issues':[],
        'snapshot':observed['snapshot'],'observed_at':observed['observed_at'],
        'terminal_claim_permitted':False,'owner_released':False,'continuation_permitted':False,'model_calls':0,'native_calls':0}
    _require(_same(observed,{**core,'report_sha256':attempt._sha(core)}),'observation_unverified')


def build_owner_disposition_program(identity:Any,closure_report:Any)->dict:
    prior=_closure(identity,closure_report['receipt']);_require(_same(prior,closure_report))
    # Retain the large closure exactly once: the payload references its digest.
    return deepcopy({'schema':attempt.PROGRAM_SCHEMA,'operation':'owner_disposition','identity':identity,
        'predecessor_receipt':prior['receipt'],'payload':{'closure_report_sha256':attempt._sha(prior)}})


def _closed_report(identity,prior,observed):
    _observation(prior,observed)
    receipt=prior['receipt']
    proof={'schema':SCHEMA,'closure_stage':prior['operation'],'closure_report_sha256':attempt._sha(prior),
        'observation':observed,'owner_disposition':'pending','successor_owner':None}
    successor=attempt._receipt(stage='owner_disposition',status='QUIESCENT',identity=identity,
        plan={'plan_id':receipt['plan_id'],'revision':receipt['plan_revision']},plan_sha256=receipt['plan_sha256'],
        predecessor=receipt,next_action='await_successor_owner',bindings={**deepcopy(receipt['bindings']),'owner_disposition':proof})
    return attempt._report(operation='owner_disposition',identity=identity,status='PASS',disposition='CONTROLLER_QUIESCENT',
        issues=[],stages=[attempt._stage('owner_readiness','PASS',observed,[])],receipt=successor)


def evaluate_owner_disposition(identity,predecessor,payload,*,observer=None):
    try:
        _require(type(payload) is dict and set(payload)=={'closure_report_sha256'})
        prior=_closure(identity,predecessor)
        _require(payload['closure_report_sha256']==attempt._sha(prior))
        _require(callable(observer),'host_observer_required')
        return _closed_report(identity,prior,observer(deepcopy(predecessor)))
    except Exception as error:
        issue=str(error) if type(error) is ValueError and str(error).startswith('owner_readiness:') else 'owner_readiness:'+type(error).__name__
        return attempt._report(operation='owner_disposition',identity=identity,status='BLOCKED',disposition='OWNER_DISPOSITION_REFUSED',issues=[issue],stages=[])


def _reconstruct(receipt):
    bindings=receipt['bindings'];proof=bindings['owner_disposition']
    prior=_closure_from_bindings(bindings,proof['closure_stage'])
    # The accepted closure owns the complete governed identity.
    if prior['operation']=='final_qualification':
        lifecycle=bindings.get('lifecycle_final')
        identity=(lifecycle['cleanup_binding']['identity'] if isinstance(lifecycle,dict)
                  else bindings['final_qualification']['pre_spawn_program']['identity'])
    elif isinstance(bindings.get('lifecycle_failure_closure'),dict):
        identity=bindings['lifecycle_failure_closure']['cleanup_binding']['identity']
    else:identity=bindings['failure_closure']['checks'][0]['identity']
    return _closed_report(identity,prior,proof['observation'])


def validate_owner_disposition_report(report):
    try:
        _json(report);_require(len(attempt._canonical(report))<=4*settlement.native.MAX_EVENT_BYTES)
        _require(_same(report,_reconstruct(report['receipt'])))
    except _INVALID:return {'valid':False,'issues':['owner_readiness:report_invalid'],'scope':'canonical_transport'}
    return {'valid':True,'issues':[],'scope':'canonical_transport'}


def owner_disposition_next_action(root_task_id,receipt):
    try:
        expected=_reconstruct(receipt)
        _require(_same(receipt,expected['receipt']) and expected['root_task_id']==root_task_id)
        return 'await_successor_owner'
    except _INVALID as error:raise ValueError('owner_readiness:receipt_invalid') from error


def _commit_time(controller,validated_report):
    proof=validated_report['receipt']['bindings']['owner_disposition']
    run_id=proof['observation']['snapshot']['authority']['owner']['controller_run_id']
    state,_=controller._state(run_id,recover_provisional=False)
    prior=state['stage_report']
    _require(attempt._sha(prior)==proof['closure_report_sha256'],'commit_closure_changed')
    current=_snapshot(controller,prior)
    _require(_same(current,proof['observation']['snapshot']),'commit_state_changed')
    now=controller._evaluation_time()
    _require(now>=settlement.observer_receipt.evidence.instant(proof['observation']['observed_at']),'commit_clock_regressed')
    return now


__all__=['build_owner_disposition_program','observe_owner_disposition_readiness','evaluate_owner_disposition',
         'validate_owner_disposition_report','owner_disposition_next_action']
