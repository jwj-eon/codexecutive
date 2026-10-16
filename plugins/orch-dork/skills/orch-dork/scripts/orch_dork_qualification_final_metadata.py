"""Final worker contracts and source-bound metadata, without terminal authority."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime,timezone
import json
import hashlib
import os
from pathlib import Path
from typing import Any

import orch_dork_governed_attempt as attempt
import orch_dork_completion_settlement as settlement
import orch_dork_qualification_wave as wave
import orch_dork_owned_file as owned


def _require(condition: bool) -> None:
    if not condition:raise ValueError('final_metadata:input_invalid')


def _same(left: Any,right: Any) -> bool:
    return attempt._canonical(left)==attempt._canonical(right)


def build_native_terminal_contracts(identity: Any,predecessor_report: Any,wave_program: Any) -> dict:
    """Project only the accepted handoffs and their observed root verifications."""
    try:
        issues=[]
        receipt=attempt._post_batch_predecessor_report(identity,predecessor_report,issues)
        _require(not issues and receipt['stage']=='capacity_settlement' and receipt['next_action']=='final_qualification')
        bindings=receipt['bindings'];verification=bindings['terminal_verification']
        _require(verification['outcome']=='success' and bindings['review_outcome']=='accepted')
        approvals=bindings['review_submission']['verifications']
        by_lane={row['logical_worker_id']:row['verification_receipt'] for row in approvals}
        _require(len(approvals)==len(by_lane)==2 and set(by_lane)=={'spec','standards'})
        contracts=[]
        for worker in bindings['worker_results']:
            task,handoff=worker['task_spec'],worker['handoff_receipt'];lane=worker['binding']['logical_worker_id']
            approved=by_lane[lane]
            _require(approved['verifier']['identity']==identity['root_task_id'] and approved['verifier']['clean_context'] is True)
            ledger=attempt.adaptive_contracts.seal_claim_ledger({'schema':attempt.adaptive_contracts.CLAIM_LEDGER_SCHEMA,
                'task_spec_sha256':task['task_spec_sha256'],'claims':handoff['claims'],'artifacts':handoff['artifact_refs']},task_spec=task)
            contracts.append({'logical_worker_id':lane,'task_spec':task,'handoff_receipt':handoff,
                'verification_receipt':approved,'claim_ledger':ledger})
        checked=attempt._terminal_worker_evidence(identity,receipt,wave_program,contracts)
        _require(checked['issues']==[] and all(stage['status']=='PASS' for stage in checked['stages']))
        core={'schema':'orch-dork/native-terminal-contracts/v1','status':'PASS',
            'predecessor_receipt_sha256':receipt['receipt_sha256'],'wave_program_sha256':attempt._sha(wave_program),
            'review_submission_sha256':bindings['review_submission']['submission_sha256'],
            'contracts':contracts,'worker_evidence':checked,'terminal_claim_permitted':False,'model_calls':0,'native_calls':0}
        return deepcopy({**core,'report_sha256':attempt._sha(core)})
    except (KeyError,IndexError,TypeError,ValueError,OverflowError,RecursionError) as error:
        raise ValueError('final_metadata:contracts_invalid') from error


def _utc(value: Any) -> str:
    clock=settlement.observer_receipt.evidence.instant(value)
    return clock.astimezone(timezone.utc).isoformat().replace('+00:00','Z')


def _trace_for_times(program: dict,source: dict,current_wave: dict,call_times: dict,now: datetime) -> dict:
    """Normalize observed lifecycle facts; never invent worker resource transfers."""
    identity=program['identity'];prior=source['native_result']['stage_report']['receipt']
    observed=source['completion_capture']['source_observation']['evidence']
    events=[];revision=prior['plan_revision']
    def event(kind,at,node,actor,refs,data):
        events.append({'seq':0,'type':kind,'node_id':node,'plan_revision':revision,'actor':actor,
            'at':_utc(at),'artifact_refs':refs,'data':data})
    root={'kind':'root','model':identity['root_model'],'effort':identity['root_effort']}
    validator={'kind':'validator','model':None,'effort':None}
    admitted=current_wave['context']['admission']['intent']
    event('plan',admitted['payload']['evaluation_time'],None,root,[],
        {'program_sha256':attempt._sha(program),'intent_sha256':admitted['event_sha256']})
    for lane in ('spec','standards'):
        role=observed['roles'][lane];windows=role['windows'];spawn=observed['worker_events'][lane][0]
        worker={'kind':'worker','model':windows[0]['model'],'effort':windows[0]['effort']}
        event('assign',spawn['call_timestamp'],lane,root,[],{'worker_id':role['task_id'],'source_ref':spawn['source_refs']['call']})
        event('start',windows[0]['start']['timestamp'],lane,worker,[],{'source_ref':windows[0]['start']})
        event('checkpoint',windows[1]['end']['timestamp'],lane,worker,[],{'source_ref':windows[1]['end'],
            'checkpoint_sources_sha256':prior['bindings']['checkpoint_sources_sha256']})
        event('finish',windows[-1]['end']['timestamp'],lane,worker,[],{'source_ref':windows[-1]['end']})
    windows=observed['roles']['root']['windows']
    actions=[action for window in windows for action in window['actions']['items']]
    _require(len(actions)==len({action['call_id'] for action in actions})
        and set(call_times)=={action['call_id'] for action in actions})
    for window in windows:
        for action in window['actions']['items']:
            stamp=settlement.observer_receipt.evidence.instant(call_times[action['call_id']])
            _require(settlement.observer_receipt.evidence.instant(window['start']['timestamp'])<=stamp
                <=settlement.observer_receipt.evidence.instant(window['end']['timestamp']))
            event('tool',call_times[action['call_id']],None,root,[],{'call_id':action['call_id'],'name':action['name'],
                'namespace':action['namespace'],'source_ref':action['source_ref']})
    # This is when the host observes completed verification, not a guessed
    # timestamp for the root's earlier reasoning or future final acceptance.
    event('verify',now.isoformat(),None,validator,[],{'scope':'observed_terminal_verification',
        'verification_sha256':prior['bindings']['terminal_verification']['verification_sha256']})
    events.sort(key=lambda row:settlement.observer_receipt.evidence.instant(row['at']))
    for seq,row in enumerate(events,1):row['seq']=seq
    trace={'schema':attempt.run_trace.TRACE_SCHEMA,'run_id':identity['run_id'],
        'plan_revisions':[{'revision':revision,'plan_sha256':prior['plan_sha256']}],'events':events}
    report=attempt.run_trace.validate_run_trace(trace);_require(report['status']=='PASS')
    return {'trace':trace,'report':report}


def _trace(program: dict,source: dict,current_wave: dict,root_raw: bytes,now: datetime) -> dict:
    """Bind exact raw call timestamps before the portable trace projection."""
    _require(root_raw.endswith(b'\n'))
    lines=root_raw.split(b'\n')[:-1]
    observed=source['completion_capture']['source_observation']['evidence']
    actions=[action for window in observed['roles']['root']['windows'] for action in window['actions']['items']]
    call_times={}
    for action in actions:
        ref=action['source_ref'];raw=lines[ref['line']-1]
        _require(hashlib.sha256(raw).hexdigest()==ref['sha256'])
        row=json.loads(raw);payload=row['payload']
        _require(payload['call_id']==action['call_id'] and payload['name']==action['name']
            and payload.get('namespace')==action['namespace'])
        call_times[action['call_id']]=row['timestamp']
    return _trace_for_times(program,source,current_wave,call_times,now)


def _capsule(program: dict,source: dict,current_wave: dict) -> dict:
    """Update the admitted capsule; leave unobserved pressure and phase timing unknown."""
    initial=attempt.coordinator_capsule.evaluate_coordinator_capsule(program['payload']['coordinator_capsule'])
    prior=source['native_result']['stage_report']['receipt'];bindings=prior['bindings']
    _require(initial['status']=='PASS' and initial['capsule_sha256']==bindings['capsule_sha256'])
    capsule=initial['capsule'];identity=capsule['identity'];owner=program['identity']['root_task_id']
    _require(identity['execution_lease']['owner_thread_id']==owner and identity['plan_sha256']==prior['plan_sha256']
        and identity['admission_sha256']==bindings['ticket_admission_sha256'])
    cursor=source['authority_after']['tip'];pointer='native-completion:'+source['report_sha256']
    state=deepcopy(capsule['state'])
    state.update(workers=[{'worker_id':row['binding']['worker_id'],'status':'completed',
            'last_event_seq':cursor['seq'],'source_pointer':pointer+'#observed-workers'} for row in bindings['worker_results']],
        integration={'status':'validating','owner_id':owner,'release_count':0,'source_pointer':pointer+'#root-verification'},
        event_cursor={'stream_id':cursor['run_id'],'seq':cursor['seq'],'prefix_sha256':cursor['event_hash'],'source_pointer':pointer+'#cursor'},
        artifact_hashes={'plan':prior['plan_sha256'],'ticket_admission':bindings['ticket_admission_sha256'],
            'native_completion':source['report_sha256'],'native_wave':current_wave['wave']['report_sha256']},
        unresolved_unknowns=['context_pressure','completion_reserve_remaining','phase_telemetry'],
        completion_reserve={'status':'unknown','remaining':None,'unit':state['completion_reserve']['unit'],
            'source_pointer':pointer+'#reserve-remaining-unobserved'},no_change_count=0,
        next_action={'kind':'stop_for_authority','reason':'complete final verification before owner disposition','source_pointer':pointer+'#pending-final'})
    state['invariant_sha256']=attempt._sha({'authority':source['authority_after'],'stage_receipt_sha256':prior['receipt_sha256']})
    telemetry={name:{'known':False,'value':None,'unit':'milliseconds','source_pointer':pointer+'#phase-unobserved-'+name}
        for name in attempt.coordinator_capsule.TELEMETRY_CATEGORIES}
    observation={key:deepcopy(identity[key]) for key in ('ticket_id','acceptance_sha256','admission_sha256','plan_sha256','source_version','installed_version')}
    observation.update(lease=deepcopy(identity['execution_lease']),artifact_hashes=deepcopy(state['artifact_hashes']),
        event_cursor=deepcopy(state['event_cursor']),invariant_sha256=state['invariant_sha256'],
        context_used=None,context_limit=None,completion_reserve_remaining=None,successor_lease=None,
        successor_capsule_version=None,successor_capsule_sha256=None,evidence_complete=True,source_pointer=pointer+'#current-observation')
    update={'schema':attempt.coordinator_capsule.PROGRAM_SCHEMA,'operation':'update','capsule_id':capsule['capsule_id'],
        'expected_version':capsule['version'],'current_capsule':capsule,'identity':identity,'state':state,'telemetry':telemetry,
        'policy':capsule['policy'],'observation':observation,'historical_replays':None,
        'event':{'event_id':'native-completion-observed',
            'type':'validation.completed','expected_version':capsule['version'],'previous_capsule_sha256':capsule['capsule_sha256'],
            'observed_invariant_sha256':state['invariant_sha256'],'source_pointer':pointer+'#capsule'}}
    report=attempt.coordinator_capsule.evaluate_coordinator_capsule(update);_require(report['status']=='PASS')
    return {'program':update,'report':report}


def observe_native_final_metadata(controller,settlement_report: Any,pre_spawn_program: Any) -> dict:
    """Observe metadata on the same current host; this never advances a stage."""
    source,program=deepcopy(settlement_report),deepcopy(pre_spawn_program)
    current,contracts,trace,capsule,dogfood,now=None,None,None,None,None,None
    issues=[]
    try:
        _require(settlement.validate_completed_capacity_settlement(source)['valid'])
        before=settlement._settled_snapshot(controller,source)
        current=wave.observe_completed_native_wave(controller,source,program);_require(current['status']=='OBSERVED')
        contracts=build_native_terminal_contracts(program['identity'],source['native_result']['stage_report'],current['wave']['wave_program'])
        root=source['completion_capture']['source_observation']['evidence']['roles']['root']
        private=os.environ.get('CODEX_HOME') or str(Path.home()/'.codex')
        captured=owned.read_private_rollout(root['path'],private_root=private)
        _require(all(_same(captured[key],root[key]) for key in ('file_sha256','prefix_bytes','custody')))
        now=controller._evaluation_time()
        _require(now>=settlement.observer_receipt.evidence.instant(current['observed_at']))
        metadata_started=now
        trace=_trace(program,source,current,captured['raw'],now)
        capsule=_capsule(program,source,current)
        spine=attempt.dogfood_recovery.derive_run_spine(root['path'],run_key=program['identity']['run_id'],
            derived_at=_utc(now.isoformat()),derived_by='native-qualification-host')
        verified=attempt.dogfood_recovery.verify_spine(spine,root['path'])
        _require(verified['verified'] is True and spine['source']['session_sha256']==root['file_sha256']
            and spine['source']['session_id']==program['identity']['root_task_id'])
        dogfood={'spine':spine,'verification':verified,'source_path':root['path'],'analysis_seen':True,'label_mode':'non_blind'}
        after_file=owned.read_private_rollout(root['path'],private_root=private)
        _require(_same({key:value for key,value in captured.items() if key!='raw'},
            {key:value for key,value in after_file.items() if key!='raw'}) and captured['raw']==after_file['raw'])
        now=controller._evaluation_time()
        _require(now>=metadata_started)
        for release in source['release_receipts']:
            signed=release['cleanup_observer_receipt']
            _require(settlement.observer_receipt.evidence.instant(signed['issued_at'])<=now<=settlement.observer_receipt.evidence.instant(signed['valid_until']))
        _require(_same(before,settlement._settled_snapshot(controller,source)))
    except Exception as error:
        issues=['final_metadata:observation_'+type(error).__name__]
    core={'schema':'orch-dork/native-final-metadata/v1','status':'REFUSED' if issues else 'OBSERVED','issues':issues,
        'current_wave':current,'terminal_contracts':contracts,'run_trace':trace,'coordinator_capsule':capsule,'dogfood':dogfood,
        'observed_at':now.isoformat() if now else None,'terminal_claim_permitted':False,'resource_release_proven':False,
        'continuation_permitted':False,'model_calls':0,'native_calls':0,'cost_usd':None}
    return deepcopy({**core,'report_sha256':attempt._sha(core)})


__all__=['build_native_terminal_contracts','observe_native_final_metadata']
