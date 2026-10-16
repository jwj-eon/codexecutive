"""Reconstruct a completed native v3 wave from admitted, observed evidence.

The pure constructor grants no authority. The host entry point binds both
historical admissions and current signed settlement around the reconstruction.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

import orch_dork_governed_attempt as attempt
import orch_dork_completion_settlement as settlement
import orch_dork_qualification_verification as verification
from orch_dork_governed_native_reports import _json

governor = attempt.efficiency_governor
SCHEMA = 'orch-dork/native-completed-wave/v1'
_INVALID = (KeyError, IndexError, TypeError, ValueError, OverflowError, RecursionError)


def _require(condition: bool) -> None:
    if not condition:raise ValueError('native_wave:input_invalid')


def _same(left: Any, right: Any) -> bool:
    return attempt._canonical(left) == attempt._canonical(right)


def build_native_completed_wave(pre_spawn_program: Any, pre_spawn_report: Any, capacity_admission_report: Any,
                                 predecessor_report: Any, observation: Any, *, checkpoint_sources: Any) -> dict:
    """Construct a canonical wave; the host must authenticate all supplied inputs.

    Inventory is an admitted-slot view, not a claimed native capacity snapshot.
    No readiness or admission is re-executed, no observation is synthesized, and
    neither DRAINED nor this PASS is a final qualification or dispatch grant.
    """
    try:
        for value in (pre_spawn_program,pre_spawn_report,capacity_admission_report,predecessor_report,observation,checkpoint_sources):
            _json(value)
            _require(len(attempt._canonical(value)) <= settlement.native.MAX_PROGRAM_BYTES)
        _require(pre_spawn_program['schema'] == attempt.CHECKPOINT_PROGRAM_SCHEMA)
        capacity_program = attempt.build_capacity_admission_program(pre_spawn_program,pre_spawn_report)
        identity = capacity_program['identity']
        issues = []
        admitted = attempt._validate_receipt(capacity_admission_report.get('receipt'),identity,issues,
            allowed_stages={'capacity_admission'},allowed_actions={'spawn'})
        current = attempt._post_batch_predecessor_report(identity,predecessor_report,issues)
        prior = pre_spawn_report['receipt']
        _require(not issues and prior['status']=='READY' and prior['predecessor_receipt_sha256'] is None
            and _same(pre_spawn_report,attempt._report(operation='pre_spawn',identity=identity,status='PASS',
                disposition='SHARED_CAPACITY_ADMISSION_REQUIRED',issues=[],stages=pre_spawn_report['stages'],receipt=prior))
            and current['stage']=='capacity_settlement' and current['status']=='SETTLED'
            and admitted['status']=='AUTHORIZED'
            and admitted['predecessor_receipt_sha256']==prior['receipt_sha256']
            and admitted['plan_sha256']==prior['plan_sha256']==current['plan_sha256']
            and _same(capacity_admission_report,attempt._report(operation='capacity_admission',identity=identity,status='PASS',
                disposition='SPAWN_AUTHORIZED',issues=[],stages=capacity_admission_report['stages'],receipt=admitted)))
        bound, final = admitted['bindings'], current['bindings']
        _require(type(bound['capacity_wave_index']) is int and bound['capacity_wave_index']==1
            and type(final['capacity_wave_index']) is int and final['capacity_wave_index']==1
            and bound['current_wave_logical_lane_ids']==['spec','standards']
            and final['completed_logical_lane_ids']==['spec','standards']
            and bound['capacity_authority_lane_ids']==[identity['run_id']+':'+lane for lane in ('spec','standards')]
            and bound['capacity_authority_store_id']==final['capacity_authority_store_id']
            and _same(bound['task_specs'],final['task_specs']) and _same(bound['all_task_specs'],final['all_task_specs']))
        plan = pre_spawn_program['payload']['logical_plan']
        custody = verification.build_native_dependency_ordered_custody(plan,predecessor_report,observation,
            checkpoint_sources=checkpoint_sources)
        wave = deepcopy(pre_spawn_program['payload']['wave_preflight'])
        _require(wave['schema']==governor.WAVE_PROGRAM_SCHEMA_V3 and wave['observations']==[]
            and wave['root_thread_id']==identity['root_task_id'] and _same(wave['logical_plan'],plan))
        rows = final['worker_results']
        originals = {row['logical_worker_id']:row['task_spec'] for row in wave['task_specs']}
        _require(len(originals)==len(wave['task_specs'])==2
            and set(originals)=={'spec','standards'} and len(rows)==2)
        members, routes, creations, terminals = [], [], [], []
        for row in rows:
            lane, worker = row['binding']['logical_worker_id'],row['binding']['worker_id']
            _require(_same(row['task_spec'],originals[lane]))
            runtime = row['runtime_observation']
            spawn = observation['evidence']['worker_events'][lane][0]
            _require(spawn['kind']=='spawn' and spawn['worker_id']==worker
                and spawn['parent_thread_id']==identity['root_task_id'] and spawn['context_policy']=='none')
            member = {'lane_id':lane,'role':'worker','worker_id':worker,'session_id':worker}
            members.append(member);routes.append({**member,'session_observation':deepcopy(runtime)})
            creations.append({'logical_worker_id':lane,'worker_id':worker,'session_id':worker,
                'status':'created','fresh':True,'parent_thread_id':spawn['parent_thread_id']})
            usage = {key:runtime['usage'][key] for key in
                ('status','input_tokens','cached_input_tokens','output_tokens','reasoning_tokens','total_tokens')}
            usage['source_pointer'] = runtime['source_pointer']
            terminals.append({'logical_worker_id':lane,'worker_id':worker,'status':'completed','usage':usage,
                'evidence_pointer':runtime['source_pointer'],'handoff_receipt':deepcopy(row['handoff_receipt'])})
        inventory = {'schema':'orch-dork/collaboration-inventory/v1','root_thread_id':identity['root_task_id'],
            'capacity':len(bound['capacity_authority_lane_ids']),'retirement_supported':False,'workers':[]}
        wave['observations'] = [{'wave_id':'wave-001','inventory':inventory,'creations':creations,'terminals':terminals,
            'custody_events':custody['bundle'],'progress_events':deepcopy(final['progress_prefixes']['1']['events']),
            'routing_program':{'schema':governor.routing_verify.WAVE_ROUTING_PROGRAM_SCHEMA_V3,
                'plan_worker_model':plan['execution']['worker_model'],'plan_worker_effort':plan['execution']['worker_effort'],
                'plan_root_model':identity['root_model'],'plan_root_effort':identity['root_effort'],
                'expected_members':members,'lanes':routes}}]
        checked = governor.run_wave_program(wave)
        _require(checked['status']=='DRAINED' and checked['plan_sha256']==current['plan_sha256'])
        core = {'schema':SCHEMA,'status':'PASS','scope':'canonical_native_wave_reconstruction',
            'pre_spawn_program_sha256':attempt._sha(pre_spawn_program),'pre_spawn_receipt_sha256':prior['receipt_sha256'],
            'capacity_admission_receipt_sha256':admitted['receipt_sha256'],'predecessor_receipt_sha256':current['receipt_sha256'],
            'native_observation_sha256':observation['report_sha256'],
            'checkpoint_sources_sha256':final['checkpoint_sources_sha256'],
            'inventory_scope':'admitted_current_wave_slots','allocated_slot_ids':bound['capacity_authority_lane_ids'],
            'wave_program':wave,'wave_report':checked,'custody_projection':custody,
            'continuation_permitted':False,'terminal_claim_permitted':False,'resource_release_proven':False,
            'model_calls':0,'native_calls':0,'cost_usd':None}
        return deepcopy({**core,'report_sha256':attempt._sha(core)})
    except _INVALID as error:
        raise ValueError('native_wave:input_invalid') from error


def validate_native_completed_wave(report: Any, pre_spawn_program: Any, pre_spawn_report: Any,
                                   capacity_admission_report: Any, predecessor_report: Any, observation: Any,
                                   *, checkpoint_sources: Any) -> bool:
    """Validate complete transport without converting supplied JSON into authority."""
    try:
        _json(report)
        return _same(report,build_native_completed_wave(pre_spawn_program,pre_spawn_report,capacity_admission_report,
            predecessor_report,observation,checkpoint_sources=checkpoint_sources))
    except _INVALID:
        return False


def observe_completed_native_wave(controller, settlement_report: Any, pre_spawn_program: Any) -> dict:
    """Authenticate admitted inputs and bracket reconstruction with current state."""
    source, program = deepcopy(settlement_report),deepcopy(pre_spawn_program)
    context, wave, now, issues = None,None,None,[]
    try:
        _require(settlement.validate_completed_capacity_settlement(source)['valid'])
        before = settlement._settled_snapshot(controller,source)
        context = settlement.observe_completion_admission_context(controller,source,program)
        _require(context['status']=='OBSERVED')
        wave = build_native_completed_wave(program,context['admission']['stage_report'],context['capacity_admission']['stage_report'],
            source['native_result']['stage_report'],source['completion_capture']['source_observation'],
            checkpoint_sources=source['completion_capture']['checkpoint_sources'])
        now = controller._evaluation_time()
        _require(now >= settlement.observer_receipt.evidence.instant(context['observed_at']))
        for release in source['release_receipts']:
            signed = release['cleanup_observer_receipt']
            _require(settlement.observer_receipt.evidence.instant(signed['issued_at']) <= now
                <= settlement.observer_receipt.evidence.instant(signed['valid_until']))
        _require(_same(before,settlement._settled_snapshot(controller,source)))
    except Exception as error:
        issues = ['native_wave:observation_'+type(error).__name__]
    core = {'schema':'orch-dork/current-native-completed-wave/v1','status':'REFUSED' if issues else 'OBSERVED',
        'issues':issues,'context':context,'wave':wave,'observed_at':now.isoformat() if now else None,
        'terminal_claim_permitted':False,'continuation_permitted':False,'resource_release_proven':False,
        'model_calls':0,'native_calls':0,'signing_key_reads':0}
    return {**core,'report_sha256':attempt._sha(core)}


__all__ = ['build_native_completed_wave','validate_native_completed_wave','observe_completed_native_wave']
