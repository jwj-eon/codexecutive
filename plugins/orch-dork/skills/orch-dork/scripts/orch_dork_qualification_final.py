"""Seven-check native qualification; owner disposition remains a separate stage.

The evaluator needs a host-injected fresh metadata observer. A serialized
OBSERVED report never supplies that authority. Report validation checks retained
transport relationships and does not authenticate a caller's JSON origin.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

import orch_dork_governed_attempt as attempt
import orch_dork_completion_settlement as settlement
import orch_dork_qualification_closure as closure
import orch_dork_qualification_budget as budget
import orch_dork_qualification_final_metadata as metadata
import orch_dork_qualification_wave as wave
from orch_dork_governed_native_reports import _json

SCHEMA='orch-dork/native-final-qualification/v1'
LIFECYCLE_SCHEMA='orch-dork/lifecycle-final-qualification/v1'
CLEANUP_BINDING_SCHEMA='orch-dork/lifecycle-cleanup-binding/v1'
CHECKS=('wave_v3_terminal','typed_terminal_contracts','independent_attempt_observer','run_trace',
        'coordinator_capsule','dogfood_spine','shared_capacity_settlement')
_INVALID=(KeyError,IndexError,TypeError,ValueError,OverflowError,RecursionError)


def _require(condition: bool,issue: str='binding_invalid') -> None:
    if not condition:raise ValueError('final_qualification:'+issue)


def _same(left: Any,right: Any) -> bool:
    return attempt._canonical(left)==attempt._canonical(right)


def _source(identity: Any,source: Any,program: Any) -> dict:
    try:
        for value in (identity,source,program):
            _json(value);_require(len(attempt._canonical(value))<=settlement.native.MAX_PROGRAM_BYTES)
        issues=[];bound=attempt._validate_identity(identity,issues)
        _require(not issues and _same(bound,program['identity']) and program['schema']==attempt.CHECKPOINT_PROGRAM_SCHEMA)
        _require(settlement.validate_completed_capacity_settlement(source)['valid'])
        receipt=attempt._post_batch_predecessor_report(bound,source['native_result']['stage_report'],issues)
        _require(not issues and receipt['stage']=='capacity_settlement' and receipt['next_action']=='final_qualification')
        _require(receipt['bindings']['terminal_verification']['outcome']=='success')
        return receipt
    except _INVALID as error:
        raise ValueError('final_qualification:source_invalid') from error


def _cleanup_source(identity: Any, source: Any) -> dict:
    try:
        _json(identity)
        _json(source)
        _require(
            len(attempt._canonical(identity)) <= settlement.native.MAX_PROGRAM_BYTES
            and len(attempt._canonical(source))
            <= 4 * settlement.native.MAX_PROGRAM_BYTES
        )
        issues = []
        bound = attempt._validate_identity(identity, issues)
        _require(
            not issues
            and settlement.validate_cleanup_capacity_settlement(source)["valid"]
        )
        receipt = attempt._post_batch_predecessor_report(
            bound, source["native_result"]["stage_report"], issues
        )
        _require(
            not issues
            and receipt["stage"] == "capacity_settlement"
            and receipt["next_action"] == "final_qualification"
            and receipt["bindings"]["capacity_authority_lane_ids"] == []
            and source["capacity_after"]["state"]["active_lane_ids"] == []
        )
        return receipt
    except _INVALID as error:
        raise ValueError("final_qualification:cleanup_source_invalid") from error


def _cleanup_binding(identity: dict, source: dict) -> tuple[dict, dict]:
    prior = _cleanup_source(identity, source)
    core = {
        "schema": CLEANUP_BINDING_SCHEMA,
        "identity": deepcopy(identity),
        "settlement_report_sha256": source["report_sha256"],
        "host_cleanup_sha256": source["host_cleanup"]["report_sha256"],
        "capacity_store_id": source["capacity_after"]["store_id"],
        "capacity_state_sha256": source["capacity_after"]["state_sha256"],
        "authority_after": deepcopy(source["authority_after"]),
    }
    return prior, {**core, "binding_sha256": attempt._sha(core)}


def _validated_cleanup_binding(
    identity: Any, predecessor: Any, cleanup_binding: Any
) -> tuple[dict, dict]:
    try:
        for value in (identity, predecessor, cleanup_binding):
            _json(value)
            _require(
                len(attempt._canonical(value))
                <= settlement.native.MAX_PROGRAM_BYTES
            )
        issues = []
        bound = attempt._validate_identity(identity, issues)
        prior = attempt._validate_receipt(
            predecessor,
            bound,
            issues,
            allowed_stages={"capacity_settlement"},
            allowed_actions={"final_qualification"},
        )
        binding = deepcopy(cleanup_binding)
        core = {key: child for key, child in binding.items() if key != "binding_sha256"}
        _require(
            not issues
            and prior["status"] == "SETTLED"
            and prior["bindings"]["capacity_authority_lane_ids"] == []
            and binding.get("schema") == CLEANUP_BINDING_SCHEMA
            and _same(binding.get("identity"), bound)
            and binding.get("binding_sha256") == attempt._sha(core)
            and settlement.capacity._digest(binding.get("settlement_report_sha256"))
            and settlement.capacity._digest(binding.get("host_cleanup_sha256"))
            and isinstance(binding.get("capacity_store_id"), str)
            and bool(binding["capacity_store_id"])
            and settlement.capacity._digest(binding.get("capacity_state_sha256"))
        )
        settlement.completion_waiting_authority(binding["authority_after"])
        return deepcopy(dict(prior)), binding
    except _INVALID as error:
        raise ValueError("final_qualification:cleanup_binding_invalid") from error


def _lifecycle_closed_report(
    identity: dict, predecessor: dict, cleanup_binding: dict
) -> dict:
    prior, binding = _validated_cleanup_binding(
        identity, predecessor, cleanup_binding
    )
    proof = {
        "schema": LIFECYCLE_SCHEMA,
        "predecessor_receipt": deepcopy(prior),
        "cleanup_binding": binding,
        "owner_disposition": "pending",
    }
    receipt = attempt._receipt(
        stage="final_qualification",
        status="QUALIFIED",
        identity=identity,
        plan={
            "plan_id": prior["plan_id"],
            "revision": prior["plan_revision"],
        },
        plan_sha256=prior["plan_sha256"],
        predecessor=prior,
        next_action="owner_disposition",
        bindings={**deepcopy(prior["bindings"]), "lifecycle_final": proof},
    )
    return attempt._report(
        operation="final_qualification",
        identity=identity,
        status="PASS",
        disposition="FINAL_QUALIFICATION_VERIFIED",
        issues=[],
        stages=[attempt._stage("clean_lifecycle", "PASS", proof, [])],
        receipt=receipt,
    )


def _metadata_transport(source: dict,program: dict,observed: Any) -> dict:
    """Validate complete saved relationships; only the host call observes origin."""
    _json(observed)
    _require(len(attempt._canonical(observed))<=settlement.native.MAX_PROGRAM_BYTES)
    current=observed['current_wave'];context=current['context'];admission=context['admission'];allocated=context['capacity_admission']
    stage=source['native_result']['stage_report'];capture=source['completion_capture']
    _require(observed['status']=='OBSERVED' and observed['issues']==[] and current['status']=='OBSERVED' and current['issues']==[])
    _require(context['status']=='OBSERVED' and context['issues']==[]
        and context['settlement_report_sha256']==source['report_sha256']
        and context['pre_spawn_program_sha256']==attempt._sha(program)
        and _same(context['authority_before'],source['authority_after']) and _same(context['authority_after'],source['authority_after']))
    closure._current_observation(source,context['settlement_observation'])
    for operation,evidence,expected in (
        ('pre_spawn',admission,program),
        ('capacity_admission',allocated,attempt.build_capacity_admission_program(program,admission['stage_report']))):
        intent,result=evidence['intent'],evidence['result']
        _require(_same(intent,settlement.native._event_record('stage_intent',intent['payload']))
            and intent['payload']['operation']==operation and intent['payload']['stage_program_sha256']==attempt._sha(expected)
            and set(intent['payload'])=={'operation','stage_program_sha256','evaluation_time','proposed_action_sha256'}
            and (intent['payload']['proposed_action_sha256'] is None or
                 (operation=='capacity_admission' and settlement.capacity._digest(intent['payload']['proposed_action_sha256'])))
            and _same(result,settlement.native._event_record('stage_result',result['payload']))
            and _same(evidence['stage_report'],result['payload']['stage_report']))
        _require(_same(evidence['journal_tip'],source['authority_after']['tip']) and settlement.capacity._digest(evidence['journal_sha256']))
    _require(admission['journal_sha256']==allocated['journal_sha256'])
    _require(set(admission)=={'intent','result','stage_report','journal_sha256','journal_tip'})
    _require(wave.validate_native_completed_wave(current['wave'],program,admission['stage_report'],allocated['stage_report'],stage,
        capture['source_observation'],checkpoint_sources=capture['checkpoint_sources']))
    admitted=allocated['stage_report']['receipt']['bindings']
    allocated_core={'intent':allocated['intent'],'result':allocated['result'],'stage_report':allocated['stage_report'],
        'inventory_scope':'admitted_current_wave_slots','inventory':current['wave']['wave_program']['observations'][0]['inventory'],
        'slot_ids':current['wave']['allocated_slot_ids'],'logical_lane_ids':['spec','standards'],
        'initial_authority_sha256':admitted['capacity_authority_state_sha256'],
        'pre_release_authority_sha256':source['capacity_before']['state_sha256'],
        'journal_sha256':admission['journal_sha256'],'journal_tip':source['authority_after']['tip']}
    _require(_same(allocated,allocated_core))
    context_core={'schema':'orch-dork/completion-admission-context/v1','status':'OBSERVED','issues':[],
        'scope':'current_host_admission_and_settlement','settlement_report_sha256':source['report_sha256'],
        'pre_spawn_program_sha256':attempt._sha(program),'admission':admission,'capacity_admission':allocated,
        'settlement_observation':context['settlement_observation'],'authority_before':source['authority_after'],
        'authority_after':source['authority_after'],'observed_at':context['observed_at'],
        'terminal_claim_permitted':False,'continuation_permitted':False,'model_calls':0,'native_calls':0,'signing_key_reads':0}
    _require(_same(context,{**context_core,'report_sha256':attempt._sha(context_core)}))
    current_core={'schema':'orch-dork/current-native-completed-wave/v1','status':'OBSERVED','issues':[],
        'context':context,'wave':current['wave'],'observed_at':current['observed_at'],'terminal_claim_permitted':False,
        'continuation_permitted':False,'resource_release_proven':False,'model_calls':0,'native_calls':0,'signing_key_reads':0}
    _require(_same(current,{**current_core,'report_sha256':attempt._sha(current_core)}))
    expected_contracts=metadata.build_native_terminal_contracts(program['identity'],stage,current['wave']['wave_program'])
    _require(_same(observed['terminal_contracts'],expected_contracts))
    trace=observed['run_trace']
    calls=[row for row in trace['trace']['events'] if row['type']=='tool']
    call_times={row['data']['call_id']:row['at'] for row in calls}
    _require(len(call_times)==len(calls))
    started=settlement.observer_receipt.evidence.instant(observed['dogfood']['spine']['derived_at'])
    _require(_same(trace,metadata._trace_for_times(program,source,current,call_times,started)))
    _require(_same(observed['coordinator_capsule'],metadata._capsule(program,source,current)))
    dogfood=observed['dogfood'];spine=dogfood['spine'];root=capture['source_observation']['evidence']['roles']['root']
    _require(dogfood['source_path']==root['path'] and dogfood['analysis_seen'] is True and dogfood['label_mode']=='non_blind')
    _require(spine['schema']==attempt.dogfood_recovery.SPINE_SCHEMA and spine['run_key']==program['identity']['run_id']
        and spine['source']['session_id']==program['identity']['root_task_id'] and spine['source']['session_sha256']==root['file_sha256']
        and spine['spine_sha256']==attempt._sha({'source':spine['source'],'facts':spine['facts']}))
    _require(set(dogfood)=={'spine','verification','source_path','analysis_seen','label_mode'}
        and set(spine)=={'schema','kind','run_key','derived_at','derived_by','host','source','facts','spine_sha256'}
        and spine['kind']=='run_spine' and spine['derived_by']=='native-qualification-host' and spine['host'] is None
        and set(spine['source'])=={'session_sha256','session_id','line_count'}
        and type(spine['source']['line_count']) is int and spine['source']['line_count']>0)
    _require(_same(dogfood['verification'],{'schema':attempt.dogfood_recovery.SPINE_SCHEMA,'verified':True,'mismatches':[],
        'session_sha256':root['file_sha256'],'spine_sha256':spine['spine_sha256']}))
    now=settlement.observer_receipt.evidence.instant(observed['observed_at'])
    started=settlement.observer_receipt.evidence.instant(spine['derived_at'])
    _require(now>=started>=settlement.observer_receipt.evidence.instant(current['observed_at'])
        >=settlement.observer_receipt.evidence.instant(context['observed_at'])
        >=settlement.observer_receipt.evidence.instant(allocated['intent']['payload']['evaluation_time'])
        >=settlement.observer_receipt.evidence.instant(admission['intent']['payload']['evaluation_time']))
    for release in source['release_receipts']:
        signed=release['cleanup_observer_receipt']
        _require(settlement.observer_receipt.evidence.instant(signed['issued_at'])<=now<=settlement.observer_receipt.evidence.instant(signed['valid_until']))
    core={'schema':'orch-dork/native-final-metadata/v1','status':'OBSERVED','issues':[],'current_wave':current,
        'terminal_contracts':expected_contracts,'run_trace':trace,'coordinator_capsule':observed['coordinator_capsule'],'dogfood':dogfood,
        'observed_at':observed['observed_at'],'terminal_claim_permitted':False,'resource_release_proven':False,
        'continuation_permitted':False,'model_calls':0,'native_calls':0,'cost_usd':None}
    _require(_same(observed,{**core,'report_sha256':attempt._sha(core)}),'metadata_invalid')
    return expected_contracts


def _final_qualification_program(
    identity: Any, settlement_report: Any, pre_spawn_program: Any
) -> dict:
    if (
        isinstance(settlement_report, dict)
        and settlement_report.get("schema")
        == settlement.CLEANUP_SETTLEMENT_SCHEMA
    ):
        prior, cleanup_binding = _cleanup_binding(identity, settlement_report)
        return {
            "schema": attempt.PROGRAM_SCHEMA,
            "operation": "final_qualification",
            "identity": identity,
            "predecessor_receipt": prior,
            "payload": {"cleanup_binding": cleanup_binding},
        }
    prior=_source(identity,settlement_report,pre_spawn_program)
    return {'schema':attempt.PROGRAM_SCHEMA,'operation':'final_qualification','identity':identity,
        'predecessor_receipt':prior,'payload':{'settlement_report':settlement_report,'pre_spawn_program':pre_spawn_program}}


def build_final_qualification_program(identity: Any,settlement_report: Any,pre_spawn_program: Any) -> dict:
    return deepcopy(_final_qualification_program(identity, settlement_report, pre_spawn_program))


def _checked_evidence(identity: dict,source: dict,program: dict,observed: dict):
    """Validate complete final evidence, retaining a known budget failure."""
    prior=_source(identity,source,program)
    contracts=_metadata_transport(source,program,observed)
    capture=source['completion_capture']
    now=settlement.observer_receipt.evidence.instant(observed['observed_at'])
    decision=budget.build_completion_budget_decision(identity,source['native_result']['stage_report'],program,
        capture['checkpoint_sources'],capture['source_observation'],now=now)
    return prior,contracts,decision


def _closed_report(identity: dict,source: dict,program: dict,observed: dict) -> dict:
    prior,contracts,decision=_checked_evidence(identity,source,program,observed)
    _require(decision['status']=='PASS','budget_exhausted')
    capture=source['completion_capture'];current=observed['current_wave']
    reports=[current['wave']['wave_report'],
        {'contracts_sha256':attempt._sha(contracts['contracts']),
         'verification_digests':contracts['worker_evidence']['verification_digests'],
         'ledger_digests':contracts['worker_evidence']['ledger_digests']},
        {'source_observation_sha256':capture['source_observation']['report_sha256'],'budget_decision':decision,
         'terminal_verification_sha256':prior['bindings']['terminal_verification']['verification_sha256'],
         'current_host_wave_sha256':current['report_sha256']},
        observed['run_trace']['report'],observed['coordinator_capsule']['report'],observed['dogfood']['verification'],
        current['context']['settlement_observation']]
    stages=[attempt._stage(name,'PASS',value,[]) for name,value in zip(CHECKS,reports)]
    proof={'schema':SCHEMA,'settlement_report':source,'pre_spawn_program':program,'metadata':observed,
        'checks':reports,'checks_sha256':attempt._sha(stages),'decision_time':observed['observed_at'],'owner_disposition':'pending'}
    receipt=attempt._receipt(stage='final_qualification',status='QUALIFIED',identity=identity,
        plan={'plan_id':prior['plan_id'],'revision':prior['plan_revision']},plan_sha256=prior['plan_sha256'],
        predecessor=prior,next_action='owner_disposition',bindings={**deepcopy(prior['bindings']),'final_qualification':proof})
    return deepcopy(attempt._report(operation='final_qualification',identity=identity,status='PASS',
        disposition='FINAL_QUALIFICATION_VERIFIED',issues=[],stages=stages,receipt=receipt))


def _cleanup_observer(cleanup_binding: dict, predecessor: dict) -> None:
    return None


def _evaluation_context(identity: Any, predecessor: Any, payload: Any, observer: Any) -> tuple[Any, Any, Any]:
    if type(payload) is dict and set(payload) == {"cleanup_binding"}:
        return payload["cleanup_binding"], predecessor, _cleanup_observer
    _require(type(payload) is dict and set(payload)=={'settlement_report','pre_spawn_program'},'payload_invalid')
    source,program=payload['settlement_report'],payload['pre_spawn_program']
    _require(_same(predecessor,_source(identity,source,program)),'predecessor_invalid')
    _require(callable(observer),'host_observer_required')
    return source, program, observer


def _evaluated_report(identity: Any, payload: Any, source: Any, program: Any, observed: Any) -> dict:
    if type(payload) is dict and set(payload) == {"cleanup_binding"}:
        return _lifecycle_closed_report(identity, program, source)
    return _closed_report(identity,source,program,observed)


def evaluate_final_qualification(identity: Any,predecessor: Any,payload: Any,*,observer=None) -> dict:
    try:
        source,program,active_observer=_evaluation_context(identity,predecessor,payload,observer)
        observed=active_observer(deepcopy(source),deepcopy(program))
        return _evaluated_report(identity,payload,source,program,observed)
    except Exception as error:
        issue=str(error) if type(error) is ValueError and str(error).startswith('final_qualification:') else 'final_qualification:'+type(error).__name__
        return attempt._report(operation='final_qualification',identity=identity,status='BLOCKED',disposition='FINAL_QUALIFICATION_REFUSED',
            issues=[issue],stages=[])


def _expected_final_report(report: dict) -> dict:
    _require(type(report) is dict and type(report.get('receipt')) is dict and type(report['receipt'].get('bindings')) is dict);lifecycle=report['receipt']['bindings'].get('lifecycle_final')
    if isinstance(lifecycle, dict):
        return _lifecycle_closed_report(
            lifecycle['cleanup_binding']['identity'],
            lifecycle['predecessor_receipt'],
            lifecycle['cleanup_binding'],
        )
    proof=report['receipt']['bindings']['final_qualification'];program=proof['pre_spawn_program']
    return _closed_report(program['identity'],proof['settlement_report'],program,proof['metadata'])


def validate_final_qualification_report(report: Any) -> dict:
    try:
        _json(report);_require(len(attempt._canonical(report))<=4*settlement.native.MAX_EVENT_BYTES)
        _require(_same(report, _expected_final_report(report)))
    except _INVALID:
        return {'valid':False,'issues':['final_qualification:report_invalid'],'scope':'canonical_transport'}
    return {'valid':True,'issues':[],'scope':'canonical_transport'}


def _validate_final_qualification_action(root_task_id: str, receipt: Any) -> None:
    _require(type(receipt) is dict and type(receipt.get('bindings')) is dict);lifecycle=receipt['bindings'].get('lifecycle_final')
    if isinstance(lifecycle, dict):
        expected = _lifecycle_closed_report(
            lifecycle['cleanup_binding']['identity'],
            lifecycle['predecessor_receipt'],
            lifecycle['cleanup_binding'],
        )
        identity = lifecycle['cleanup_binding']['identity']
    else:
        proof=receipt['bindings']['final_qualification'];program=proof['pre_spawn_program']
        expected=_closed_report(program['identity'],proof['settlement_report'],program,proof['metadata'])
        identity = program['identity']
    _require(root_task_id==identity['root_task_id'] and _same(receipt,expected['receipt']))


def final_qualification_next_action(root_task_id: str,receipt: Any) -> str:
    try:
        _validate_final_qualification_action(root_task_id, receipt)
        return 'owner_disposition'
    except _INVALID as error:
        raise ValueError('final_qualification:receipt_invalid') from error


def _commit_time(controller, validated_report: dict):
    """Final host guard after validation, before the native journal intent.

    This private seam consumes only the controller's freshly prepared, fully
    validated report. It obtains current authority again and charges validation
    delay against the already validated frozen limit. The returned time is
    retained in the native intent; the proof retains its earlier observation
    time. Neither timestamp can be supplied by the stage input.
    """
    lifecycle = validated_report['receipt']['bindings'].get('lifecycle_final')
    if isinstance(lifecycle, dict):
        binding = lifecycle['cleanup_binding']
        _require(
            validate_final_qualification_report(validated_report)['valid'],
            'cleanup_report_invalid',
        )
        authority = controller.grants.canonical_authority()
        _require(
            _same(authority, binding['authority_after']), 'cleanup_owner_changed'
        )
        current_capacity = settlement._read_capacity(controller)
        _require(
            current_capacity['store_id'] == binding['capacity_store_id']
            and current_capacity['state_sha256']
            == binding['capacity_state_sha256']
            and current_capacity['state']['active_lane_ids'] == [],
            'cleanup_capacity_changed',
        )
        return controller._evaluation_time()
    proof=validated_report['receipt']['bindings']['final_qualification']
    source=proof['settlement_report']
    observed=settlement.observe_current_completion_settlement(controller,source)
    closure._current_observation(source,observed)
    now=controller._evaluation_time()
    _require(now>=settlement.observer_receipt.evidence.instant(proof['decision_time']),'commit_clock_regressed')
    decision=proof['checks'][2]['budget_decision']
    start=settlement.observer_receipt.evidence.instant(decision['observation']['wall_interval']['start']['timestamp'])
    delta=now-start
    wall_ms=delta.days*86_400_000+delta.seconds*1000+(delta.microseconds+999)//1000
    _require(0<=wall_ms<=decision['limits']['wall_time_ms'],'commit_budget_exhausted')
    for release in source['release_receipts']:
        signed=release['cleanup_observer_receipt']
        _require(settlement.observer_receipt.evidence.instant(signed['issued_at'])<=now
            <=settlement.observer_receipt.evidence.instant(signed['valid_until']),'commit_signature_expired')
    return now


__all__=['build_final_qualification_program','evaluate_final_qualification','validate_final_qualification_report',
         'final_qualification_next_action','CHECKS']
