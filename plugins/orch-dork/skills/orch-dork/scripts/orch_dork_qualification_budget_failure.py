"""Verified failure closure for a completed attempt over its frozen budget.

All non-budget final evidence must validate through the same owning helpers as
success. Only known measured exhaustion is a failure proof; missing, stale or
malformed evidence stays refused. A fresh host observer is mandatory.
"""
from __future__ import annotations
from copy import deepcopy
from typing import Any

import orch_dork_governed_attempt as attempt
import orch_dork_qualification_final as final
import orch_dork_qualification_closure as failure

SCHEMA='orch-dork/completion-budget-failure-closure/v1'
PROFILE='completion_budget_exhausted'


def _require(condition,issue='binding_invalid'):
    if not condition:raise ValueError('budget_failure:'+issue)


def build_budget_failure_program(identity: Any,source: Any,pre_spawn_program: Any)->dict:
    prior=final._source(identity,source,pre_spawn_program)
    return deepcopy({'schema':attempt.PROGRAM_SCHEMA,'operation':'failure_closure','identity':identity,
        'predecessor_receipt':prior,'payload':{'failure_profile':PROFILE,'settlement_report':source,'pre_spawn_program':pre_spawn_program}})


def _closed_report(identity,source,program,observed):
    prior,_contracts,decision=final._checked_evidence(identity,source,program,observed)
    _require(decision['status']=='BUDGET_EXHAUSTED','known_exhaustion_required')
    current=observed['current_wave']['context']['settlement_observation']
    reports=failure._checks(identity,source,current)
    reports[0].update(failure_reason=PROFILE,budget_decision=decision,metadata_sha256=observed['report_sha256'])
    stages=[attempt._stage(name,'PASS',body,[]) for name,body in zip(failure.CHECKS,reports)]
    proof={'schema':SCHEMA,'outcome':'failure','failure_reason':PROFILE,
        'settlement_report_sha256':source['report_sha256'],'current_observation_sha256':current['report_sha256'],
        'checks_sha256':attempt._sha(stages),'checks':reports,'owner_disposition':'pending',
        'pre_spawn_program':program,'metadata':observed}
    receipt=attempt._receipt(stage='failure_closure',status='VERIFIED_FAILURE',identity=identity,
        plan={'plan_id':prior['plan_id'],'revision':prior['plan_revision']},plan_sha256=prior['plan_sha256'],
        predecessor=prior,next_action='owner_disposition',bindings={**deepcopy(prior['bindings']),'failure_closure':proof})
    return deepcopy(attempt._report(operation='failure_closure',identity=identity,status='PASS',disposition='VERIFIED_FAILURE_CLOSED',
        issues=[],stages=stages,receipt=receipt))


def evaluate_budget_failure(identity,predecessor,payload,*,observer=None):
    try:
        _require(type(payload) is dict and set(payload)=={'failure_profile','settlement_report','pre_spawn_program'}
            and payload['failure_profile']==PROFILE,'payload_invalid')
        source,program=payload['settlement_report'],payload['pre_spawn_program']
        _require(final._same(predecessor,final._source(identity,source,program)),'predecessor_invalid')
        _require(callable(observer),'host_observer_required')
        return _closed_report(identity,source,program,observer(deepcopy(source),deepcopy(program)))
    except Exception as error:
        issue=str(error) if type(error) is ValueError and str(error).startswith('budget_failure:') else 'budget_failure:'+type(error).__name__
        return attempt._report(operation='failure_closure',identity=identity,status='BLOCKED',disposition='FAILURE_CLOSURE_REFUSED',
            issues=[issue],stages=[])


__all__=['build_budget_failure_program','evaluate_budget_failure','SCHEMA','PROFILE']
