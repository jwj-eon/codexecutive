"""Reconstruct production prefixes and reconcile their finite-model paths.

This reader checks whole public reports and raw host responses, then closes the
path-derivation obligation against the unchanged finite model. It does not
authenticate captured execution or claim a complete production graph,
resource closure, other observation classes, or both readiness orders in
production.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
import re
import weakref

from lifecycle_conformance import explorer, host_adapter, values
from lifecycle_conformance import reference_model as model, reference_values as rv
import orch_dork_governed_native_controller as native_contract
import orch_dork_native_result as native_result
import orch_dork_native_attempt_observer as attempt_observer
import orch_dork_owned_file as owned_file
import orch_dork_coordinator_usage as coordinator_usage
import orch_dork_project_ground_enforcement as ground_contract
import orch_dork_qualification_successor as successor
import orch_dork_native_worker_finals as worker_finals
import orch_dork_qualification_review as qualification_review
import orch_dork_qualification_results as qualification_results
import orch_dork_run_engine as run_engine
import orch_dork_run_store as run_store
import orch_dork_completion_process as completion_process
import orch_dork_completion_settlement as completion_settlement
import orch_dork_qualification_final as final_qualification
import orch_dork_qualification_closure as failure_closure
import orch_dork_qualification_owner as owner_disposition
import orch_dork_qualification_owner_rotation as owner_rotation


OBSERVATIONS_SCHEMA = (
    'orch-dork/production-graph-mapping-inputs/v11'
)
PREFIX_EVIDENCE_SCHEMA = (
    'orch-dork/source-bound-production-graph-reconstruction/v11'
)
EVIDENCE_SCHEMA = (
    'orch-dork/source-bound-production-graph-reconstruction/v12'
)
RECONCILIATION_SCHEMA = (
    'orch-dork/production-model-path-reconciliation/v1'
)
_PRODUCTION_PATH_PARENTS = rv.freeze({
    'first_spawn': None,
    'completed_second_spawn': 'first_spawn',
    'partial_spec_acknowledgement': 'completed_second_spawn',
    'successful_standards_acknowledgement':
        'partial_spec_acknowledgement',
    'completed_spec_continuation':
        'successful_standards_acknowledgement',
    'completed_standards_continuation':
        'completed_spec_continuation',
    'spec_first_checkpoint_spec': 'completed_standards_continuation',
    'spec_first_checkpoint_standards': 'spec_first_checkpoint_spec',
    'spec_first_progress_admission':
        'spec_first_checkpoint_standards',
    'spec_first_final_continue_spec': 'spec_first_progress_admission',
    'spec_first_final_continue_standards':
        'spec_first_final_continue_spec',
    'spec_first_spec_result': 'spec_first_final_continue_standards',
    'spec_first_standards_result': 'spec_first_spec_result',
    'spec_first_result_aggregation': 'spec_first_standards_result',
    'spec_first_semantic_review_accepted':
        'spec_first_result_aggregation',
    'spec_first_semantic_review_rejected':
        'spec_first_result_aggregation',
    'spec_first_semantic_review_evidence_required':
        'spec_first_result_aggregation',
    'standards_first_checkpoint_standards':
        'completed_standards_continuation',
    'standards_first_checkpoint_spec':
        'standards_first_checkpoint_standards',
    'standards_first_progress_admission':
        'standards_first_checkpoint_spec',
    'standards_first_final_continue_spec':
        'standards_first_progress_admission',
    'standards_first_final_continue_standards':
        'standards_first_final_continue_spec',
    'standards_first_spec_result':
        'standards_first_final_continue_standards',
    'standards_first_standards_result': 'standards_first_spec_result',
    'standards_first_result_aggregation':
        'standards_first_standards_result',
    'standards_first_semantic_review_accepted':
        'standards_first_result_aggregation',
    'standards_first_semantic_review_rejected':
        'standards_first_result_aggregation',
    'standards_first_semantic_review_evidence_required':
        'standards_first_result_aggregation',
    'spec_first_terminal_cleanup_accepted_complete':
        'spec_first_semantic_review_accepted',
    'spec_first_terminal_cleanup_rejected_complete':
        'spec_first_semantic_review_rejected',
    'standards_first_terminal_cleanup_accepted_complete':
        'standards_first_semantic_review_accepted',
    'standards_first_terminal_cleanup_rejected_complete':
        'standards_first_semantic_review_rejected',
    'terminal_cleanup_known_failure':
        'spec_first_semantic_review_accepted',
    'terminal_cleanup_unknown': 'spec_first_semantic_review_accepted',
    'terminal_settlement_accepted':
        'spec_first_terminal_cleanup_accepted_complete',
    'terminal_settlement_rejected':
        'standards_first_terminal_cleanup_rejected_complete',
    'failed_second_spawn': 'first_spawn',
    'completed_compensation_close': 'failed_second_spawn',
})
_PRODUCTION_PATH_ORDER = rv.freeze([
    'first_spawn', 'completed_second_spawn',
    'partial_spec_acknowledgement',
    'successful_standards_acknowledgement',
    'completed_spec_continuation',
    'completed_standards_continuation',
    'spec_first_checkpoint_spec',
    'spec_first_checkpoint_standards',
    'spec_first_progress_admission',
    'spec_first_final_continue_spec',
    'spec_first_final_continue_standards',
    'spec_first_spec_result',
    'spec_first_standards_result',
    'spec_first_result_aggregation',
    'spec_first_semantic_review_accepted',
    'spec_first_semantic_review_rejected',
    'spec_first_semantic_review_evidence_required',
    'standards_first_checkpoint_standards',
    'standards_first_checkpoint_spec',
    'standards_first_progress_admission',
    'standards_first_final_continue_spec',
    'standards_first_final_continue_standards',
    'standards_first_spec_result',
    'standards_first_standards_result',
    'standards_first_result_aggregation',
    'standards_first_semantic_review_accepted',
    'standards_first_semantic_review_rejected',
    'standards_first_semantic_review_evidence_required',
    'spec_first_terminal_cleanup_accepted_complete',
    'spec_first_terminal_cleanup_rejected_complete',
    'standards_first_terminal_cleanup_accepted_complete',
    'standards_first_terminal_cleanup_rejected_complete',
    'terminal_cleanup_known_failure',
    'terminal_cleanup_unknown',
    'terminal_settlement_accepted',
    'terminal_settlement_rejected',
    'failed_second_spawn', 'completed_compensation_close',
])
_PRODUCTION_INPUT_ALIASES = rv.freeze([{
    'mapping_name': 'first_spawn',
    'inputs': [
        'failure_branch.first_spawn',
        'success_branch.first_spawn',
    ],
}, {
    'mapping_name': 'terminal_cleanup_known_failure',
    'inputs': [
        'terminal_cleanup.known_failures.failed',
        'terminal_cleanup.known_failures.cancelled',
        'terminal_cleanup.known_failures.timed_out',
    ],
}])
_PRODUCTION_DECLARED_SEGMENT_REPLAYS = rv.freeze([{
    'owner_mapping':
        'spec_first_terminal_cleanup_accepted_complete',
    'replay_mapping': 'terminal_cleanup_known_failure',
    'parent_mapping': 'spec_first_semantic_review_accepted',
    'segment_offset': 0,
    'transition_count': 2,
}, {
    'owner_mapping':
        'spec_first_terminal_cleanup_accepted_complete',
    'replay_mapping': 'terminal_cleanup_unknown',
    'parent_mapping': 'spec_first_semantic_review_accepted',
    'segment_offset': 0,
    'transition_count': 2,
}])
# Mirrored from the source-bound project-ground hook. Keeping this reader free
# of a namespace-package import makes the projected runtime SBOM closed; a hook
# contract change still invalidates both these comparisons and SOURCE_PATHS.
HOOK_DURABLE_EVENT_SCHEMA = 'orch-dork/project-ground-durable-event/v1'
HOOK_DURABLE_EVENT_FIELDS = {
    'schema', 'report_schema', 'report_sha256', 'hook_event_name',
    'decision', 'status', 'coverage_class', 'mutating',
    'tool_input_sha256', 'state_sha256', 'completion_invalidated',
    'reason_codes', 'identity', 'native_controller',
    'durable_record_sha256',
}
SOURCE_PATHS = (
    'hooks/project_ground_hook.py',
    'skills/orch-dork/scripts/lifecycle_conformance/explorer.py',
    'skills/orch-dork/scripts/lifecycle_conformance/host_adapter.py',
    'skills/orch-dork/scripts/lifecycle_conformance/model.py',
    'skills/orch-dork/scripts/lifecycle_conformance/production_graph_evidence.py',
    'skills/orch-dork/scripts/lifecycle_conformance/protocol.py',
    'skills/orch-dork/scripts/lifecycle_conformance/reference_model.py',
    'skills/orch-dork/scripts/lifecycle_conformance/reference_values.py',
    'skills/orch-dork/scripts/lifecycle_conformance/registries.py',
    'skills/orch-dork/scripts/lifecycle_conformance/values.py',
    'skills/orch-dork/scripts/orch_dork_governed_native_controller.py',
    'skills/orch-dork/scripts/orch_dork_governed_attempt.py',
    'skills/orch-dork/scripts/orch_dork_adaptive_contracts.py',
    'skills/orch-dork/scripts/orch_dork_codex_usage.py',
    'skills/orch-dork/scripts/orch_dork_coordinator_usage.py',
    'skills/orch-dork/scripts/orch_dork_completion_process.py',
    'skills/orch-dork/scripts/orch_dork_completion_settlement.py',
    'skills/orch-dork/scripts/orch_dork_local_task_runtime.py',
    'skills/orch-dork/scripts/orch_dork_native_attempt_observer.py',
    'skills/orch-dork/scripts/orch_dork_native_result.py',
    'skills/orch-dork/scripts/orch_dork_native_worker_finals.py',
    'skills/orch-dork/scripts/orch_dork_owned_file.py',
    'skills/orch-dork/scripts/orch_dork_project_ground_enforcement.py',
    'skills/orch-dork/scripts/orch_dork_qualification_progress.py',
    'skills/orch-dork/scripts/orch_dork_qualification_final.py',
    'skills/orch-dork/scripts/orch_dork_qualification_closure.py',
    'skills/orch-dork/scripts/orch_dork_qualification_owner.py',
    'skills/orch-dork/scripts/orch_dork_qualification_owner_rotation.py',
    'skills/orch-dork/scripts/orch_dork_qualification_review.py',
    'skills/orch-dork/scripts/orch_dork_qualification_results.py',
    'skills/orch-dork/scripts/orch_dork_qualification_successor.py',
    'skills/orch-dork/scripts/orch_dork_route_policy.py',
    'skills/orch-dork/scripts/orch_dork_routing_verify.py',
    'skills/orch-dork/scripts/orch_dork_run_engine.py',
    'skills/orch-dork/scripts/orch_dork_run_store.py',
)


def _require(condition, reason):
    if not condition:
        raise values.LifecycleContractError('public_native_comparison:' + reason)


def _same(left, right):
    return rv.freeze(left) == rv.freeze(right)


def _strict_json_record(raw):
    """Decode one JSON record while refusing duplicate or nonfinite values."""

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate json key')
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError('nonfinite json number')

    return json.loads(
        raw, object_pairs_hook=unique, parse_constant=reject_constant)


def _exact_pre_work_records(records):
    """Recognize the complete four-row receipt-only rollout grammar."""

    if type(records) is not list or len(records) != 4:
        return False
    session, context, message, tokens = records
    if not all(type(record) is dict
               and set(record) == {'type', 'payload'}
               and type(record['payload']) is dict
               for record in records):
        return False
    session_payload = session['payload']
    context_payload = context['payload']
    message_payload = message['payload']
    token_payload = tokens['payload']
    collaboration = context_payload.get('collaboration_mode')
    settings = (collaboration.get('settings')
                if type(collaboration) is dict else None)
    info = token_payload.get('info')
    last_usage = (info.get('last_token_usage')
                  if type(info) is dict else None)
    total_usage = (info.get('total_token_usage')
                   if type(info) is dict else None)
    usage_fields = {
        'input_tokens', 'cached_input_tokens', 'cache_write_input_tokens',
        'output_tokens', 'reasoning_output_tokens', 'total_tokens',
    }
    return (
        session['type'] == 'session_meta'
        and set(session_payload) == {'id'}
        and type(session_payload['id']) is str
        and bool(session_payload['id'])
        and context['type'] == 'turn_context'
        and set(context_payload) == {'model', 'collaboration_mode'}
        and type(context_payload['model']) is str
        and bool(context_payload['model'])
        and type(collaboration) is dict
        and set(collaboration) == {'settings'}
        and type(settings) is dict
        and set(settings) == {'reasoning_effort'}
        and type(settings['reasoning_effort']) is str
        and bool(settings['reasoning_effort'])
        and message['type'] == 'event_msg'
        and set(message_payload) == {'type', 'message'}
        and message_payload['type'] == 'agent_message'
        and type(message_payload['message']) is str
        and bool(message_payload['message'].strip())
        and tokens['type'] == 'event_msg'
        and set(token_payload) == {'type', 'info'}
        and token_payload['type'] == 'token_count'
        and type(info) is dict
        and set(info) == {'last_token_usage', 'total_token_usage'}
        and type(last_usage) is dict
        and type(total_usage) is dict
        and set(last_usage) == usage_fields
        and set(total_usage) == usage_fields
        and all(type(value) is int and value >= 0
                for usage in (last_usage, total_usage)
                for value in usage.values())
        and _same(last_usage, total_usage)
    )


def _validated_action_step(step, expected_action, previous_report, *,
                           action_kind, lane_ids, outcome, label):
    """Validate one complete public action/hook/durable-observation boundary."""
    _require(type(step) is dict and set(step) == {
        'action', 'raw_response', 'pre_hook_report', 'post_hook_report',
        'advance_report',
    }, label + '_input_shape')
    action = step['action']
    raw = step['raw_response']
    pre = step['pre_hook_report']
    post = step['post_hook_report']
    advance = step['advance_report']
    _require(_same(action, expected_action), label + '_action_join')
    if 'spawn_compensation_evidence' in advance:
        validation = (
            successor.validate_issue94_successor_action_advance_evidence(
                advance))
        _require(validation.get('valid') is True
                 and validation.get('scope') == 'archival_evidence_only'
                 and validation.get('action_authorized') is False,
                 label + '_advance_evidence')
    else:
        _require(successor.validate_issue94_successor_action_advance_report(
            advance).get('valid') is True, label + '_advance_report')
    _require(len(advance['controller_transitions']) == 1,
             label + '_transition_count')
    transition = advance['controller_transitions'][0]
    program, after = transition['program'], transition['report']
    _require(native_contract.validate_governed_native_controller_report(
        after).get('valid') is True, label + '_controller_report')
    before_cursor, after_cursor = previous_report['cursor'], after['cursor']
    _require(program['operation'] == 'observe'
             and _same(program['expected_cursor'], before_cursor)
             and program['controller_id'] == action['controller_id'],
             label + '_cursor_join')
    _require(after_cursor['run_id'] == before_cursor['run_id']
             and after_cursor['seq'] == before_cursor['seq'] + 2
             and after_cursor['event_hash'] != before_cursor['event_hash'],
             label + '_successor_cursor')
    observation = program['payload']
    _require(set(observation) == {
        'schema', 'action_id', 'tool_name', 'tool_input_sha256',
        'tool_use_id', 'outcome', 'hook_report_sha256', 'native_receipt',
    } and observation['schema'] == native_contract.ACTION_OBSERVATION_SCHEMA,
             label + '_observation_grammar')
    call_id = observation['tool_use_id']
    _require(type(call_id) is str
             and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}',
                              call_id) is not None,
             label + '_call_identity')
    for hook, event_name, grant_state, decision, fields in (
        (pre, 'PreToolUse', 'DISPATCHED', 'ALLOW',
         native_contract.DURABLE_PRETOOL_NATIVE_FIELDS),
        (post, 'PostToolUse', 'POST_OBSERVED', 'OBSERVED',
         native_contract.DURABLE_POSTTOOL_NATIVE_FIELDS),
    ):
        _require(type(hook) is dict and hook['hook_event_name'] == event_name
                 and hook['schema'] == ground_contract.REPORT_SCHEMA
                 and hook['status'] == 'PASS' and hook['decision'] == decision,
                 label + '_hook_report')
        core = {key: value for key, value in hook.items()
                if key != 'report_sha256'}
        _require(hashlib.sha256(host_adapter.canonical_bytes(core)).hexdigest()
                 == hook['report_sha256'], label + '_hook_seal')
        native = hook['native_controller']
        _require(type(native) is dict and set(native) == fields
                 and native['matched'] is True and native['present'] is True
                 and native['status'] == 'ACTIVE'
                 and type(native['controller_seq']) is int
                 and native['controller_seq'] == before_cursor['seq']
                 and native['controller_id'] == action['controller_id']
                 and native['action_id'] == action['action_id']
                 and native['tool_use_id'] == call_id
                 and native['grant_state'] == grant_state
                 and hook['tool_input_sha256'] == action['tool_input_sha256'],
                 label + '_hook_call_join')
        identity = hook['identity']
        _require(set(identity) == native_contract.DURABLE_HOOK_IDENTITY_FIELDS
                 and type(identity['turn_id']) is str
                 and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}',
                                  identity['turn_id']) is not None
                 and identity['session_id'] == action['actor_thread_id']
                 and identity['current_thread_id'] == action['actor_thread_id'],
                 label + '_hook_actor_join')
    _require(pre['mutating'] is True
             and _same(pre['identity'], post['identity'])
             and post['native_controller']['pretool_report_sha256']
             == pre['report_sha256']
             and observation['hook_report_sha256'] == post['report_sha256'],
             label + '_hook_chain')
    durable = advance['durable_hook_report']
    _require(set(durable) == HOOK_DURABLE_EVENT_FIELDS
             and durable['schema'] == HOOK_DURABLE_EVENT_SCHEMA
             and durable['report_schema'] == post['schema']
             and all(_same(durable[key], post[key])
                     for key in HOOK_DURABLE_EVENT_FIELDS
                     - {'schema', 'report_schema', 'durable_record_sha256'})
             and durable['durable_record_sha256'] == values.canonical_digest(
                 {key: value for key, value in durable.items()
                  if key != 'durable_record_sha256'}),
             label + '_durable_join')
    authority = advance['authority_before']
    _require(_same(authority['tip'], before_cursor)
             and authority['lifecycle']['action_sha256']
             == action['action_sha256']
             and authority['lifecycle']['tool_use_id'] == call_id
             and authority['lifecycle']['expected_binding_status'] == 'ACTIVE'
             and authority['lifecycle']['grant_state'] == 'POST_OBSERVED'
             and all(authority['lifecycle'][key] is False for key in
                     ('terminal', 'cleanup_required', 'pending_intent')),
             label + '_authority_join')
    authority_identity = authority['identity']
    root_route = previous_report['stage_report']['routing']['root']
    _require(set(authority_identity) == {
        'controller_id', 'controller_run_id', 'root_thread_id',
        'root_session_id', 'root_model', 'hook_definition_sha256',
        'hook_registration_sha256', 'activation_sha256',
    } and set(root_route) == {'model', 'effort'}
        and type(root_route['effort']) is str and bool(root_route['effort']),
             label + '_authority_identity_shape')
    _require(all(authority[part]['controller_run_id'] == before_cursor['run_id']
                 and authority[part]['controller_id'] == action['controller_id']
                 for part in ('owner', 'identity', 'hook_projection'))
             and authority['hook_projection']['controller_seq']
             == before_cursor['seq']
             and authority['hook_projection']['controller_event_hash']
             == before_cursor['event_hash']
             and authority_identity['root_thread_id']
             == action['actor_thread_id']
             and authority_identity['root_session_id']
             == action['actor_thread_id']
             and authority_identity['root_model'] == root_route['model'],
             label + '_authority_identity')
    normalized = native_result.normalize_native_result(
        raw, action_kind=action_kind, expected_lane_ids=lane_ids,
        outcome=post['native_controller']['outcome'])
    _require(post['native_controller']['outcome'] == outcome
             and hashlib.sha256(host_adapter.canonical_bytes(raw)).hexdigest()
             == post['native_controller']['result_sha256']
             and (
                 outcome == 'completed'
                 and normalized is not None
                 and _same(normalized,
                           post['native_controller']['result_binding'])
                 or outcome != 'completed'
                 and normalized is None
                 and post['native_controller']['result_binding'] is None
             ), label + '_raw_result')
    _require(observation['action_id'] == action['action_id']
             and observation['tool_name'] == action['tool_name']
             and observation['tool_input_sha256'] == action['tool_input_sha256']
             and observation['outcome'] == outcome,
             label + '_observation_join')
    receipt = observation['native_receipt']
    _require(set(receipt) == {
        'schema', 'action_id', 'outcome', 'tool_name', 'tool_input_sha256',
        'tool_use_id', 'result_sha256', 'result_binding', 'source_pointer',
    } and receipt['schema'] == native_contract.NATIVE_ACTION_RECEIPT_SCHEMA
        and receipt['source_pointer']
        == 'project-ground-durable-event#' + durable['durable_record_sha256']
        and all(receipt[key] == observation[key] for key in
                ('action_id', 'tool_name', 'tool_input_sha256',
                 'tool_use_id', 'outcome'))
        and receipt['result_sha256']
        == post['native_controller']['result_sha256']
        and _same(receipt['result_binding'], normalized),
             label + '_receipt_join')
    return {
        'action': action,
        'raw': raw,
        'pre': pre,
        'post': post,
        'advance': advance,
        'program': program,
        'controller': after,
        'before_cursor': before_cursor,
        'after_cursor': after_cursor,
        'observation': observation,
        'call_id': call_id,
        'durable': durable,
        'authority': authority,
        'normalized': normalized,
        'receipt': receipt,
    }


def _validated_terminal_hook_step(
        step, expected_action, previous_report, evidence, *, lane, outcome,
        label):
    """Bind one cleanup result to both hook reports and retained evidence."""

    _require(type(step) is dict and set(step) == {
                 'lane', 'expected_outcome', 'action', 'raw_response',
                 'pre_hook_report', 'post_hook_report', 'advance_report',
                 'error_type', 'error_message', 'transport_calls',
                 'fake_calls',
             }, label + '_input_shape')
    action = step['action']
    raw = step['raw_response']
    pre = step['pre_hook_report']
    post = step['post_hook_report']
    before_cursor = previous_report['cursor']
    _require(_same(action, expected_action)
             and action['kind'] == 'stop'
             and action['tool_name'] == 'multi_agent_v1__close_agent'
             and action['lane_ids'] == [lane]
             and type(action['tool_input']['target']) is str
             and bool(action['tool_input']['target']),
             label + '_action_join')
    for hook, event_name, grant_state, decision, fields in (
        (pre, 'PreToolUse', 'DISPATCHED', 'ALLOW',
         native_contract.DURABLE_PRETOOL_NATIVE_FIELDS),
        (post, 'PostToolUse', 'POST_OBSERVED', 'OBSERVED',
         native_contract.DURABLE_POSTTOOL_NATIVE_FIELDS),
    ):
        _require(type(hook) is dict
                 and hook['hook_event_name'] == event_name
                 and hook['schema'] == ground_contract.REPORT_SCHEMA
                 and hook['status'] == 'PASS'
                 and hook['decision'] == decision,
                 label + '_hook_report')
        core = {
            key: value for key, value in hook.items()
            if key != 'report_sha256'
        }
        _require(hashlib.sha256(
                     host_adapter.canonical_bytes(core)).hexdigest()
                 == hook['report_sha256'],
                 label + '_hook_seal')
        native = hook['native_controller']
        _require(type(native) is dict and set(native) == fields
                 and native['matched'] is True
                 and native['present'] is True
                 and native['status'] == 'ACTIVE'
                 and native['controller_seq'] == before_cursor['seq']
                 and native['controller_id'] == action['controller_id']
                 and native['action_id'] == action['action_id']
                 and native['grant_state'] == grant_state
                 and hook['tool_input_sha256']
                     == action['tool_input_sha256'],
                 label + '_hook_action_join')
        identity = hook['identity']
        _require(set(identity)
                     == native_contract.DURABLE_HOOK_IDENTITY_FIELDS
                 and identity['session_id'] == action['actor_thread_id']
                 and identity['current_thread_id']
                     == action['actor_thread_id'],
                 label + '_hook_identity')
    pre_native = pre['native_controller']
    post_native = post['native_controller']
    call_id = pre_native['tool_use_id']
    _require(type(call_id) is str
             and re.fullmatch(
                 r'[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}', call_id)
                 is not None
             and post_native['tool_use_id'] == call_id
             and pre['mutating'] is True
             and _same(pre['identity'], post['identity'])
             and post_native['pretool_report_sha256']
                 == pre['report_sha256'],
             label + '_hook_chain')
    normalized = native_result.normalize_native_result(
        raw, action_kind='stop', expected_lane_ids=[lane], outcome=outcome)
    _require(post_native['outcome'] == outcome
             and hashlib.sha256(
                 host_adapter.canonical_bytes(raw)).hexdigest()
                 == post_native['result_sha256']
             and (outcome == 'completed'
                  and normalized is not None
                  and _same(normalized, post_native['result_binding'])
                  or outcome != 'completed'
                  and normalized is None
                  and post_native['result_binding'] is None),
             label + '_raw_result')
    durable_fields = HOOK_DURABLE_EVENT_FIELDS - {
        'schema', 'report_schema', 'durable_record_sha256',
    }
    durable_records = []
    for hook in (pre, post):
        durable_core = {
            'schema': HOOK_DURABLE_EVENT_SCHEMA,
            'report_schema': hook['schema'],
            **{
                field: deepcopy(hook[field])
                for field in sorted(durable_fields)
            },
        }
        durable_records.append({
            **durable_core,
            'durable_record_sha256': values.canonical_digest(
                durable_core),
        })
    pre_durable, post_durable = durable_records
    _require(type(evidence) is dict and set(evidence) == {
                 'action', 'pretool_report_sha256',
                 'pretool_durable_record_sha256',
                 'posttool_report_sha256',
                 'posttool_durable_record_sha256', 'result_binding',
             }
             and _same(evidence['action'], action)
             and evidence['pretool_report_sha256']
                 == pre['report_sha256']
             and evidence['posttool_report_sha256']
                 == post['report_sha256']
             and evidence['pretool_durable_record_sha256']
                 == pre_durable['durable_record_sha256']
             and evidence['posttool_durable_record_sha256']
                 == post_durable['durable_record_sha256']
             and _same(evidence['result_binding'], normalized),
             label + '_retained_evidence')
    return {
        'normalized': normalized,
        'call_id': call_id,
        'pre_durable': pre_durable,
        'post_durable': post_durable,
    }


def compare_first_spawn(first_action_report, *, raw_response, pre_hook_report,
                        post_hook_report, advance_report):
    """Check only a completed first spawn that authorizes the standards spawn.

    Report-format acceptance comes from the actual public validators. The joins
    below additionally bind the initial action, call, response, hooks and next
    action across those individually valid reports. Unsupported prefixes refuse.
    """
    first, pre, post, advance, raw = rv.freeze([
        first_action_report, pre_hook_report, post_hook_report, advance_report,
        raw_response]).to_plain()
    _require(successor.validate_issue94_successor_first_action_report(first).get('valid') is True,
             'first_report')
    _require(successor.validate_issue94_successor_action_advance_report(advance).get('valid') is True,
             'advance_report')
    try:
        action = first['action']
        _require(native_contract.validate_governed_native_controller_report(
            first['controller_report']).get('valid') is True, 'first_controller_report')
        _require(action['kind'] == 'spawn' and action['lane_ids'] == ['spec']
                 and type(action['batch_index']) is int and action['batch_index'] == 0
                 and action['batch_lane_ids'] == ['spec', 'standards']
                 and action['batch_kind'] == 'spawn' and action['batch_phase'] == 'primary'
                 and action['batch_failure_outcome'] is None and action['batch_size'] == 2,
                 'unsupported_prefix')
        _require(advance['pre_turn_report_sha256'] == first['pre_turn_report_sha256']
                 and _same(advance['source_roots'], first['source_roots']), 'pre_turn_join')
        _require(len(advance['controller_transitions']) == 1, 'transition_count')
        transition = advance['controller_transitions'][0]
        program, after = transition['program'], transition['report']
        _require(native_contract.validate_governed_native_controller_report(after).get('valid') is True,
                 'next_controller_report')
        # These are the two public boundaries of this supported prefix. A
        # transport-valid report can still describe a contradictory transition.
        authorized_state = {'terminal': False, 'pending_intent': False,
            'action_outcome': None, 'action_authorized': True,
            'grant_state': 'AUTHORIZED', 'cleanup_required': False}
        _require(_same(first['controller_report']['controller_state'], authorized_state)
                 and _same(after['controller_state'], authorized_state), 'controller_state')
        before_cursor = first['controller_report']['cursor']
        after_cursor = after['cursor']
        _require(after_cursor['run_id'] == before_cursor['run_id']
                 and after_cursor['seq'] > before_cursor['seq']
                 and after_cursor['event_hash'] != before_cursor['event_hash'], 'successor_cursor')
        _require(set(program) == {'schema', 'controller_id', 'operation', 'expected_cursor', 'payload'}
                 and program['schema'] == native_contract.PROGRAM_SCHEMA
                 and program['controller_id'] == action['controller_id']
                 and program['operation'] == 'observe'
                 and _same(program['expected_cursor'], first['controller_report']['cursor']), 'cursor_join')
        observation = program['payload']
        _require(set(observation) == {'schema', 'action_id', 'tool_name', 'tool_input_sha256',
                                     'tool_use_id', 'outcome', 'hook_report_sha256', 'native_receipt'}
                 and observation['schema'] == native_contract.ACTION_OBSERVATION_SCHEMA, 'observation_grammar')
        call_id = observation['tool_use_id']
        _require(type(call_id) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}', call_id)
                 is not None, 'call_identity')
        for hook, event_name, grant_state, decision, fields in (
            (pre, 'PreToolUse', 'DISPATCHED', 'ALLOW', native_contract.DURABLE_PRETOOL_NATIVE_FIELDS),
            (post, 'PostToolUse', 'POST_OBSERVED', 'OBSERVED', native_contract.DURABLE_POSTTOOL_NATIVE_FIELDS),
        ):
            _require(type(hook) is dict and hook['hook_event_name'] == event_name
                     and hook['schema'] == ground_contract.REPORT_SCHEMA
                     and hook['status'] == 'PASS' and hook['decision'] == decision, 'hook_report')
            core = {key: value for key, value in hook.items() if key != 'report_sha256'}
            _require(hashlib.sha256(host_adapter.canonical_bytes(core)).hexdigest()
                     == hook['report_sha256'], 'hook_seal')
            native = hook['native_controller']
            _require(type(native) is dict and set(native) == fields
                     and native['matched'] is True and native['present'] is True
                     and native['status'] == 'ACTIVE'
                     and type(native['controller_seq']) is int
                     and native['controller_seq'] == first['controller_report']['cursor']['seq']
                     and native['controller_id'] == action['controller_id']
                     and native['action_id'] == action['action_id']
                     and native['tool_use_id'] == call_id and native['grant_state'] == grant_state
                     and hook['tool_input_sha256'] == action['tool_input_sha256'], 'hook_call_join')
            _require(set(hook['identity']) == native_contract.DURABLE_HOOK_IDENTITY_FIELDS
                     and type(hook['identity']['turn_id']) is str
                     and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}', hook['identity']['turn_id'])
                     is not None
                     and hook['identity']['session_id'] == action['actor_thread_id']
                     and hook['identity']['current_thread_id'] == action['actor_thread_id'], 'hook_actor_join')
        _require(pre['mutating'] is True
                 and type(pre['native_controller']['pretool_event_sha256']) is str
                 and re.fullmatch(r'[0-9a-f]{64}', pre['native_controller']['pretool_event_sha256']) is not None,
                 'pre_hook_admission')
        _require(_same(pre['identity'], post['identity']), 'hook_identity_join')
        _require(post['native_controller']['pretool_report_sha256'] == pre['report_sha256']
                 and observation['hook_report_sha256'] == post['report_sha256'], 'hook_chain')
        durable = advance['durable_hook_report']
        _require(set(durable) == HOOK_DURABLE_EVENT_FIELDS
                 and durable['schema'] == HOOK_DURABLE_EVENT_SCHEMA
                 and durable['report_schema'] == post['schema']
                 and all(_same(durable[key], post[key]) for key in HOOK_DURABLE_EVENT_FIELDS
                         - {'schema', 'report_schema', 'durable_record_sha256'})
                 and durable['durable_record_sha256'] == values.canonical_digest(
                     {key: value for key, value in durable.items() if key != 'durable_record_sha256'}),
                 'durable_join')
        authority = advance['authority_before']
        _require(authority['lifecycle']['action_sha256'] == action['action_sha256']
                 and authority['lifecycle']['tool_use_id'] == call_id
                 and authority['owner']['controller_id'] == action['controller_id'], 'authority_join')
        _require(_same(authority['tip'], before_cursor)
                 and all(authority[part]['controller_run_id'] == before_cursor['run_id']
                         and authority[part]['controller_id'] == action['controller_id']
                         for part in ('owner', 'identity', 'hook_projection'))
                 and authority['hook_projection']['controller_seq'] == before_cursor['seq']
                 and type(authority['hook_projection']['controller_seq']) is int
                 and authority['hook_projection']['controller_event_hash'] == before_cursor['event_hash']
                 and authority['identity']['root_thread_id'] == action['actor_thread_id']
                 and authority['identity']['root_session_id'] == action['actor_thread_id'], 'authority_identity')
        _require(authority['lifecycle']['expected_binding_status'] == 'ACTIVE'
                 and authority['lifecycle']['grant_state'] == 'POST_OBSERVED'
                 and all(authority['lifecycle'][key] is False for key in
                         ('terminal', 'cleanup_required', 'pending_intent')), 'authority_state')
        normalized = native_result.normalize_native_result(raw, action_kind=action['kind'],
            expected_lane_ids=action['lane_ids'], outcome=post['native_controller']['outcome'])
        _require(normalized is not None and post['native_controller']['outcome'] == 'completed', 'raw_result')
        _require(hashlib.sha256(host_adapter.canonical_bytes(raw)).hexdigest()
                 == post['native_controller']['result_sha256']
                 and _same(normalized, post['native_controller']['result_binding']), 'raw_result_join')
        _require(observation['action_id'] == action['action_id']
                 and observation['tool_name'] == action['tool_name']
                 and observation['tool_input_sha256'] == action['tool_input_sha256'], 'action_join')
        receipt = observation['native_receipt']
        _require(set(receipt) == {'schema', 'action_id', 'outcome', 'tool_name', 'tool_input_sha256',
                                 'tool_use_id', 'result_sha256', 'result_binding', 'source_pointer'}
                 and receipt['schema'] == native_contract.NATIVE_ACTION_RECEIPT_SCHEMA
                 and receipt['source_pointer'] == 'project-ground-durable-event#' + durable['durable_record_sha256'],
                 'receipt_grammar')
        _require(observation['outcome'] == post['native_controller']['outcome']
                 and all(receipt[key] == observation[key] for key in
                         ('action_id', 'tool_name', 'tool_input_sha256', 'tool_use_id', 'outcome'))
                 and receipt['result_sha256'] == post['native_controller']['result_sha256']
                 and _same(receipt['result_binding'], normalized), 'native_receipt_join')
        next_action = advance['action']
        _require(_same(next_action, after['action']) and next_action['kind'] == 'spawn'
                 and next_action['lane_ids'] == ['standards']
                 and type(next_action['batch_index']) is int and next_action['batch_index'] == 1
                 and next_action['batch_id'] == action['batch_id'], 'next_action')
        _require(all(_same(next_action[key], action[key]) for key in
                     ('controller_id', 'actor_thread_id', 'adapter_sha256', 'predecessor_receipt_sha256',
                      'batch_schema', 'batch_kind', 'batch_size', 'batch_lane_ids', 'batch_requests',
                      'batch_requests_sha256', 'batch_phase', 'batch_failure_outcome'))
                 and next_action['action_id'] != action['action_id']
                 and _same(after['stage_report'], first['controller_report']['stage_report']),
                 'next_batch_provenance')
        # The selected readiness prefix is explicit. Production comparison here
        # starts at the returned first spawn, after the actual seed preparation.
        state, choices = model.initial_state(explorer.GRAPH_CASE), []
        model_states = [state.to_plain()]
        state_ids = [explorer.state_identity(state)]
        transition_ids = []
        model_steps = []
        while state.to_plain().get('stage') != 'spawn.standards':
            _require(len(choices) < 8, 'model_prefix_bound')
            event = next(e for e in model.outgoing_stimuli(state).to_plain()
                         if e.get('outcome', 'accepted') == 'accepted')
            choice = explorer.abstract_event(event)
            reduction = model.reduce(state, event).to_plain()
            next_state = rv.freeze(reduction['successor'])
            directive = model.legal_directive(next_state).to_plain()
            _require(_same(reduction['directive'], directive),
                     'model_bridge_directive')
            successor_id = explorer.state_identity(next_state)
            transition_id = explorer.edge_identity(
                state_ids[-1], event, successor_id)
            choices.append(choice)
            transition_ids.append(transition_id)
            model_steps.append({
                'source_state_id': state_ids[-1],
                'choice': choice,
                'transition_id': transition_id,
                'target_state_id': successor_id,
                'directive': directive,
            })
            state = next_state
            model_states.append(state.to_plain())
            state_ids.append(successor_id)
        facts = state.to_plain()
        _require(facts['action']['method'] == 'spawn_agent'
                 and facts['action']['lane'] == next_action['lane_ids'][0], 'model_action')
        bindings = first['controller_report']['stage_report']['receipt']['bindings']
        run_id = first['controller_report']['stage_report']['run_id']
        expected_capacity = [run_id + ':' + lane for lane, row in facts['lanes'].items()
                             if row['capacity'] in ('reserved', 'occupied')]
        _require(sorted(bindings['capacity_authority_lane_ids']) == sorted(expected_capacity), 'model_capacity')
        source_indexes = [index for index, item in enumerate(model_states)
                          if item.get('stage') == 'spawn.spec']
        _require(len(source_indexes) == 1, 'model_source_state')
        source_index = source_indexes[0]
        source = model_states[source_index]
        _require(source['action']['method'] == 'spawn_agent'
                 and source['action']['lane'] == action['lane_ids'][0], 'model_source_action')
        graph_mapping = {
            'schema': 'orch-dork/production-graph-prefix/v2',
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': {
                'kind': 'completed_first_spawn_to_next_authorized_spawn',
                'source_state_id': state_ids[source_index],
                'target_state_id': state_ids[-1],
                'model_bridge_state_ids': state_ids[source_index:],
                'model_bridge_transition_ids': transition_ids[source_index:],
                'model_bridge_steps': model_steps[source_index:],
            },
            'gap': {
                'status': 'PREFIX_ONLY',
                'observed_boundary_count': 1,
                'next_uncovered_choices': [explorer.abstract_event(event) for event in
                                           model.outgoing_stimuli(state).to_plain()],
                'production_graph_complete': False,
            },
        }
        return rv.freeze({'scope': 'first_completed_spawn_prefix', 'model_choices': choices,
            'model_state': state.to_plain(), 'native_worker_id': normalized['lanes'][0]['agent_id'],
            'graph_mapping': graph_mapping,
            'input_sha256': values.canonical_digest([first, raw, pre, post, advance]),
            'capture_authenticated': False,
            'host_execution_custody': False,
            'controller_continuation_authorized': False,
            'execution_attested': False, 'complete_campaign': False,
            'release_authorized': False,
            'qualification_authorized': False})
    except (KeyError, IndexError, TypeError, StopIteration) as error:
        raise values.LifecycleContractError('public_native_comparison:unsupported_shape') from error


def compare_completed_second_spawn(first_spawn, completed_second_step):
    """Map two completed production spawns to the acknowledgement wait."""
    first, completed = rv.freeze(
        [first_spawn, completed_second_step]
    ).to_plain()
    _require(type(first) is dict and set(first) == {
        'first_action_report', 'raw_response', 'pre_hook_report',
        'post_hook_report', 'advance_report',
    }, 'completed_first_input_shape')
    _require(type(completed) is dict and set(completed) == {
        'action', 'raw_response', 'pre_hook_report', 'post_hook_report',
        'advance_report',
    }, 'completed_second_input_shape')
    prefix = compare_first_spawn(**first).to_plain()
    try:
        first_advance = first['advance_report']
        previous = first_advance['controller_transitions'][-1]['report']
        checked = _validated_action_step(
            completed, first_advance['action'], previous,
            action_kind='spawn', lane_ids=['standards'],
            outcome='completed', label='completed_second',
        )
        action = checked['action']
        advance = checked['advance']
        after = checked['controller']
        normalized = checked['normalized']
        _require(action['kind'] == 'spawn'
                 and action['tool_name'] == 'multi_agent_v1__spawn_agent'
                 and action['lane_ids'] == ['standards']
                 and action['batch_kind'] == 'spawn'
                 and action['batch_phase'] == 'primary'
                 and action['batch_index'] == 1
                 and action['batch_size'] == 2
                 and action['batch_lane_ids'] == ['spec', 'standards']
                 and action['batch_failure_outcome'] is None,
                 'completed_second_action')
        _require(advance['pre_turn_report_sha256']
                 == first_advance['pre_turn_report_sha256']
                 and _same(advance['source_roots'], first_advance['source_roots']),
                 'completed_prefix_provenance')
        _require(advance['status'] == 'PASS'
                 and advance['decision']
                 == 'AWAITING_WORKER_ACKNOWLEDGEMENTS'
                 and advance['issues'] == [] and advance['action'] is None,
                 'completed_ack_wait')
        _require(after['status'] == 'PASS'
                 and after['decision'] == 'ACTION_OBSERVED'
                 and after['issues'] == [] and after['action'] is None
                 and after['controller_state'] == {
                     'terminal': False,
                     'pending_intent': False,
                     'action_outcome': 'completed',
                     'action_authorized': False,
                     'grant_state': None,
                     'cleanup_required': False,
                 }, 'completed_controller_report')
        acknowledgements = advance['acknowledgements']
        ack_core = {key: value for key, value in acknowledgements.items()
                    if key != 'acknowledgements_sha256'}
        _require(set(acknowledgements) == {
            'schema', 'state', 'expected_lane_ids', 'observed_lane_ids',
            'pending_lane_ids', 'runtime_observations',
            'acknowledgements_sha256',
        } and acknowledgements['schema']
            == successor.WORKER_ACKNOWLEDGEMENTS_SCHEMA
            and acknowledgements['state'] == 'AWAITING'
            and acknowledgements['expected_lane_ids'] == ['spec', 'standards']
            and acknowledgements['observed_lane_ids'] == []
            and acknowledgements['pending_lane_ids'] == ['spec', 'standards']
            and acknowledgements['runtime_observations'] == []
            and acknowledgements['acknowledgements_sha256']
            == values.canonical_digest(ack_core),
                 'completed_acknowledgements')
        expected_bridge = (
            'mcp__orch_dork__advance_issue94_bootstrapped_after_native_action'
            if advance['schema']
            == successor.BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA
            else 'mcp__orch_dork__advance_issue94_successor_after_native_action'
        )
        _require(_same(after['stage_report'], previous['stage_report'])
                 and advance['worker_results'] == []
                 and advance['review_packet'] is None
                 and advance['boundary'] == {
                     'native_action_called_by_bridge': False,
                     'native_action_observed_by_bridge': True,
                     'worker_acknowledgements_observed': 0,
                     'controller_stage_advanced': False,
                     'next_action': expected_bridge,
                 }, 'completed_ack_boundary')

        state = rv.freeze(prefix['model_state'])
        source_id = explorer.state_identity(state)
        _require(source_id == prefix['graph_mapping']['production_boundary'][
            'target_state_id'], 'completed_graph_source')
        choice = {
            'stage': 'spawn.standards', 'lane': 'standards',
            'outcome': 'accepted', 'variant': 'evidence',
        }
        events = [event for event in model.outgoing_stimuli(state).to_plain()
                  if _same(explorer.abstract_event(event), choice)]
        _require(len(events) == 1, 'completed_model_choice')
        event = events[0]
        reduction = model.reduce(state, event).to_plain()
        successor_state = rv.freeze(reduction['successor'])
        target_id = explorer.state_identity(successor_state)
        directive = model.legal_directive(successor_state).to_plain()
        _require(_same(reduction['directive'], directive)
                 and successor_state.to_plain()['stage'] == 'ack'
                 and directive['kind'] == 'wait_for_observation'
                 and directive['payload']['detail'] == 'acknowledgement'
                 and [item['lane'] for item in directive['payload']['bindings']]
                 == ['spec', 'standards'],
                 'completed_model_ack_wait')
        graph_mapping = {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': {
                'kind': 'completed_second_spawn_to_acknowledgement_wait',
                'choice': choice,
                'source_state_id': source_id,
                'transition_id': explorer.edge_identity(
                    source_id, event, target_id
                ),
                'target_state_id': target_id,
            },
            'gap': {
                'status': 'PREFIX_ONLY',
                'observed_boundary_count': 2,
                'next_uncovered_choices': [
                    explorer.abstract_event(item) for item in
                    model.outgoing_stimuli(successor_state).to_plain()
                ],
                'production_graph_complete': False,
            },
        }
        return rv.freeze({
            'schema': 'orch-dork/production-graph-second-spawn/v1',
            'scope': 'two_completed_spawn_prefix',
            'graph_mapping': graph_mapping,
            'model_state': successor_state.to_plain(),
            'native_worker_ids': {
                'spec': prefix['native_worker_id'],
                'standards': normalized['lanes'][0]['agent_id'],
            },
            'native_pending_acknowledgements':
                acknowledgements['pending_lane_ids'],
            'input_sha256': values.canonical_digest([first, completed]),
            'capture_authenticated': False,
            'host_execution_custody': False,
            'controller_continuation_authorized': False,
            'execution_attested': False,
            'complete_campaign': False,
            'release_authorized': False,
            'qualification_authorized': False,
        })
    except (KeyError, IndexError, TypeError, StopIteration, ValueError) as error:
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_completed_shape'
        ) from error


def _acknowledgement_input_projection(source_bytes, observer_read, advance):
    return {
        'raw_rollout_sha256': hashlib.sha256(source_bytes).hexdigest(),
        'raw_rollout_size': len(source_bytes),
        'observer_read': observer_read,
        'advance_report': advance,
    }


def _complete_acknowledgement_input_projection(
        source_bytes, observer_reads, advance, action_source):
    return {
        'raw_rollout_sha256': hashlib.sha256(source_bytes).hexdigest(),
        'raw_rollout_size': len(source_bytes),
        'observer_reads': observer_reads,
        'advance_report': advance,
        'action_source_root': action_source['source_root'],
        'action_source_hashes': {
            path: hashlib.sha256(text.encode('utf-8')).hexdigest()
            for path, text in sorted(action_source['documents'].items())
        },
    }


def _expected_review_corpus(source_root, documents, lane_id, task_spec):
    """Rebuild the adapter's bounded corpus from retained exact source text."""

    _require(type(source_root) is str and source_root.startswith('/')
             and '\x00' not in source_root,
             'standards_ack_action_source_root')
    _require(type(documents) is dict and set(documents) == {
        'AGENTS.md', 'SPEC.md', 'TICKETS.md',
    } and all(type(text) is str
              and len(text.encode('utf-8')) <= 8_388_608
              for text in documents.values()),
             'standards_ack_action_source_documents')
    raw_scope = task_spec.get('read_scope')
    _require(type(raw_scope) is list
             and all(type(item) is str for item in raw_scope),
             'standards_ack_action_read_scope')

    def between(text, start, end):
        offset = text.find(start)
        if offset < 0:
            return ''
        limit = text.find(end, offset + len(start))
        return text[offset:] if limit < 0 else text[offset:limit]

    excerpts = []

    def add(relative, selector, content):
        normalized = content.strip()
        _require(bool(normalized)
                 and len(normalized.encode('utf-8')) <= 48_000,
                 'standards_ack_action_excerpt')
        source_text = documents[relative]
        excerpts.append({
            'path': relative,
            'source_sha256': hashlib.sha256(
                source_text.encode('utf-8')).hexdigest(),
            'selector': selector,
            'content': normalized,
            'excerpt_sha256': hashlib.sha256(
                normalized.encode('utf-8')).hexdigest(),
        })

    lane_kind = (lane_id if lane_id in {'spec', 'standards'} else 'generic')
    for relative in raw_scope:
        if relative not in {'AGENTS.md', 'SPEC.md', 'TICKETS.md'}:
            continue
        text = documents[relative]
        if relative == 'AGENTS.md' and lane_kind == 'standards':
            add(relative, 'qualification-first-promotion-loop', between(
                text,
                '# Working in this repository',
                '## Ticket ledger and host ownership',
            ))
        elif relative == 'SPEC.md' and lane_kind == 'spec':
            add(relative, 'FR63-controller-contract', between(
                text,
                'One provider-free `orch-dork/governed-native-controller/v1`',
                'Activation writes one content-addressed',
            ))
            add(relative, 'FR63-spawn-and-worker-start', between(
                text,
                'The action adapter emits one exact direct collaboration-tool input',
                'The production seam hard-binds',
            ))
            add(relative, 'FR63-retained-action-evidence', between(
                text,
                'Each accepted action observation retains the exact action',
                "Capacity admission and settlement use FR62's canonical",
            ))
            add(relative, 'acceptance-criterion-51', between(
                text,
                '51. A provider-free host controller activated before a native task',
                '52.',
            ))
        elif relative == 'TICKETS.md' and lane_kind in {'spec', 'standards'}:
            issue_row = next((line for line in text.splitlines()
                              if line.startswith('| 163 |')), '')
            current_cycle = between(
                text,
                '- [ ] Preserve Cycle 31 as replay v17',
                '#### Cycle 1 authority and orchestration evidence',
            )
            if not current_cycle:
                current_cycle = between(
                    text,
                    '- [x] Preserve Cycle 31 as replay v17',
                    '#### Cycle 1 authority and orchestration evidence',
                )
            add(relative, 'issue-163-row-and-current-cycle',
                issue_row + '\n\n' + current_cycle)
    _require(lane_kind not in {'spec', 'standards'} or bool(excerpts),
             'standards_ack_action_review_corpus')
    core = {
        'schema': 'orch-dork/native-review-corpus/v1',
        'lane_id': lane_id,
        'task_spec_sha256': task_spec.get('task_spec_sha256'),
        'source_root_sha256': hashlib.sha256(
            source_root.encode('utf-8')).hexdigest(),
        'excerpts': excerpts,
    }
    corpus = {
        **core,
        'corpus_sha256': successor.route_policy.canonical_sha256(core),
    }
    _require(len(host_adapter.canonical_bytes(corpus)) <= 72_000,
             'standards_ack_action_review_corpus_size')
    return corpus


def _expected_worker_start_action(*, controller_id, root_id, cursor,
                                  acknowledgements, proposal, receipt,
                                  dispatches, workers, action_source):
    """Independently reconstruct the closed adapter's exact first continuation."""

    expected_action_id = 'issue94-worker-start-' + (
        successor.route_policy.canonical_sha256({
            'controller_id': controller_id,
            'cursor': cursor,
            'acknowledgements_sha256': acknowledgements[
                'acknowledgements_sha256'],
        })[:24]
    )
    _require(proposal == {
        'schema': native_contract.ACTION_PROPOSAL_SCHEMA,
        'action_id': expected_action_id,
        'kind': 'continue',
        'actor_thread_id': root_id,
        'adapter_sha256':
            native_contract.CLOSED_NATIVE_ACTION_ADAPTER_SHA256,
    }, 'standards_ack_action_proposal_exact')
    requests = []
    for lane in ('spec', 'standards'):
        task_spec = dispatches[lane]['task_spec']
        packet = {
            'schema': 'orch-dork/native-continuation/v1',
            'controller_id': controller_id,
            'lane_id': lane,
            'predecessor_receipt_sha256': receipt['receipt_sha256'],
            'task_spec_sha256': task_spec['task_spec_sha256'],
            'review_corpus': _expected_review_corpus(
                action_source['source_root'],
                action_source['documents'],
                lane,
                task_spec,
            ),
            'instruction': (
                'Begin the frozen TaskSpec using the supplied evidence. '
                'Do not call tools or spawn. Fill only claims, artifact_refs '
                'and checks in checkpoint_submission with your actual progress. '
                'Preserve its schema, task_spec_sha256 and sequence; add no fields. '
                'Do not supply usage or a source pointer. Return only that JSON '
                'object, then yield. Await another controller-owned continuation '
                'before returning the final handoff.'
            ),
            'checkpoint_submission': {
                'schema': 'orch-dork/worker-progress-submission/v1',
                'task_spec_sha256': task_spec['task_spec_sha256'],
                'sequence': 1,
                'claims': [],
                'artifact_refs': [],
                'checks': [],
            },
        }
        requests.append({
            'lane_id': lane,
            'kind': 'continue',
            'tool_name': 'multi_agent_v1__send_input',
            'tool_input': {
                'target': workers[lane],
                'message': host_adapter.canonical_bytes(packet).decode('utf-8'),
            },
        })
    tool_input = requests[0]['tool_input']
    core = {
        'schema': native_contract.ACTION_SCHEMA,
        'controller_id': controller_id,
        'action_id': expected_action_id,
        'kind': 'continue',
        'lane_ids': ['spec'],
        'actor_thread_id': root_id,
        'tool_name': 'multi_agent_v1__send_input',
        'tool_input': tool_input,
        'tool_input_sha256': successor.route_policy.canonical_sha256(
            tool_input),
        'adapter_sha256':
            native_contract.CLOSED_NATIVE_ACTION_ADAPTER_SHA256,
        'predecessor_receipt_sha256': receipt['receipt_sha256'],
        'batch_schema': native_contract.NATIVE_BATCH_SCHEMA,
        'batch_id': expected_action_id,
        'batch_kind': 'continue',
        'batch_phase': 'primary',
        'batch_index': 0,
        'batch_size': 2,
        'batch_lane_ids': ['spec', 'standards'],
        'batch_requests': requests,
        'batch_requests_sha256': successor.route_policy.canonical_sha256(
            requests),
        'batch_failure_outcome': None,
    }
    return {
        **core,
        'action_sha256': successor.route_policy.canonical_sha256(core),
    }


def _expected_next_batch_action(action):
    """Independently reconstruct the second leg of one sealed native batch."""

    _require(type(action) is dict and action['batch_phase'] == 'primary'
             and action['batch_index'] == 0
             and action['batch_failure_outcome'] is None
             and type(action['batch_requests']) is list
             and len(action['batch_requests']) == 2,
             'continuation_batch_source')
    index = 1
    request = action['batch_requests'][index]
    _require(type(request) is dict and set(request) == {
        'lane_id', 'kind', 'tool_name', 'tool_input',
    }, 'continuation_batch_request')
    action_id = 'native-' + successor.route_policy.canonical_sha256({
        'batch_id': action['batch_id'],
        'phase': action['batch_phase'],
        'index': index,
        'request': request,
        'failure_outcome': action['batch_failure_outcome'],
    })[:32]
    core = {
        'schema': native_contract.ACTION_SCHEMA,
        'controller_id': action['controller_id'],
        'action_id': action_id,
        'kind': request['kind'],
        'lane_ids': [request['lane_id']],
        'actor_thread_id': action['actor_thread_id'],
        'tool_name': request['tool_name'],
        'tool_input': request['tool_input'],
        'tool_input_sha256': successor.route_policy.canonical_sha256(
            request['tool_input']),
        'adapter_sha256': action['adapter_sha256'],
        'predecessor_receipt_sha256':
            action['predecessor_receipt_sha256'],
        'batch_schema': native_contract.NATIVE_BATCH_SCHEMA,
        'batch_id': action['batch_id'],
        'batch_kind': action['batch_kind'],
        'batch_phase': action['batch_phase'],
        'batch_index': index,
        'batch_size': len(action['batch_requests']),
        'batch_lane_ids': action['batch_lane_ids'],
        'batch_requests': action['batch_requests'],
        'batch_requests_sha256': successor.route_policy.canonical_sha256(
            action['batch_requests']),
        'batch_failure_outcome': action['batch_failure_outcome'],
    }
    return {
        **core,
        'action_sha256': successor.route_policy.canonical_sha256(core),
    }


def compare_first_successful_spec_acknowledgement(
        first_spawn, completed_second_step, acknowledgement_step):
    """Map one byte-rebuilt spec pre-work receipt onto the ack graph edge."""

    first, completed = rv.freeze([
        first_spawn, completed_second_step,
    ]).to_plain()
    _require(type(acknowledgement_step) is dict
             and set(acknowledgement_step) == {
        'raw_rollout_bytes', 'observer_read', 'advance_report',
    }, 'spec_ack_input_shape')
    source_bytes = acknowledgement_step['raw_rollout_bytes']
    _require(type(source_bytes) is bytes, 'spec_ack_source_type')
    observer_read, advance = rv.freeze([
        acknowledgement_step['observer_read'],
        acknowledgement_step['advance_report'],
    ]).to_plain()
    try:
        lines = source_bytes.splitlines()
        _require(0 < len(lines) <= 32 and all(lines)
                 and len(source_bytes) <= 128 * 1024,
                 'spec_ack_source_bound')
        raw_records = [_strict_json_record(line) for line in lines]
        _require(_exact_pre_work_records(raw_records),
                 'spec_ack_source_records')
        prefix = compare_completed_second_spawn(first, completed).to_plain()
        _require(type(observer_read) is dict and set(observer_read) == {
            'session_id', 'observer_id', 'report',
        }, 'spec_ack_observer_read_shape')
        _require(
            successor.validate_issue94_successor_action_advance_report(
                advance).get('valid') is True,
            'spec_ack_advance_report',
        )
        _require(advance['schema'] == successor.ACTION_ADVANCE_REPORT_SCHEMA,
                 'spec_ack_advance_schema')

        first_action = first['first_action_report']['action']
        spec_worker = prefix['native_worker_ids']['spec']
        root_id = first_action['actor_thread_id']
        _require(observer_read['session_id'] == spec_worker
                 and observer_read['observer_id'] == root_id,
                 'spec_ack_observer_identity')
        rebuilt_observation = (
            successor.routing_verify.build_session_runtime_observation(
                source_bytes,
                session_id=observer_read['session_id'],
                observer_id=observer_read['observer_id'],
            )
        )
        observation = observer_read['report']
        _require(_same(observation, rebuilt_observation)
                 and successor.routing_verify.validate_session_runtime_observation(
                     observation).get('valid') is True,
                 'spec_ack_observation_rebuild')
        route = observation['route']
        _require(observation['observer_id'] == root_id
                 and observation['source_pointer']
                 == 'session://' + spec_worker
                 and observation['skipped_lines'] == 0
                 and route == {
                     'session_id': spec_worker,
                     'model': first_action['tool_input']['model'],
                     'effort': first_action['tool_input']['reasoning_effort'],
                     'context_policy': 'none',
                     'inherited_history': False,
                 }
                 and observation['usage']['status'] == 'observed'
                 and observation['usage']['tool_calls'] == 0,
                 'spec_ack_route')

        dispatch = _strict_json_record(first_action['tool_input']['message'])
        _require(type(dispatch) is dict
                 and dispatch['schema'] == 'orch-dork/native-task-dispatch/v1'
                 and dispatch['controller_id'] == first_action['controller_id']
                 and dispatch['lane_id'] == 'spec'
                 and dispatch['task_spec']['task_spec_sha256']
                 == dispatch['pre_work_receipt']['task_spec_sha256'],
                 'spec_ack_dispatch')
        expected_receipt = successor.route_policy.task_spec_pre_work_receipt(
            logical_lane_id='spec',
            task_spec_sha256=dispatch['task_spec']['task_spec_sha256'],
        )
        _require(_same(dispatch['pre_work_receipt'], expected_receipt)
                 and observation['terminal_schema']
                 == successor.route_policy.TASK_SPEC_PRE_WORK_RECEIPT_SCHEMA
                 and observation['terminal_json_sha256']
                 == successor.route_policy.canonical_sha256(expected_receipt),
                 'spec_ack_pre_work_receipt')
        terminal_messages = []
        for record in raw_records:
            payload = record.get('payload')
            if record.get('type') != 'event_msg' or type(payload) is not dict:
                continue
            if payload.get('type') == 'agent_message':
                message = payload.get('message')
            elif payload.get('type') == 'task_complete':
                message = payload.get('last_agent_message')
            else:
                continue
            if type(message) is str and message.strip():
                terminal_messages.append(_strict_json_record(message))
        _require(len(terminal_messages) == 1
                 and _same(terminal_messages[0], expected_receipt),
                 'spec_ack_first_terminal_receipt')

        second_advance = completed['advance_report']
        second_after = second_advance['controller_transitions'][-1]['report']
        authority = advance['authority_before']
        previous_authority = second_advance['authority_before']
        projection = authority['hook_projection']
        binding_core = {
            'schema': native_contract.HOOK_BINDING_SCHEMA,
            'controller_id': projection['controller_id'],
            'controller_run_id': projection['controller_run_id'],
            'controller_seq': projection['controller_seq'],
            'controller_event_hash': projection['controller_event_hash'],
            'root_thread_id': authority['identity']['root_thread_id'],
            'root_session_id': authority['identity']['root_session_id'],
            'root_model': authority['identity']['root_model'],
            'hook_definition_sha256':
                authority['identity']['hook_definition_sha256'],
            'hook_registration_sha256':
                authority['identity']['hook_registration_sha256'],
            'store_identity_sha256': authority['store_identity_sha256'],
            'ground_state_sha256': authority['ground_state_sha256'],
            'status': 'WAITING',
            'action': None,
        }
        _require(advance['pre_turn_report_sha256']
                 == second_advance['pre_turn_report_sha256']
                 and _same(advance['source_roots'],
                           second_advance['source_roots']),
                 'spec_ack_prefix_provenance')
        _require(type(authority) is dict
                 and set(authority) == set(previous_authority)
                 and all(_same(authority[key], previous_authority[key]) for key in (
                     'ground_state_sha256', 'identity', 'owner', 'policy',
                     'store_identity_sha256',
                 ))
                 and _same(authority['tip'], second_after['cursor'])
                 and set(projection) == {
                     'binding_sha256', 'controller_event_hash',
                     'controller_id', 'controller_run_id', 'controller_seq',
                 }
                 and projection['binding_sha256']
                 == values.canonical_digest(binding_core)
                 and projection['controller_id']
                 == first_action['controller_id']
                 and projection['controller_run_id']
                 == second_after['cursor']['run_id']
                 and projection['controller_seq']
                 == second_after['cursor']['seq']
                 and projection['controller_event_hash']
                 == second_after['cursor']['event_hash']
                 and authority['identity']['root_thread_id'] == root_id
                 and authority['identity']['root_session_id'] == root_id
                 and authority['lifecycle'] == {
                     'action_sha256': None,
                     'cleanup_required': False,
                     'expected_binding_status': 'WAITING',
                     'grant_state': None,
                     'pending_intent': False,
                     'terminal': False,
                     'terminal_evidence_sha256': None,
                     'terminal_qualified': False,
                     'tool_use_id': None,
                 }, 'spec_ack_authority_continuity')

        acknowledgements = advance['acknowledgements']
        ack_core = {key: value for key, value in acknowledgements.items()
                    if key != 'acknowledgements_sha256'}
        _require(set(acknowledgements) == {
            'schema', 'state', 'expected_lane_ids', 'observed_lane_ids',
            'pending_lane_ids', 'runtime_observations',
            'acknowledgements_sha256',
        } and acknowledgements['schema']
            == successor.WORKER_ACKNOWLEDGEMENTS_SCHEMA
            and acknowledgements['state'] == 'AWAITING'
            and acknowledgements['expected_lane_ids'] == ['spec', 'standards']
            and acknowledgements['observed_lane_ids'] == ['spec']
            and acknowledgements['pending_lane_ids'] == ['standards']
            and acknowledgements['acknowledgements_sha256']
            == values.canonical_digest(ack_core),
                 'spec_ack_acknowledgements')
        runtime_rows = acknowledgements['runtime_observations']
        _require(len(runtime_rows) == 1 and runtime_rows[0] == {
            'logical_worker_id': 'spec',
            'worker_id': spec_worker,
            'session_id': spec_worker,
            'observation': observation,
        }, 'spec_ack_runtime_observation_join')
        expected_bridge = (
            'mcp__orch_dork__advance_issue94_successor_after_native_action'
        )
        _require(advance['status'] == 'PASS'
                 and advance['decision']
                 == 'AWAITING_WORKER_ACKNOWLEDGEMENTS'
                 and advance['issues'] == []
                 and advance['durable_hook_report'] is None
                 and advance['controller_transitions'] == []
                 and advance['worker_results'] == []
                 and advance['review_packet'] is None
                 and advance['action'] is None
                 and advance['boundary'] == {
                     'native_action_called_by_bridge': False,
                     'native_action_observed_by_bridge': False,
                     'worker_acknowledgements_observed': 1,
                     'controller_stage_advanced': False,
                     'next_action': expected_bridge,
                 }
                 and advance['provider_free'] is True
                 and advance['counters'] == {
                     'controller_observations': 0,
                     'controller_stages': 0,
                     'session_runtime_observations': 1,
                     'hosted_calls': 0,
                     'model_calls': 0,
                     'native_actions': 0,
                     'network_calls': 0,
                     'provider_calls': 0,
                     'task_creations': 0,
                     'worker_creations': 0,
                 }, 'spec_ack_wait_boundary')

        state = rv.freeze(prefix['model_state'])
        source_id = explorer.state_identity(state)
        _require(source_id == prefix['graph_mapping'][
            'production_boundary']['target_state_id'],
            'spec_ack_graph_source')
        choice = {
            'stage': 'ack', 'lane': 'spec',
            'outcome': 'accepted', 'variant': 'SUCCESS',
        }
        events = [event for event in model.outgoing_stimuli(state).to_plain()
                  if _same(explorer.abstract_event(event), choice)]
        _require(len(events) == 1, 'spec_ack_model_choice')
        event = events[0]
        reduction = model.reduce(state, event).to_plain()
        successor_state = rv.freeze(reduction['successor'])
        target_id = explorer.state_identity(successor_state)
        directive = model.legal_directive(successor_state).to_plain()
        successor_facts = successor_state.to_plain()
        _require(_same(reduction['directive'], directive)
                 and successor_facts['stage'] == 'ack'
                 and successor_facts['lanes']['spec']['acknowledgement']
                 == 'SUCCESS'
                 and successor_facts['lanes']['standards'][
                     'acknowledgement'] == 'pending'
                 and directive['kind'] == 'wait_for_observation'
                 and directive['payload']['detail'] == 'acknowledgement'
                 and [item['lane'] for item in
                      directive['payload']['bindings']] == ['standards'],
                 'spec_ack_model_wait')
        graph_mapping = {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': {
                'kind': 'successful_spec_acknowledgement_to_standards_wait',
                'choice': choice,
                'source_state_id': source_id,
                'transition_id': explorer.edge_identity(
                    source_id, event, target_id
                ),
                'target_state_id': target_id,
            },
            'gap': {
                'status': 'PREFIX_ONLY',
                'observed_boundary_count': 3,
                'next_uncovered_choices': [
                    explorer.abstract_event(item) for item in
                    model.outgoing_stimuli(successor_state).to_plain()
                ],
                'production_graph_complete': False,
            },
        }
        return rv.freeze({
            'schema':
                'orch-dork/production-graph-worker-acknowledgement/v1',
            'scope': 'first_successful_spec_acknowledgement_prefix',
            'graph_mapping': graph_mapping,
            'model_state': successor_facts,
            'native_observation': {
                'logical_worker_id': 'spec',
                'worker_id': spec_worker,
                'session_id': spec_worker,
                'observer_id': root_id,
                'source_sha256': observation['source_sha256'],
                'report_sha256': observation['report_sha256'],
            },
            'native_pending_acknowledgements': ['standards'],
            'input_sha256': values.canonical_digest([
                first,
                completed,
                _acknowledgement_input_projection(
                    source_bytes, observer_read, advance
                ),
            ]),
            'capture_authenticated': False,
            'host_execution_custody': False,
            'controller_continuation_authorized': False,
            'execution_attested': False,
            'complete_campaign': False,
            'release_authorized': False,
            'qualification_authorized': False,
        })
    except (KeyError, IndexError, TypeError, StopIteration, UnicodeError,
            ValueError, RecursionError) as error:
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_spec_ack_shape'
        ) from error


def compare_first_successful_standards_acknowledgement(
        first_spawn, completed_second_step, spec_acknowledgement_step,
        standards_acknowledgement_step):
    """Map the second exact pre-work receipt without executing continuation."""

    first, completed = rv.freeze([
        first_spawn, completed_second_step,
    ]).to_plain()
    _require(type(spec_acknowledgement_step) is dict
             and set(spec_acknowledgement_step) == {
                 'raw_rollout_bytes', 'observer_read', 'advance_report',
             }
             and type(spec_acknowledgement_step['raw_rollout_bytes']) is bytes,
             'standards_ack_spec_input_shape')
    _require(type(standards_acknowledgement_step) is dict
             and set(standards_acknowledgement_step) == {
                 'raw_rollout_bytes', 'observer_reads', 'advance_report',
                 'action_source',
             }, 'standards_ack_input_shape')
    standards_source = standards_acknowledgement_step['raw_rollout_bytes']
    _require(type(standards_source) is bytes,
             'standards_ack_source_type')
    spec_source = spec_acknowledgement_step['raw_rollout_bytes']
    spec_observer_read, spec_advance = rv.freeze([
        spec_acknowledgement_step['observer_read'],
        spec_acknowledgement_step['advance_report'],
    ]).to_plain()
    observer_reads, advance, action_source = rv.freeze([
        standards_acknowledgement_step['observer_reads'],
        standards_acknowledgement_step['advance_report'],
        standards_acknowledgement_step['action_source'],
    ]).to_plain()
    try:
        spec_mapping = compare_first_successful_spec_acknowledgement(
            first, completed, {
                'raw_rollout_bytes': spec_source,
                'observer_read': spec_observer_read,
                'advance_report': spec_advance,
            },
        ).to_plain()
        completed_mapping = compare_completed_second_spawn(
            first, completed).to_plain()
        _require(type(observer_reads) is list and len(observer_reads) == 2
                 and all(type(item) is dict and set(item) == {
                     'session_id', 'observer_id', 'report',
                 } for item in observer_reads),
                 'standards_ack_observer_reads_shape')
        _require(_same(observer_reads[0], spec_observer_read),
                 'standards_ack_spec_reread')
        _require(
            successor.validate_issue94_successor_action_advance_report(
                advance).get('valid') is True,
            'standards_ack_advance_report',
        )
        _require(advance['schema'] == successor.ACTION_ADVANCE_REPORT_SCHEMA,
                 'standards_ack_advance_schema')

        first_action = first['first_action_report']['action']
        standards_action = completed['action']
        root_id = first_action['actor_thread_id']
        workers = completed_mapping['native_worker_ids']
        actions = {'spec': first_action, 'standards': standards_action}
        sources = {'spec': spec_source, 'standards': standards_source}
        reads = dict(zip(('spec', 'standards'), observer_reads))
        observations = {}
        receipts = {}
        dispatches = {}
        for lane in ('spec', 'standards'):
            source_bytes = sources[lane]
            lines = source_bytes.splitlines()
            _require(0 < len(lines) <= 32 and all(lines)
                     and len(source_bytes) <= 128 * 1024,
                     'standards_ack_' + lane + '_source_bound')
            records = [_strict_json_record(line) for line in lines]
            _require(_exact_pre_work_records(records),
                     'standards_ack_' + lane + '_source_records')
            observer_read = reads[lane]
            worker_id = workers[lane]
            _require(observer_read['session_id'] == worker_id
                     and observer_read['observer_id'] == root_id,
                     'standards_ack_' + lane + '_observer_identity')
            rebuilt = successor.routing_verify.build_session_runtime_observation(
                source_bytes,
                session_id=worker_id,
                observer_id=root_id,
            )
            observation = observer_read['report']
            _require(_same(observation, rebuilt)
                     and successor.routing_verify.validate_session_runtime_observation(
                         observation).get('valid') is True,
                     'standards_ack_' + lane + '_observation_rebuild')
            route = observation['route']
            action = actions[lane]
            _require(observation['observer_id'] == root_id
                     and observation['source_pointer']
                     == 'session://' + worker_id
                     and observation['skipped_lines'] == 0
                     and route == {
                         'session_id': worker_id,
                         'model': action['tool_input']['model'],
                         'effort': action['tool_input']['reasoning_effort'],
                         'context_policy': 'none',
                         'inherited_history': False,
                     }
                     and observation['usage']['status'] == 'observed'
                     and observation['usage']['tool_calls'] == 0,
                     'standards_ack_' + lane + '_route')
            dispatch = _strict_json_record(action['tool_input']['message'])
            _require(type(dispatch) is dict
                     and dispatch['schema']
                     == 'orch-dork/native-task-dispatch/v1'
                     and dispatch['controller_id'] == action['controller_id']
                     and dispatch['lane_id'] == lane
                     and dispatch['task_spec']['task_spec_sha256']
                     == dispatch['pre_work_receipt']['task_spec_sha256'],
                     'standards_ack_' + lane + '_dispatch')
            expected_receipt = successor.route_policy.task_spec_pre_work_receipt(
                logical_lane_id=lane,
                task_spec_sha256=dispatch['task_spec'][
                    'task_spec_sha256'],
            )
            terminal_messages = []
            for record in records:
                payload = record.get('payload')
                if (record.get('type') != 'event_msg'
                        or type(payload) is not dict):
                    continue
                if payload.get('type') == 'agent_message':
                    message = payload.get('message')
                elif payload.get('type') == 'task_complete':
                    message = payload.get('last_agent_message')
                else:
                    continue
                if type(message) is str and message.strip():
                    terminal_messages.append(_strict_json_record(message))
            _require(_same(dispatch['pre_work_receipt'], expected_receipt)
                     and observation['terminal_schema']
                     == successor.route_policy.TASK_SPEC_PRE_WORK_RECEIPT_SCHEMA
                     and observation['terminal_json_sha256']
                     == successor.route_policy.canonical_sha256(
                         expected_receipt)
                     and len(terminal_messages) == 1
                     and _same(terminal_messages[0], expected_receipt),
                     'standards_ack_' + lane + '_pre_work_receipt')
            observations[lane] = observation
            receipts[lane] = expected_receipt
            dispatches[lane] = dispatch

        _require(advance['pre_turn_report_sha256']
                 == spec_advance['pre_turn_report_sha256']
                 and _same(advance['source_roots'],
                           spec_advance['source_roots'])
                 and _same(advance['authority_before'],
                           spec_advance['authority_before']),
                 'standards_ack_prefix_provenance')
        _require(action_source['source_root']
                 == advance['source_roots']['source'],
                 'standards_ack_action_source_provenance')
        authority = advance['authority_before']
        acknowledgements = advance['acknowledgements']
        ack_core = {key: value for key, value in acknowledgements.items()
                    if key != 'acknowledgements_sha256'}
        expected_runtime_rows = [{
            'logical_worker_id': lane,
            'worker_id': workers[lane],
            'session_id': workers[lane],
            'observation': observations[lane],
        } for lane in ('spec', 'standards')]
        _require(set(acknowledgements) == {
            'schema', 'state', 'expected_lane_ids', 'observed_lane_ids',
            'pending_lane_ids', 'runtime_observations',
            'acknowledgements_sha256',
        }
                 and acknowledgements['schema']
                 == successor.WORKER_ACKNOWLEDGEMENTS_SCHEMA
                 and acknowledgements['state'] == 'ACCEPTED'
                 and acknowledgements['expected_lane_ids']
                 == ['spec', 'standards']
                 and acknowledgements['observed_lane_ids']
                 == ['spec', 'standards']
                 and acknowledgements['pending_lane_ids'] == []
                 and _same(acknowledgements['runtime_observations'],
                           expected_runtime_rows)
                 and acknowledgements['acknowledgements_sha256']
                 == values.canonical_digest(ack_core),
                 'standards_ack_acknowledgements')

        _require(set(advance) == {
            'schema', 'status', 'decision', 'issues',
            'pre_turn_report_sha256', 'source_roots', 'authority_before',
            'durable_hook_report', 'controller_transitions',
            'acknowledgements', 'worker_results', 'review_packet', 'action',
            'boundary', 'provider_free', 'counters', 'report_sha256',
        } and advance['status'] == 'PASS'
            and advance['decision'] == 'READY_FOR_NEXT_ACTION'
            and advance['issues'] == []
            and advance['durable_hook_report'] is None
            and len(advance['controller_transitions']) == 1
            and advance['worker_results'] == []
            and advance['review_packet'] is None
            and advance['provider_free'] is True,
                 'standards_ack_bridge_report')
        transition = advance['controller_transitions'][0]
        _require(type(transition) is dict
                 and set(transition) == {'program', 'report'},
                 'standards_ack_transition_shape')
        program, controller_report = (
            transition['program'], transition['report'])
        _require(native_contract.validate_governed_native_controller_report(
            controller_report).get('valid') is True,
                 'standards_ack_controller_report')
        _require(set(program) == {
            'schema', 'controller_id', 'operation', 'expected_cursor',
            'payload',
        } and program['schema'] == native_contract.PROGRAM_SCHEMA
            and program['controller_id'] == first_action['controller_id']
            and program['operation'] == 'stage'
            and _same(program['expected_cursor'], authority['tip'])
            and type(program['payload']) is dict
            and set(program['payload']) == {
                'stage_program', 'proposed_action',
            }, 'standards_ack_stage_envelope')
        stage_program = program['payload']['stage_program']
        proposal = program['payload']['proposed_action']
        _require(type(stage_program) is dict and set(stage_program) == {
            'schema', 'operation', 'identity', 'predecessor_receipt',
            'payload',
        } and stage_program['schema']
            == successor.governed_attempt.PROGRAM_SCHEMA
            and stage_program['operation'] == 'worker_start',
                 'standards_ack_worker_start_program')
        second_after = completed['advance_report'][
            'controller_transitions'][-1]['report']
        predecessor = second_after['stage_report']['receipt']
        identity = stage_program['identity']
        prior_stage = first['first_action_report']['controller_report'][
            'stage_report']
        generation = prior_stage['receipt']['bindings']['generation']
        expected_identity = {
            'attempt_id': prior_stage['attempt_id'],
            'fresh_task': generation['fresh_task'],
            'installed_version': generation['installed_version'],
            'root_effort': prior_stage['routing']['root']['effort'],
            'root_model': prior_stage['routing']['root']['model'],
            'root_task_id': prior_stage['root_task_id'],
            'run_id': prior_stage['run_id'],
            'source_version': generation['source_version'],
            'task_loaded_version': generation['task_loaded_version'],
        }
        _require(_same(stage_program['predecessor_receipt'], predecessor)
                 and _same(identity, expected_identity)
                 and identity['attempt_id'] == predecessor['attempt_id']
                 and identity['run_id'] == predecessor['run_id'],
                 'standards_ack_worker_start_identity')
        expected_creations = [{
            'logical_worker_id': lane,
            'worker_id': workers[lane],
            'session_id': workers[lane],
            'status': 'created',
            'fresh': True,
            'parent_thread_id': root_id,
        } for lane in ('spec', 'standards')]
        expected_deliveries = []
        delivery_acks = {}
        for lane in ('spec', 'standards'):
            worker_id = workers[lane]
            task_spec_sha256 = dispatches[lane]['task_spec'][
                'task_spec_sha256']
            acknowledgement = {
                'schema': successor.route_policy.TASK_SPEC_ACK_SCHEMA,
                'ack_id': 'issue94-pre-work-' + values.canonical_digest({
                    'receipt': receipts[lane],
                    'worker_id': worker_id,
                    'session_id': worker_id,
                })[:24],
                'task_spec_sha256': task_spec_sha256,
                'logical_lane_id': lane,
                'native_worker_id': worker_id,
                'session_id': worker_id,
                'acknowledged_seq': 1,
                'first_substantial_work_seq': 2,
            }
            delivery_acks[lane] = acknowledgement
            expected_deliveries.append({
                'schema': successor.route_policy.PROGRAM_SCHEMA,
                'operation': 'task_spec_delivery',
                'payload': {
                    'schema': successor.route_policy.TASK_SPEC_DELIVERY_SCHEMA,
                    'expected_task_spec_sha256': task_spec_sha256,
                    'expected_lane_id': lane,
                    'expected_native_worker_id': worker_id,
                    'expected_session_id': worker_id,
                    'prior_ack_ids': [],
                    'acknowledgement': acknowledgement,
                },
            })
        stage_payload = stage_program['payload']
        _require(type(stage_payload) is dict and set(stage_payload) == {
            'creations', 'deliveries', 'route_observations', 'tool_events',
        } and _same(stage_payload['creations'], expected_creations)
            and _same(stage_payload['deliveries'], expected_deliveries)
            and _same(stage_payload['route_observations'],
                      expected_runtime_rows)
            and stage_payload['tool_events'] == [],
                 'standards_ack_worker_start_payload')
        _require(type(proposal) is dict and set(proposal) == {
            'schema', 'action_id', 'kind', 'actor_thread_id',
            'adapter_sha256',
        } and proposal['schema'] == native_contract.ACTION_PROPOSAL_SCHEMA
            and proposal['kind'] == 'continue'
            and proposal['actor_thread_id'] == root_id
            and proposal['adapter_sha256']
            == first_action['adapter_sha256']
            and proposal['adapter_sha256']
            == native_contract.CLOSED_NATIVE_ACTION_ADAPTER_SHA256,
                 'standards_ack_action_proposal')

        action = advance['action']
        stage_report = controller_report['stage_report']
        receipt = stage_report['receipt']
        rebuilt_stage_report = (
            successor.governed_attempt.evaluate_governed_attempt(stage_program)
        )
        expected_action = _expected_worker_start_action(
            controller_id=first_action['controller_id'],
            root_id=root_id,
            cursor=authority['tip'],
            acknowledgements=acknowledgements,
            proposal=proposal,
            receipt=receipt,
            dispatches=dispatches,
            workers=workers,
            action_source=action_source,
        )
        _require(_same(action, controller_report['action'])
                 and _same(action, expected_action)
                 and _same(stage_report, rebuilt_stage_report)
                 and proposal['action_id'] == action['action_id']
                 and action['schema'] == native_contract.ACTION_SCHEMA
                 and action['controller_id'] == first_action['controller_id']
                 and action['actor_thread_id'] == root_id
                 and action['kind'] == 'continue'
                 and action['tool_name'] == 'multi_agent_v1__send_input'
                 and action['lane_ids'] == ['spec']
                 and action['batch_kind'] == 'continue'
                 and action['batch_phase'] == 'primary'
                 and action['batch_index'] == 0
                 and action['batch_size'] == 2
                 and action['batch_lane_ids'] == ['spec', 'standards']
                 and action['batch_failure_outcome'] is None
                 and action['tool_input']['target'] == workers['spec'],
                 'standards_ack_prospective_action')
        _require(type(action['batch_requests']) is list
                 and len(action['batch_requests']) == 2
                 and action['batch_requests_sha256']
                 == successor.route_policy.canonical_sha256(
                     action['batch_requests'])
                 and action['tool_input_sha256']
                 == successor.route_policy.canonical_sha256(
                     action['tool_input'])
                 and _same(action['tool_input'],
                           action['batch_requests'][0]['tool_input']),
                 'standards_ack_action_batch')
        for lane, request in zip(
                ('spec', 'standards'), action['batch_requests']):
            _require(type(request) is dict and set(request) == {
                'kind', 'lane_id', 'tool_name', 'tool_input',
            } and request['kind'] == 'continue'
                and request['lane_id'] == lane
                and request['tool_name'] == 'multi_agent_v1__send_input'
                and request['tool_input']['target'] == workers[lane],
                     'standards_ack_' + lane + '_batch_request')
            continuation = _strict_json_record(
                request['tool_input']['message'])
            _require(type(continuation) is dict
                     and continuation['schema']
                     == 'orch-dork/native-continuation/v1'
                     and continuation['controller_id']
                     == first_action['controller_id']
                     and continuation['lane_id'] == lane
                     and continuation['task_spec_sha256']
                     == dispatches[lane]['task_spec']['task_spec_sha256']
                     and continuation['predecessor_receipt_sha256']
                     == action['predecessor_receipt_sha256']
                     and continuation['checkpoint_submission']['sequence'] == 1
                     and continuation['checkpoint_submission'][
                         'task_spec_sha256']
                     == continuation['task_spec_sha256'],
                     'standards_ack_' + lane + '_continuation_packet')

        _require(controller_report['status'] == 'PASS'
                 and controller_report['decision'] == 'ACTION_AUTHORIZED'
                 and controller_report['issues'] == []
                 and controller_report['controller_id']
                 == first_action['controller_id']
                 and controller_report['next_stage_action'] == 'continue'
                 and controller_report['native_calls'] == 0
                 and controller_report['native_action_authorizations'] == 1
                 and controller_report['authority_grants_minted'] == 0
                 and controller_report['credential_reads'] == 0
                 and controller_report['hosted_calls'] == 0
                 and controller_report['model_calls'] == 0
                 and controller_report['task_creations'] == 0
                 and controller_report['worker_creations'] == 0
                 and controller_report['provider_free'] is True
                 and controller_report['controller_state'] == {
                     'action_authorized': True,
                     'action_outcome': None,
                     'cleanup_required': False,
                     'grant_state': 'AUTHORIZED',
                     'pending_intent': False,
                     'terminal': False,
                 }
                 and controller_report['cursor']['run_id']
                 == authority['tip']['run_id']
                 and controller_report['cursor']['seq']
                 == authority['tip']['seq'] + 2
                 and controller_report['cursor']['event_hash']
                 != authority['tip']['event_hash'],
                 'standards_ack_controller_transition')
        _require(stage_report['status'] == 'PASS'
                 and stage_report['operation'] == 'worker_start'
                 and stage_report['disposition'] == 'WORK_AUTHORIZED'
                 and stage_report['final_verdict'] == 'WORK_AUTHORIZED'
                 and stage_report['next_action'] == 'continue'
                 and stage_report['work_authorized'] is True
                 and stage_report['spawn_authorized'] is False
                 and stage_report['continuation_authorized'] is False
                 and stage_report['terminal_claim_permitted'] is False
                 and stage_report['provider_free'] is True
                 and stage_report['hosted_calls'] == 0
                 and stage_report['model_calls'] == 0
                 and stage_report['live_task_operations'] == 0
                 and stage_report['automatic_fallbacks'] == 0
                 and stage_report['automatic_replacements'] == 0
                 and stage_report['automatic_retries'] == 0
                 and receipt['stage'] == 'worker_start'
                 and receipt['status'] == 'AUTHORIZED'
                 and receipt['next_action'] == 'continue'
                 and receipt['predecessor_receipt_sha256']
                 == predecessor['receipt_sha256']
                 and action['predecessor_receipt_sha256']
                 == receipt['receipt_sha256'],
                 'standards_ack_worker_start_report')
        lane_bindings = {
            row['logical_worker_id']: row
            for row in receipt['bindings']['lane_bindings']
        }
        graph_lanes = {
            row['logical_worker_id']: row
            for row in stage_report['graph']['lanes']
        }
        _require(set(lane_bindings) == {'spec', 'standards'}
                 and set(graph_lanes) == {'spec', 'standards'},
                 'standards_ack_worker_start_lanes')
        for lane in ('spec', 'standards'):
            expected_binding = {
                'allowed_tools': dispatches[lane]['task_spec'][
                    'allowed_tools'],
                'delivery_ack_sha256': values.canonical_digest(
                    delivery_acks[lane]),
                'logical_worker_id': lane,
                'route_observation_sha256': observations[lane][
                    'report_sha256'],
                'session_id': workers[lane],
                'task_spec_sha256': dispatches[lane]['task_spec'][
                    'task_spec_sha256'],
                'worker_id': workers[lane],
            }
            _require(_same(lane_bindings[lane], expected_binding)
                     and _same(graph_lanes[lane], {
                         **expected_binding,
                         'dependencies': dispatches[lane]['task_spec'][
                             'dependencies'],
                         'executor': 'subagent',
                     }), 'standards_ack_' + lane + '_stage_binding')

        _require(advance['boundary'] == {
            'native_action_called_by_bridge': False,
            'native_action_observed_by_bridge': False,
            'worker_acknowledgements_observed': 2,
            'controller_stage_advanced': True,
            'next_action': 'multi_agent_v1__send_input',
        } and advance['counters'] == {
            'controller_observations': 0,
            'controller_stages': 1,
            'session_runtime_observations': 2,
            'hosted_calls': 0,
            'model_calls': 0,
            'native_actions': 0,
            'network_calls': 0,
            'provider_calls': 0,
            'task_creations': 0,
            'worker_creations': 0,
        }, 'standards_ack_unexecuted_boundary')

        state = rv.freeze(spec_mapping['model_state'])
        source_id = explorer.state_identity(state)
        _require(source_id == spec_mapping['graph_mapping'][
            'production_boundary']['target_state_id'],
                 'standards_ack_graph_source')
        choice = {
            'stage': 'ack', 'lane': 'standards',
            'outcome': 'accepted', 'variant': 'SUCCESS',
        }
        events = [event for event in model.outgoing_stimuli(state).to_plain()
                  if _same(explorer.abstract_event(event), choice)]
        _require(len(events) == 1, 'standards_ack_model_choice')
        event = events[0]
        reduction = model.reduce(state, event).to_plain()
        successor_state = rv.freeze(reduction['successor'])
        successor_facts = successor_state.to_plain()
        target_id = explorer.state_identity(successor_state)
        directive = model.legal_directive(successor_state).to_plain()
        directive_action = directive['payload']['action']
        _require(_same(reduction['directive'], directive)
                 and successor_facts['stage'] == 'continue.spec'
                 and successor_facts['lanes']['spec']['acknowledgement']
                 == 'SUCCESS'
                 and successor_facts['lanes']['standards'][
                     'acknowledgement'] == 'SUCCESS'
                 and directive['kind'] == 'action'
                 and directive['payload']['detail'] == 'send_input'
                 and directive_action['method'] == 'send_input'
                 and directive_action['lane'] == 'spec'
                 and directive_action['controller_returned'] is True,
                 'standards_ack_model_continuation')
        graph_mapping = {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': {
                'kind':
                    'successful_standards_acknowledgement_to_spec_continuation',
                'choice': choice,
                'source_state_id': source_id,
                'transition_id': explorer.edge_identity(
                    source_id, event, target_id),
                'target_state_id': target_id,
            },
            'gap': {
                'status': 'PREFIX_ONLY',
                'observed_boundary_count': 4,
                'next_uncovered_choices': [
                    explorer.abstract_event(item) for item in
                    model.outgoing_stimuli(successor_state).to_plain()
                ],
                'production_graph_complete': False,
            },
        }
        return rv.freeze({
            'schema':
                'orch-dork/production-graph-complete-worker-acknowledgements/v1',
            'scope': 'two_successful_worker_acknowledgements_prefix',
            'graph_mapping': graph_mapping,
            'model_state': successor_facts,
            'native_observations': [{
                'logical_worker_id': lane,
                'worker_id': workers[lane],
                'session_id': workers[lane],
                'observer_id': root_id,
                'source_sha256': observations[lane]['source_sha256'],
                'report_sha256': observations[lane]['report_sha256'],
            } for lane in ('spec', 'standards')],
            'native_pending_acknowledgements': [],
            'native_prospective_action': {
                'tool_name': action['tool_name'],
                'kind': action['kind'],
                'lane_ids': action['lane_ids'],
                'target': action['tool_input']['target'],
                'execution_observed_in_bridge_report': False,
            },
            'input_sha256': values.canonical_digest([
                first,
                completed,
                _acknowledgement_input_projection(
                    spec_source, spec_observer_read, spec_advance),
                _complete_acknowledgement_input_projection(
                    standards_source, observer_reads, advance, action_source),
            ]),
            'capture_authenticated': False,
            'host_execution_custody': False,
            'controller_continuation_authorized': False,
            'execution_attested': False,
            'complete_campaign': False,
            'release_authorized': False,
            'qualification_authorized': False,
        })
    except (KeyError, IndexError, TypeError, StopIteration, UnicodeError,
            ValueError, RecursionError) as error:
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_standards_ack_shape'
        ) from error


def compare_completed_spec_checkpoint_continuation(
        first_spawn, completed_second_step, spec_acknowledgement_step,
        standards_acknowledgement_step, continuation_step):
    """Map the observed spec checkpoint submission to its deferred graph edge."""

    prefix = compare_first_successful_standards_acknowledgement(
        first_spawn,
        completed_second_step,
        spec_acknowledgement_step,
        standards_acknowledgement_step,
    ).to_plain()
    continuation = rv.freeze(continuation_step).to_plain()
    standards_advance = rv.freeze(
        standards_acknowledgement_step['advance_report']).to_plain()
    try:
        expected_action = standards_advance['action']
        previous = standards_advance['controller_transitions'][-1]['report']
        checked = _validated_action_step(
            continuation,
            expected_action,
            previous,
            action_kind='continue',
            lane_ids=['spec'],
            outcome='completed',
            label='spec_checkpoint_continuation',
        )
        action = checked['action']
        raw = checked['raw']
        advance = checked['advance']
        after = checked['controller']
        normalized = checked['normalized']
        _require(action['kind'] == 'continue'
                 and action['tool_name'] == 'multi_agent_v1__send_input'
                 and action['lane_ids'] == ['spec']
                 and action['batch_kind'] == 'continue'
                 and action['batch_phase'] == 'primary'
                 and action['batch_index'] == 0
                 and action['batch_size'] == 2
                 and action['batch_lane_ids'] == ['spec', 'standards']
                 and action['batch_failure_outcome'] is None,
                 'spec_checkpoint_continuation_action')
        _require(type(raw) is dict and set(raw) == {'submission_id'}
                 and normalized == {
                     'schema': native_result.NATIVE_CONTINUE_RESULT_SCHEMA,
                     'submissions': [{
                         'lane_id': 'spec',
                         'submission': {
                             'submission_id': raw['submission_id'],
                         },
                     }],
                 }, 'spec_checkpoint_continuation_result')
        _require(advance['pre_turn_report_sha256']
                 == standards_advance['pre_turn_report_sha256']
                 and _same(advance['source_roots'],
                           standards_advance['source_roots']),
                 'spec_checkpoint_continuation_provenance')

        next_action = advance['action']
        expected_next_action = _expected_next_batch_action(action)
        _require(_same(next_action, expected_next_action)
                 and _same(after['action'], expected_next_action)
                 and next_action['kind'] == 'continue'
                 and next_action['tool_name']
                 == 'multi_agent_v1__send_input'
                 and next_action['lane_ids'] == ['standards']
                 and next_action['batch_index'] == 1
                 and next_action['tool_input']
                 == action['batch_requests'][1]['tool_input'],
                 'spec_checkpoint_continuation_next_action')
        authorized_state = {
            'action_authorized': True,
            'action_outcome': None,
            'cleanup_required': False,
            'grant_state': 'AUTHORIZED',
            'pending_intent': False,
            'terminal': False,
        }
        _require(after['status'] == 'PASS'
                 and after['decision'] == 'ACTION_AUTHORIZED'
                 and after['issues'] == []
                 and after['controller_state'] == authorized_state
                 and after['next_stage_action'] == 'continue'
                 and after['native_action_authorizations'] == 1
                 and after['authority_grants_minted'] == 0
                 and after['credential_reads'] == 0
                 and after['hosted_calls'] == 0
                 and after['model_calls'] == 0
                 and after['native_calls'] == 0
                 and after['task_creations'] == 0
                 and after['worker_creations'] == 0
                 and after['provider_free'] is True
                 and _same(after['stage_report'], previous['stage_report']),
                 'spec_checkpoint_continuation_controller')
        acknowledgement_core = {
            'schema': successor.WORKER_ACKNOWLEDGEMENTS_SCHEMA,
            'state': 'NOT_APPLICABLE',
            'expected_lane_ids': [],
            'observed_lane_ids': [],
            'pending_lane_ids': [],
            'runtime_observations': [],
        }
        expected_acknowledgements = {
            **acknowledgement_core,
            'acknowledgements_sha256': values.canonical_digest(
                acknowledgement_core),
        }
        _require(set(advance) == {
            'schema', 'status', 'decision', 'issues',
            'pre_turn_report_sha256', 'source_roots', 'authority_before',
            'durable_hook_report', 'controller_transitions',
            'acknowledgements', 'worker_results', 'review_packet', 'action',
            'boundary', 'provider_free', 'counters', 'report_sha256',
        } and advance['schema'] == successor.ACTION_ADVANCE_REPORT_SCHEMA
            and advance['status'] == 'PASS'
            and advance['decision'] == 'READY_FOR_NEXT_ACTION'
            and advance['issues'] == []
            and _same(advance['acknowledgements'],
                      expected_acknowledgements)
            and advance['worker_results'] == []
            and advance['review_packet'] is None
            and advance['provider_free'] is True,
                 'spec_checkpoint_continuation_bridge_report')
        _require(advance['boundary'] == {
            'native_action_called_by_bridge': False,
            'native_action_observed_by_bridge': True,
            'worker_acknowledgements_observed': 0,
            'controller_stage_advanced': False,
            'next_action': 'multi_agent_v1__send_input',
        } and advance['counters'] == {
            'controller_observations': 1,
            'controller_stages': 0,
            'session_runtime_observations': 0,
            'hosted_calls': 0,
            'model_calls': 0,
            'native_actions': 0,
            'network_calls': 0,
            'provider_calls': 0,
            'task_creations': 0,
            'worker_creations': 0,
        }, 'spec_checkpoint_continuation_boundary')

        state = rv.freeze(prefix['model_state'])
        source_id = explorer.state_identity(state)
        _require(source_id == prefix['graph_mapping'][
            'production_boundary']['target_state_id'],
                 'spec_checkpoint_continuation_graph_source')
        choice = {
            'stage': 'continue.spec', 'lane': 'spec',
            'outcome': 'accepted', 'variant': 'checkpoint_deferred',
        }
        events = [
            event for event in model.outgoing_stimuli(state).to_plain()
            if _same(explorer.abstract_event(event), choice)
        ]
        _require(len(events) == 1,
                 'spec_checkpoint_continuation_model_choice')
        event = events[0]
        reduction = model.reduce(state, event).to_plain()
        successor_state = rv.freeze(reduction['successor'])
        successor_facts = successor_state.to_plain()
        target_id = explorer.state_identity(successor_state)
        directive = model.legal_directive(successor_state).to_plain()
        directive_action = directive['payload']['action']
        _require(_same(reduction['directive'], directive)
                 and successor_facts['stage'] == 'continue.standards'
                 and successor_facts['progress_admission'] == 'pending'
                 and successor_facts['lanes']['spec']['checkpoint'] is None
                 and successor_facts['lanes']['spec'][
                     'checkpoint_continuation'] is not None
                 and successor_facts['lanes']['spec']['typed_result'] is None
                 and directive['kind'] == 'action'
                 and directive['payload']['detail'] == 'send_input'
                 and directive_action['method'] == 'send_input'
                 and directive_action['lane'] == 'standards'
                 and directive_action['controller_returned'] is True,
                 'spec_checkpoint_continuation_model_target')
        graph_mapping = {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': {
                'kind':
                    'completed_spec_checkpoint_deferred_to_standards_continuation',
                'choice': choice,
                'source_state_id': source_id,
                'transition_id': explorer.edge_identity(
                    source_id, event, target_id),
                'target_state_id': target_id,
            },
            'gap': {
                'status': 'PREFIX_ONLY',
                'observed_boundary_count': 5,
                'next_uncovered_choices': [
                    explorer.abstract_event(item) for item in
                    model.outgoing_stimuli(successor_state).to_plain()
                ],
                'production_graph_complete': False,
            },
        }
        return rv.freeze({
            'schema':
                'orch-dork/production-graph-spec-checkpoint-continuation/v1',
            'scope':
                'completed_spec_checkpoint_deferred_continuation_prefix',
            'graph_mapping': graph_mapping,
            'model_state': successor_facts,
            'native_submission_id': raw['submission_id'],
            'native_prospective_action': {
                'tool_name': next_action['tool_name'],
                'kind': next_action['kind'],
                'lane_ids': next_action['lane_ids'],
                'target': next_action['tool_input']['target'],
                'execution_observed_in_bridge_report': False,
            },
            'input_sha256': values.canonical_digest([
                prefix['input_sha256'], continuation,
            ]),
            'capture_authenticated': False,
            'host_execution_custody': False,
            'controller_continuation_authorized': False,
            'execution_attested': False,
            'complete_campaign': False,
            'release_authorized': False,
            'qualification_authorized': False,
        })
    except (KeyError, IndexError, TypeError, StopIteration, ValueError) as error:
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_spec_continuation_shape'
        ) from error


def compare_completed_standards_checkpoint_continuation(
        first_spawn, completed_second_step, spec_acknowledgement_step,
        standards_acknowledgement_step, spec_continuation_step,
        standards_continuation_step):
    """Map the observed standards submission to the checkpoint-wait edge."""

    prefix = compare_completed_spec_checkpoint_continuation(
        first_spawn,
        completed_second_step,
        spec_acknowledgement_step,
        standards_acknowledgement_step,
        spec_continuation_step,
    ).to_plain()
    spec_continuation = rv.freeze(spec_continuation_step).to_plain()
    continuation = rv.freeze(standards_continuation_step).to_plain()
    try:
        spec_advance = spec_continuation['advance_report']
        expected_action = _expected_next_batch_action(
            spec_continuation['action'])
        previous = spec_advance['controller_transitions'][-1]['report']
        checked = _validated_action_step(
            continuation,
            expected_action,
            previous,
            action_kind='continue',
            lane_ids=['standards'],
            outcome='completed',
            label='standards_checkpoint_continuation',
        )
        action = checked['action']
        raw = checked['raw']
        advance = checked['advance']
        after = checked['controller']
        normalized = checked['normalized']
        _require(action['kind'] == 'continue'
                 and action['tool_name'] == 'multi_agent_v1__send_input'
                 and action['lane_ids'] == ['standards']
                 and action['batch_kind'] == 'continue'
                 and action['batch_phase'] == 'primary'
                 and action['batch_index'] == 1
                 and action['batch_size'] == 2
                 and action['batch_lane_ids'] == ['spec', 'standards']
                 and action['batch_failure_outcome'] is None,
                 'standards_checkpoint_continuation_action')
        _require(type(raw) is dict and set(raw) == {'submission_id'}
                 and normalized == {
                     'schema': native_result.NATIVE_CONTINUE_RESULT_SCHEMA,
                     'submissions': [{
                         'lane_id': 'standards',
                         'submission': {
                             'submission_id': raw['submission_id'],
                         },
                     }],
                 }, 'standards_checkpoint_continuation_result')
        _require(advance['pre_turn_report_sha256']
                 == spec_advance['pre_turn_report_sha256']
                 and _same(advance['source_roots'],
                           spec_advance['source_roots']),
                 'standards_checkpoint_continuation_provenance')

        observed_state = {
            'action_authorized': False,
            'action_outcome': 'completed',
            'cleanup_required': False,
            'grant_state': None,
            'pending_intent': False,
            'terminal': False,
        }
        _require(after['status'] == 'PASS'
                 and after['decision'] == 'ACTION_OBSERVED'
                 and after['issues'] == []
                 and after['controller_state'] == observed_state
                 and after['action'] is None
                 and after['next_stage_action'] == 'continue'
                 and after['native_action_authorizations'] == 0
                 and after['authority_grants_minted'] == 0
                 and after['credential_reads'] == 0
                 and after['hosted_calls'] == 0
                 and after['model_calls'] == 0
                 and after['native_calls'] == 0
                 and after['task_creations'] == 0
                 and after['worker_creations'] == 0
                 and after['provider_free'] is True
                 and _same(after['stage_report'], previous['stage_report']),
                 'standards_checkpoint_continuation_controller')
        acknowledgement_core = {
            'schema': successor.WORKER_ACKNOWLEDGEMENTS_SCHEMA,
            'state': 'NOT_APPLICABLE',
            'expected_lane_ids': [],
            'observed_lane_ids': [],
            'pending_lane_ids': [],
            'runtime_observations': [],
        }
        expected_acknowledgements = {
            **acknowledgement_core,
            'acknowledgements_sha256': values.canonical_digest(
                acknowledgement_core),
        }
        _require(set(advance) == {
            'schema', 'status', 'decision', 'issues',
            'pre_turn_report_sha256', 'source_roots', 'authority_before',
            'durable_hook_report', 'controller_transitions',
            'acknowledgements', 'worker_results', 'review_packet', 'action',
            'boundary', 'provider_free', 'counters', 'report_sha256',
        } and advance['schema'] == successor.ACTION_ADVANCE_REPORT_SCHEMA
            and advance['status'] == 'PASS'
            and advance['decision'] == 'AWAITING_WORKER_CHECKPOINTS'
            and advance['issues'] == []
            and _same(advance['acknowledgements'],
                      expected_acknowledgements)
            and advance['worker_results'] == []
            and advance['review_packet'] is None
            and advance['action'] is None
            and advance['provider_free'] is True,
                 'standards_checkpoint_continuation_bridge_report')
        expected_boundary = {
            'native_action_called_by_bridge': False,
            'native_action_observed_by_bridge': True,
            'worker_acknowledgements_observed': 0,
            'controller_stage_advanced': False,
            'next_action':
                'mcp__orch_dork__advance_issue94_successor_after_native_action',
        }
        _require(advance['boundary'] == expected_boundary
                 and advance['counters'] == {
                     'controller_observations': 1,
                     'controller_stages': 0,
                     'session_runtime_observations': 0,
                     'hosted_calls': 0,
                     'model_calls': 0,
                     'native_actions': 0,
                     'network_calls': 0,
                     'provider_calls': 0,
                     'task_creations': 0,
                     'worker_creations': 0,
                 }, 'standards_checkpoint_continuation_boundary')

        state = rv.freeze(prefix['model_state'])
        source_id = explorer.state_identity(state)
        _require(source_id == prefix['graph_mapping'][
            'production_boundary']['target_state_id'],
                 'standards_checkpoint_continuation_graph_source')
        choice = {
            'stage': 'continue.standards', 'lane': 'standards',
            'outcome': 'accepted', 'variant': 'checkpoint_deferred',
        }
        events = [
            event for event in model.outgoing_stimuli(state).to_plain()
            if _same(explorer.abstract_event(event), choice)
        ]
        _require(len(events) == 1,
                 'standards_checkpoint_continuation_model_choice')
        event = events[0]
        reduction = model.reduce(state, event).to_plain()
        successor_state = rv.freeze(reduction['successor'])
        successor_facts = successor_state.to_plain()
        target_id = explorer.state_identity(successor_state)
        directive = model.legal_directive(successor_state).to_plain()
        bindings = directive['payload']['bindings']
        _require(_same(reduction['directive'], directive)
                 and successor_facts['stage'] == 'checkpoint.spec'
                 and successor_facts['phase'] == 'worker_progress'
                 and successor_facts['progress_admission'] == 'pending'
                 and successor_facts['action'] is None
                 and successor_facts['aggregation'] == 'pending'
                 and all(
                     successor_facts['lanes'][lane]['capacity'] == 'occupied'
                     and successor_facts['lanes'][lane]['checkpoint'] is None
                     and successor_facts['lanes'][lane][
                         'checkpoint_continuation'] is not None
                     and successor_facts['lanes'][lane][
                         'typed_result'] is None
                     for lane in ('spec', 'standards')
                 )
                 and directive['kind'] == 'wait_for_observation'
                 and directive['payload']['detail'] == 'worker_progress'
                 and directive['payload']['evidence']
                 == successor_facts['result']
                 and [(item['lane'], item['stage']) for item in bindings]
                 == [('spec', 'checkpoint.spec'),
                     ('standards', 'checkpoint.standards')],
                 'standards_checkpoint_continuation_model_target')
        graph_mapping = {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': {
                'kind':
                    'completed_standards_checkpoint_deferred_to_checkpoint_wait',
                'choice': choice,
                'source_state_id': source_id,
                'transition_id': explorer.edge_identity(
                    source_id, event, target_id),
                'target_state_id': target_id,
            },
            'gap': {
                'status': 'PREFIX_ONLY',
                'observed_boundary_count': 6,
                'next_uncovered_choices': [
                    explorer.abstract_event(item) for item in
                    model.outgoing_stimuli(successor_state).to_plain()
                ],
                'production_graph_complete': False,
            },
        }
        return rv.freeze({
            'schema':
                'orch-dork/production-graph-standards-checkpoint-continuation/v1',
            'scope':
                'completed_standards_checkpoint_deferred_continuation_prefix',
            'graph_mapping': graph_mapping,
            'model_state': successor_facts,
            'native_submission_id': raw['submission_id'],
            'native_checkpoint_wait': {
                'decision': advance['decision'],
                'action': None,
                'next_action': advance['boundary']['next_action'],
                'checkpoint_execution_observed_in_bridge_report': False,
            },
            'input_sha256': values.canonical_digest([
                prefix['input_sha256'], continuation,
            ]),
            'capture_authenticated': False,
            'host_execution_custody': False,
            'controller_continuation_authorized': False,
            'execution_attested': False,
            'complete_campaign': False,
            'release_authorized': False,
            'qualification_authorized': False,
        })
    except (KeyError, IndexError, TypeError, StopIteration, ValueError) as error:
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_standards_continuation_shape'
        ) from error


def compare_failed_second_spawn(first_spawn, failed_second_step):
    """Map one actual failed standards spawn to its exact compensation edge."""
    first, failed = rv.freeze([first_spawn, failed_second_step]).to_plain()
    _require(type(first) is dict and set(first) == {
        'first_action_report', 'raw_response', 'pre_hook_report',
        'post_hook_report', 'advance_report',
    }, 'first_input_shape')
    _require(type(failed) is dict and set(failed) == {
        'action', 'raw_response', 'pre_hook_report', 'post_hook_report',
        'advance_report',
    }, 'failed_input_shape')
    prefix = compare_first_spawn(**first).to_plain()
    try:
        first_advance = first['advance_report']
        previous = first_advance['controller_transitions'][-1]['report']
        checked = _validated_action_step(
            failed, first_advance['action'], previous,
            action_kind='spawn', lane_ids=['standards'], outcome='failed',
            label='failed_second',
        )
        action = checked['action']
        advance = checked['advance']
        after = checked['controller']
        _require(_same(checked['raw'], {'status': 'failed'}),
                 'failed_raw_shape')
        _require(action['kind'] == 'spawn'
                 and action['tool_name'] == 'multi_agent_v1__spawn_agent'
                 and action['lane_ids'] == ['standards']
                 and action['batch_kind'] == 'spawn'
                 and action['batch_phase'] == 'primary'
                 and action['batch_index'] == 1
                 and action['batch_size'] == 2
                 and action['batch_lane_ids'] == ['spec', 'standards']
                 and action['batch_failure_outcome'] is None,
                 'second_action')
        _require(advance['pre_turn_report_sha256']
                 == first_advance['pre_turn_report_sha256']
                 and _same(advance['source_roots'], first_advance['source_roots']),
                 'prefix_provenance')
        compensation = advance['action']
        _require(_same(compensation, after['action'])
                 and compensation['kind'] == 'stop'
                 and compensation['tool_name'] == 'multi_agent_v1__close_agent'
                 and compensation['lane_ids'] == ['spec']
                 and compensation['batch_kind'] == 'spawn'
                 and compensation['batch_phase'] == 'compensation'
                 and compensation['batch_index'] == 0
                 and compensation['batch_size'] == 1
                 and compensation['batch_lane_ids'] == ['spec', 'standards']
                 and compensation['batch_failure_outcome'] == 'failed'
                 and compensation['batch_id'] == action['batch_id']
                 and compensation['tool_input']
                 == {'target': prefix['native_worker_id']},
                 'compensation_action')
        evidence_rows = advance['spawn_compensation_evidence']['action_evidence']
        first_action = first['first_action_report']['action']
        _require(len(evidence_rows) == 2
                 and _same(evidence_rows[0]['action'], first_action)
                 and _same(evidence_rows[1]['action'], action)
                 and evidence_rows[1]['result_binding'] is None,
                 'compensation_evidence_actions')
        for evidence, expected_action, step in (
            (evidence_rows[0], first_action, first),
            (evidence_rows[1], action, failed),
        ):
            _require(
                _same(evidence['action'], expected_action)
                and evidence['pretool_report_sha256']
                == step['pre_hook_report']['report_sha256']
                and evidence['posttool_report_sha256']
                == step['post_hook_report']['report_sha256']
                and evidence['posttool_durable_record_sha256']
                == step['advance_report']['durable_hook_report'][
                    'durable_record_sha256'
                ]
                and _same(
                    evidence['result_binding'],
                    step['post_hook_report']['native_controller'][
                        'result_binding'
                    ],
                ),
                'compensation_evidence_step_join',
            )
        first_binding = native_result.spawn_result_binding(
            evidence_rows[0]['result_binding'], ['spec'])
        _require(first_binding is not None
                 and first_binding['lanes'][0]['agent_id']
                 == prefix['native_worker_id'], 'compensation_evidence_target')
        _require(_same(after['stage_report'], previous['stage_report'])
                 and all(_same(action[key], first_action[key]) for key in (
                     'controller_id', 'actor_thread_id', 'adapter_sha256',
                     'predecessor_receipt_sha256', 'batch_schema', 'batch_kind',
                     'batch_size', 'batch_lane_ids', 'batch_requests',
                     'batch_requests_sha256', 'batch_phase',
                     'batch_failure_outcome',
                 )), 'failed_batch_provenance')

        state = rv.freeze(prefix['model_state'])
        source_id = explorer.state_identity(state)
        _require(source_id == prefix['graph_mapping']['production_boundary'][
            'target_state_id'], 'failed_graph_source')
        choice = {
            'stage': 'spawn.standards', 'lane': 'standards',
            'outcome': 'failed', 'variant': 'evidence',
        }
        events = [event for event in model.outgoing_stimuli(state).to_plain()
                  if _same(explorer.abstract_event(event), choice)]
        _require(len(events) == 1, 'failed_model_choice')
        event = events[0]
        reduction = model.reduce(state, event).to_plain()
        successor_state = rv.freeze(reduction['successor'])
        target_id = explorer.state_identity(successor_state)
        directive = model.legal_directive(successor_state).to_plain()
        _require(_same(reduction['directive'], directive)
                 and successor_state.to_plain()['stage'] == 'close.spec'
                 and directive['kind'] == 'action'
                 and directive['payload']['action']['method'] == 'close_agent'
                 and directive['payload']['action']['lane'] == 'spec',
                 'failed_model_compensation')
        boundary = {
            'kind': 'failed_second_spawn_to_compensation_close',
            'choice': choice,
            'source_state_id': source_id,
            'transition_id': explorer.edge_identity(source_id, event, target_id),
            'target_state_id': target_id,
        }
        graph_mapping = {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': boundary,
            'gap': {
                'status': 'PREFIX_ONLY',
                'observed_boundary_count': 2,
                'next_uncovered_choices': [
                    explorer.abstract_event(item) for item in
                    model.outgoing_stimuli(successor_state).to_plain()
                ],
                'production_graph_complete': False,
            },
        }
        return rv.freeze({
            'schema': 'orch-dork/production-graph-failed-second-spawn/v1',
            'scope': 'first_prefix_failed_second_spawn',
            'graph_mapping': graph_mapping,
            'model_state': successor_state.to_plain(),
            'native_compensation_target': compensation['tool_input']['target'],
            'input_sha256': values.canonical_digest([first, failed]),
            'capture_authenticated': False,
            'host_execution_custody': False,
            'controller_continuation_authorized': False,
            'execution_attested': False,
            'complete_campaign': False,
            'release_authorized': False,
            'qualification_authorized': False,
        })
    except (KeyError, IndexError, TypeError, StopIteration, ValueError) as error:
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_failed_shape'
        ) from error


def compare_completed_compensation_close(first_spawn, failed_second_step,
                                         completed_close_step):
    """Map the confirmed compensation close without authorizing failed work."""
    first, failed, closed = rv.freeze(
        [first_spawn, failed_second_step, completed_close_step]
    ).to_plain()
    _require(type(closed) is dict and set(closed) == {
        'action', 'raw_response', 'pre_hook_report', 'post_hook_report',
        'advance_report',
    }, 'close_input_shape')
    failed_prefix = compare_failed_second_spawn(first, failed).to_plain()
    try:
        failed_advance = failed['advance_report']
        previous = failed_advance['controller_transitions'][-1]['report']
        checked = _validated_action_step(
            closed, failed_advance['action'], previous,
            action_kind='stop', lane_ids=['spec'], outcome='completed',
            label='close',
        )
        action = checked['action']
        advance = checked['advance']
        after = checked['controller']
        pre = checked['pre']
        post = checked['post']
        durable = checked['durable']
        normalized = checked['normalized']
        _require(_same(checked['raw'], {'previous_status': 'shutdown'}),
                 'close_raw_shape')
        _require(action['kind'] == 'stop'
                 and action['tool_name'] == 'multi_agent_v1__close_agent'
                 and action['lane_ids'] == ['spec']
                 and action['batch_kind'] == 'spawn'
                 and action['batch_phase'] == 'compensation'
                 and action['batch_index'] == 0
                 and action['batch_size'] == 1
                 and action['batch_lane_ids'] == ['spec', 'standards']
                 and action['batch_failure_outcome'] == 'failed'
                 and action['tool_input'] == {
                     'target': failed_prefix['native_compensation_target']
                 }, 'close_action')
        _require(advance['status'] == 'PASS'
                 and advance['decision'] == 'ACTION_TERMINAL_FAILURE'
                 and advance['issues'] == [] and advance['action'] is None,
                 'close_terminal_wrapper')
        _require(advance['pre_turn_report_sha256']
                 == failed_advance['pre_turn_report_sha256']
                 and _same(advance['source_roots'], failed_advance['source_roots']),
                 'close_provenance')
        _require(after['status'] == 'BLOCKED'
                 and after['decision'] == 'ACTION_TERMINAL_FAILURE'
                 and after['issues'] == ['native_action:failed']
                 and after['action'] is None
                 and after['controller_state'] == {
                     'terminal': False,
                     'pending_intent': False,
                     'action_outcome': 'failed',
                     'action_authorized': False,
                     'grant_state': None,
                     'cleanup_required': True,
                 }, 'close_controller_report')
        evidence_rows = advance['spawn_compensation_evidence']['action_evidence']
        previous_evidence = failed_advance[
            'spawn_compensation_evidence'
        ]['action_evidence']
        _require(len(evidence_rows) == 3
                 and _same(evidence_rows[:2], previous_evidence)
                 and _same(evidence_rows[-1]['action'], action)
                 and evidence_rows[-1]['pretool_report_sha256']
                 == pre['report_sha256']
                 and evidence_rows[-1]['posttool_report_sha256']
                 == post['report_sha256']
                 and evidence_rows[-1]['posttool_durable_record_sha256']
                 == durable['durable_record_sha256']
                 and _same(evidence_rows[-1]['result_binding'], normalized),
                 'close_compensation_evidence')
        _require(_same(after['stage_report'], previous['stage_report'])
                 and advance['boundary'] == {
                     'native_action_called_by_bridge': False,
                     'native_action_observed_by_bridge': True,
                     'worker_acknowledgements_observed': 0,
                     'controller_stage_advanced': False,
                     'next_action': None,
                 }, 'close_terminal_boundary')

        state = rv.freeze(failed_prefix['model_state'])
        source_id = explorer.state_identity(state)
        _require(source_id == failed_prefix['graph_mapping'][
            'production_boundary']['target_state_id'], 'close_graph_source')
        choice = {
            'stage': 'close.spec', 'lane': 'spec',
            'outcome': 'accepted', 'variant': 'evidence',
        }
        events = [event for event in model.outgoing_stimuli(state).to_plain()
                  if _same(explorer.abstract_event(event), choice)]
        _require(len(events) == 1, 'close_model_choice')
        event = events[0]
        reduction = model.reduce(state, event).to_plain()
        successor_state = rv.freeze(reduction['successor'])
        target_id = explorer.state_identity(successor_state)
        directive = model.legal_directive(successor_state).to_plain()
        _require(_same(reduction['directive'], directive)
                 and successor_state.to_plain()['stage'] == 'verify'
                 and directive['kind'] == 'wait_for_observation'
                 and directive['payload']['detail'] == 'terminal_verification',
                 'close_model_terminal_failure')
        graph_mapping = {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': {
                'kind': 'completed_compensation_close_to_terminal_verification',
                'choice': choice,
                'source_state_id': source_id,
                'transition_id': explorer.edge_identity(source_id, event,
                                                        target_id),
                'target_state_id': target_id,
            },
            'gap': {
                'status': 'PREFIX_ONLY',
                'observed_boundary_count': 3,
                'next_uncovered_choices': [
                    explorer.abstract_event(item) for item in
                    model.outgoing_stimuli(successor_state).to_plain()
                ],
                'next_uncovered_choices_context': 'fresh_controller_root',
                'same_controller_continuation_authorized': False,
                'production_graph_complete': False,
            },
        }
        return rv.freeze({
            'schema': 'orch-dork/production-graph-compensation-close/v1',
            'scope': 'failed_second_spawn_completed_compensation_close',
            'terminal_controller_decision': after['decision'],
            'graph_mapping': graph_mapping,
            'model_state': successor_state.to_plain(),
            'input_sha256': values.canonical_digest([first, failed, closed]),
            'capture_authenticated': False,
            'host_execution_custody': False,
            'controller_continuation_authorized': False,
            'execution_attested': False,
            'complete_campaign': False,
            'release_authorized': False,
            'qualification_authorized': False,
        })
    except (KeyError, IndexError, TypeError, StopIteration, ValueError) as error:
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_close_shape'
        ) from error


_SERIAL_FALSE_FIELDS = (
    'retained_owner_authentication', 'chronology_attested',
    'capture_authenticated', 'host_execution_custody',
    'controller_continuation_authorized', 'execution_attested',
    'complete_campaign', 'release_authorized', 'qualification_authorized',
)
_SERIAL_COMPARISON_AUTHORITY = object()
_ISSUED_SERIAL_COMPARISONS = {}
_FINAL_CONTINUATION_AUTHORITY = object()
_ISSUED_FINAL_CONTINUATIONS = {}
_SPEC_RESULT_AUTHORITY = object()
_ISSUED_SPEC_RESULTS = {}
_STANDARDS_RESULT_AUTHORITY = object()
_ISSUED_STANDARDS_RESULTS = {}
_SEMANTIC_REVIEW_AUTHORITY = object()
_ISSUED_SEMANTIC_REVIEWS = {}
_TERMINAL_CLEANUP_AUTHORITY = object()
_ISSUED_TERMINAL_CLEANUPS = {}
_TERMINAL_SETTLEMENT_AUTHORITY = object()
_ISSUED_TERMINAL_SETTLEMENTS = {}
_LIVE_CAPTURE_AUTHORITY = object()
_LIVE_CAPTURE_SESSIONS = {}


@dataclass(frozen=True, eq=False)
class SerialCheckpointLiveComparison:
    """One process-local comparison issued while live sources still exist."""

    report: rv.FrozenValue
    _authority: object
    _issue_token: object


@dataclass(frozen=True, eq=False)
class FinalContinuationLiveComparison:
    """One issued final-continuation comparison bound to its serial parent."""

    report: rv.FrozenValue
    _serial_parent: SerialCheckpointLiveComparison
    _authority: object
    _issue_token: object


@dataclass(frozen=True, eq=False)
class SpecResultLiveComparison:
    """One issued spec-result comparison bound to its final-batch parent."""

    report: rv.FrozenValue
    _final_parent: FinalContinuationLiveComparison
    _authority: object
    _issue_token: object


@dataclass(frozen=True, eq=False)
class StandardsResultLiveComparison:
    """One issued standards-result comparison bound to its spec parent."""

    report: rv.FrozenValue
    _spec_parent: SpecResultLiveComparison
    _authority: object
    _issue_token: object


@dataclass(frozen=True, eq=False)
class SemanticReviewOutcomeLiveComparison:
    """One issued review outcome bound to its standards-result parent."""

    report: rv.FrozenValue
    _standards_parent: StandardsResultLiveComparison
    _authority: object
    _issue_token: object


@dataclass(frozen=True, eq=False)
class TerminalCleanupLiveComparison:
    """One terminal-cleanup comparison bound to its review parent."""

    report: rv.FrozenValue
    _review_parent: SemanticReviewOutcomeLiveComparison
    _authority: object
    _issue_token: object


@dataclass(frozen=True, eq=False)
class TerminalSettlementLiveComparison:
    """One terminal-settlement comparison bound to its cleanup parent."""

    report: rv.FrozenValue
    _cleanup_parent: TerminalCleanupLiveComparison
    _authority: object
    _issue_token: object


@dataclass(frozen=True, eq=False)
class LiveProductionGraphCapture:
    """One revocable same-process authority for a live raw-source callback."""

    _authority: object
    _capture_token: object


@contextmanager
def open_live_production_graph_capture(source_owner):
    """Open one issuer bound to the exact live raw-source callback owner."""

    try:
        owner_ref = weakref.ref(source_owner)
    except TypeError as error:
        raise values.LifecycleContractError(
            'public_native_comparison:live_capture_source_owner') from error
    token = object()
    capture = LiveProductionGraphCapture(
        _authority=_LIVE_CAPTURE_AUTHORITY,
        _capture_token=token,
    )
    _LIVE_CAPTURE_SESSIONS[token] = {
        'capture': weakref.ref(
            capture,
            lambda _: _LIVE_CAPTURE_SESSIONS.pop(token, None),
        ),
        'pid': os.getpid(),
        'source_owner': owner_ref,
        'observations': {},
        'issued_serial': set(),
        'issued_final': set(),
        'issued_spec': set(),
        'issued_standards': set(),
        'issued_reviews': set(),
        'issued_terminal_cleanup': set(),
        'issued_terminal_settlement': set(),
    }
    try:
        yield capture
    finally:
        _LIVE_CAPTURE_SESSIONS.pop(token, None)


def _live_capture_record(value, source_owner=None):
    token = (value._capture_token
             if type(value) is LiveProductionGraphCapture else None)
    record = _LIVE_CAPTURE_SESSIONS.get(token)
    _require(type(value) is LiveProductionGraphCapture
             and value._authority is _LIVE_CAPTURE_AUTHORITY
             and record is not None and record['capture']() is value
             and record['pid'] == os.getpid()
             and record['source_owner']() is not None
             and (source_owner is None
                  or record['source_owner']() is source_owner),
             'live_capture_session')
    return record


def _bind_live_production_graph_observation(
        capture_session, source_owner, kind, observation, *, reservation=None):
    """Bind one exact callback-owned observation object to a live issuer."""

    record = _live_capture_record(capture_session, source_owner)
    retained = record['observations'].get(kind)
    _require(kind in {
                 'serial', 'final', 'spec', 'standards', 'review',
                 'terminal_cleanup', 'terminal_settlement',
             }
             and type(observation) is dict
             and (
                 reservation is None and retained is None
                 or reservation is not None
                 and type(retained) is dict
                 and set(retained) == {'reservation'}
                 and retained['reservation'] is reservation
             ),
             'live_capture_observation_binding')
    record['observations'][kind] = {
        'value': observation,
        'snapshot': deepcopy(observation),
    }
    return observation


def _reserve_live_production_graph_observation(
        capture_session, source_owner, kind):
    """Reserve one observation kind before its source performs any effect."""

    record = _live_capture_record(capture_session, source_owner)
    _require(kind in {'terminal_cleanup', 'terminal_settlement'}
             and kind not in record['observations'],
             'live_capture_observation_reservation')
    reservation = object()
    record['observations'][kind] = {'reservation': reservation}
    return reservation


def _require_live_observation(capture_session, kind, observation):
    record = _live_capture_record(capture_session)
    retained = record['observations'].get(kind)
    _require(type(retained) is dict
             and retained.get('value') is observation
             and retained.get('snapshot') == observation,
             'live_capture_observation_identity')
    return record


def _serial_comparison_fingerprint(value):
    if type(value) is SerialCheckpointLiveComparison:
        return value.report.digest()
    return None


def _require_issued_serial_comparison(value):
    token = (value._issue_token
             if type(value) is SerialCheckpointLiveComparison else None)
    record = _ISSUED_SERIAL_COMPARISONS.get(token)
    _require(type(value) is SerialCheckpointLiveComparison
             and value._authority is _SERIAL_COMPARISON_AUTHORITY
             and record is not None and record['value']() is value
             and record['pid'] == os.getpid()
             and record['fingerprint']
             == _serial_comparison_fingerprint(value),
             'retained_serial_issued_object')


def _final_continuation_fingerprint(value):
    if type(value) is FinalContinuationLiveComparison:
        return (
            value.report.digest(),
            value._serial_parent._issue_token,
            value._serial_parent.report.digest(),
        )
    return None


def _require_issued_final_continuation(value, serial_parent):
    token = (value._issue_token
             if type(value) is FinalContinuationLiveComparison else None)
    record = _ISSUED_FINAL_CONTINUATIONS.get(token)
    _require(type(value) is FinalContinuationLiveComparison
             and value._authority is _FINAL_CONTINUATION_AUTHORITY
             and value._serial_parent is serial_parent
             and record is not None and record['value']() is value
             and record['pid'] == os.getpid()
             and record['fingerprint']
             == _final_continuation_fingerprint(value)
             and record['parent']() is serial_parent,
             'retained_final_continuation_issued_object')


def _spec_result_fingerprint(value):
    if type(value) is SpecResultLiveComparison:
        return (
            value.report.digest(),
            value._final_parent._issue_token,
            value._final_parent.report.digest(),
        )
    return None


def _require_issued_spec_result(value, final_parent):
    token = (value._issue_token
             if type(value) is SpecResultLiveComparison else None)
    record = _ISSUED_SPEC_RESULTS.get(token)
    _require(type(value) is SpecResultLiveComparison
             and value._authority is _SPEC_RESULT_AUTHORITY
             and value._final_parent is final_parent
             and record is not None and record['value']() is value
             and record['pid'] == os.getpid()
             and record['fingerprint'] == _spec_result_fingerprint(value)
             and record['parent']() is final_parent,
             'retained_spec_result_issued_object')


def _standards_result_fingerprint(value):
    if type(value) is StandardsResultLiveComparison:
        return (
            value.report.digest(),
            value._spec_parent._issue_token,
            value._spec_parent.report.digest(),
        )
    return None


def _require_issued_standards_result(value, spec_parent):
    token = (value._issue_token
             if type(value) is StandardsResultLiveComparison else None)
    record = _ISSUED_STANDARDS_RESULTS.get(token)
    _require(type(value) is StandardsResultLiveComparison
             and value._authority is _STANDARDS_RESULT_AUTHORITY
             and value._spec_parent is spec_parent
             and record is not None and record['value']() is value
             and record['pid'] == os.getpid()
             and record['fingerprint']
             == _standards_result_fingerprint(value)
             and record['parent']() is spec_parent,
             'retained_standards_result_issued_object')


def _semantic_review_fingerprint(value):
    if type(value) is SemanticReviewOutcomeLiveComparison:
        return (
            value.report.digest(),
            value._standards_parent._issue_token,
            value._standards_parent.report.digest(),
        )
    return None


def _require_issued_semantic_review(value, standards_parent):
    token = (value._issue_token
             if type(value) is SemanticReviewOutcomeLiveComparison else None)
    record = _ISSUED_SEMANTIC_REVIEWS.get(token)
    _require(type(value) is SemanticReviewOutcomeLiveComparison
             and value._authority is _SEMANTIC_REVIEW_AUTHORITY
             and value._standards_parent is standards_parent
             and record is not None and record['value']() is value
             and record['pid'] == os.getpid()
             and record['fingerprint']
             == _semantic_review_fingerprint(value)
             and record['parent']() is standards_parent,
             'retained_semantic_review_issued_object')


def _terminal_cleanup_fingerprint(value):
    if type(value) is TerminalCleanupLiveComparison:
        return (
            value.report.digest(),
            value._review_parent._issue_token,
            value._review_parent.report.digest(),
        )
    return None


def _require_issued_terminal_cleanup(value, review_parent):
    token = (value._issue_token
             if type(value) is TerminalCleanupLiveComparison else None)
    record = _ISSUED_TERMINAL_CLEANUPS.get(token)
    _require(type(value) is TerminalCleanupLiveComparison
             and value._authority is _TERMINAL_CLEANUP_AUTHORITY
             and value._review_parent is review_parent
             and record is not None and record['value']() is value
             and record['pid'] == os.getpid()
             and record['fingerprint']
             == _terminal_cleanup_fingerprint(value)
             and record['parent']() is review_parent,
             'retained_terminal_cleanup_issued_object')


def _terminal_settlement_fingerprint(value):
    if type(value) is TerminalSettlementLiveComparison:
        return (
            value.report.digest(),
            value._cleanup_parent._issue_token,
            value._cleanup_parent.report.digest(),
        )
    return None


def _require_issued_terminal_settlement(value, cleanup_parent):
    token = (value._issue_token
             if type(value) is TerminalSettlementLiveComparison else None)
    record = _ISSUED_TERMINAL_SETTLEMENTS.get(token)
    _require(type(value) is TerminalSettlementLiveComparison
             and value._authority is _TERMINAL_SETTLEMENT_AUTHORITY
             and value._cleanup_parent is cleanup_parent
             and record is not None and record['value']() is value
             and record['pid'] == os.getpid()
             and record['fingerprint']
             == _terminal_settlement_fingerprint(value)
             and record['parent']() is cleanup_parent,
             'retained_terminal_settlement_issued_object')


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_ISSUED_SERIAL_COMPARISONS.clear)
    os.register_at_fork(after_in_child=_ISSUED_FINAL_CONTINUATIONS.clear)
    os.register_at_fork(after_in_child=_ISSUED_SPEC_RESULTS.clear)
    os.register_at_fork(after_in_child=_ISSUED_STANDARDS_RESULTS.clear)
    os.register_at_fork(after_in_child=_ISSUED_SEMANTIC_REVIEWS.clear)
    os.register_at_fork(after_in_child=_ISSUED_TERMINAL_CLEANUPS.clear)
    os.register_at_fork(after_in_child=_ISSUED_TERMINAL_SETTLEMENTS.clear)
    os.register_at_fork(after_in_child=_LIVE_CAPTURE_SESSIONS.clear)


def _serial_raw_fingerprint(raw, label):
    _require(type(raw) is bytes
             and 0 < len(raw) <= owned_file.MAX_PRIVATE_ROLLOUT_BYTES,
             'serial_checkpoint_' + label)
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}


def _serial_checkpoint_input_projection(value):
    _require(type(value) is dict and set(value) == {
        'arrival_order', 'arrival_observations', 'arrival_raw',
        'arrival_root_before', 'raw_root', 'advance_report',
    }, 'serial_checkpoint_input_shape')
    order = value['arrival_order']
    _require(type(order) is list and len(order) == 2
             and set(order) == {'spec', 'standards'},
             'serial_checkpoint_order')
    reports = value['arrival_observations']
    _require(type(reports) is list and len(reports) == 2,
             'serial_checkpoint_reports')
    detached_reports = [rv.freeze(report).to_plain() for report in reports]
    raw = value['arrival_raw']
    _require(type(raw) is dict and set(raw) == {
        'before', 'appends', 'after_first', 'after_second',
    }, 'serial_checkpoint_raw_shape')
    raw_projection = {}
    for group in ('before', 'appends', 'after_first', 'after_second'):
        rows = raw[group]
        _require(type(rows) is dict and set(rows) == {'spec', 'standards'},
                 'serial_checkpoint_raw_shape')
        raw_projection[group] = {
            lane: _serial_raw_fingerprint(
                rows[lane], group + '_' + lane)
            for lane in ('spec', 'standards')
        }
    return {
        'arrival_order': list(order),
        'arrival_observations': detached_reports,
        'arrival_raw': raw_projection,
        'arrival_root_before': _serial_raw_fingerprint(
            value['arrival_root_before'], 'root_before'),
        'raw_root': _serial_raw_fingerprint(value['raw_root'], 'root_after'),
        'advance_report': rv.freeze(value['advance_report']).to_plain(),
    }


def _serial_checkpoint_wait_anchor(checkpoint_wait):
    return {
        'report_sha256': values.canonical_digest(checkpoint_wait),
        'schema': checkpoint_wait['schema'],
        'scope': checkpoint_wait['scope'],
        'production_boundary': checkpoint_wait['graph_mapping'][
            'production_boundary'],
        'model_state_sha256': values.canonical_digest(
            checkpoint_wait['model_state']),
        'input_sha256': checkpoint_wait['input_sha256'],
    }


def compare_serial_checkpoint_arrival_order(checkpoint_wait_report,
                                            serial_observation):
    """Map one observed serial checkpoint order without retaining authority."""
    checkpoint_wait = rv.freeze(checkpoint_wait_report).to_plain()
    projection = _serial_checkpoint_input_projection(serial_observation)
    order = tuple(projection['arrival_order'])
    arrivals = projection['arrival_observations']
    raw = serial_observation['arrival_raw']
    root_bytes = serial_observation['arrival_root_before']
    try:
        _require(checkpoint_wait['schema'] ==
                 'orch-dork/production-graph-standards-checkpoint-continuation/v1'
                 and checkpoint_wait['scope'] ==
                 'completed_standards_checkpoint_deferred_continuation_prefix'
                 and checkpoint_wait['graph_mapping']['production_boundary'][
                     'kind'] ==
                 'completed_standards_checkpoint_deferred_to_checkpoint_wait'
                 and checkpoint_wait['graph_mapping']['graph_case']
                 == explorer.GRAPH_CASE
                 and checkpoint_wait['graph_mapping']['graph_owner']
                 == explorer.OWNER
                 and checkpoint_wait['graph_mapping']['gap'][
                     'production_graph_complete'] is False
                 and checkpoint_wait['graph_mapping']['gap'].get(
                     'same_controller_continuation_authorized', False
                 ) is False
                 and all(checkpoint_wait.get(field, False) is False
                         for field in _SERIAL_FALSE_FIELDS),
                 'serial_checkpoint_wait_scope')
        _require(serial_observation['raw_root'] == root_bytes,
                 'serial_checkpoint_root_changed')
        for lane in ('spec', 'standards'):
            _require(raw['after_second'][lane]
                     == raw['before'][lane] + raw['appends'][lane],
                     'serial_checkpoint_final_bytes')
        first, second = order
        _require(raw['after_first'][first]
                 == raw['before'][first] + raw['appends'][first]
                 and raw['after_first'][second] == raw['before'][second]
                 and raw['after_second'][first] == raw['after_first'][first]
                 and raw['after_second'][second]
                 == raw['after_first'][second] + raw['appends'][second],
                 'serial_checkpoint_append_order')

        expected_completed = ([first], ['spec', 'standards'])
        expected_pending = ([second], [])
        snapshots = (raw['after_first'], raw['after_second'])
        for index, report in enumerate(arrivals):
            _require(attempt_observer.
                     validate_native_worker_checkpoint_arrival_observation(
                         report).get('valid') is True
                     and report['status'] == 'OBSERVED'
                     and report['issues'] == []
                     and report['raw_checkpoint_custody_observed'] is True
                     and all(report[field] is False
                             for field in _SERIAL_FALSE_FIELDS),
                     'serial_checkpoint_arrival_report')
            evidence = report['evidence']
            inventory = evidence['source_inventory']['observation']
            _require(inventory['completed_lane_ids']
                     == expected_completed[index]
                     and inventory['pending_lane_ids']
                     == expected_pending[index]
                     and set(evidence['workers'])
                     == set(expected_completed[index]),
                     'serial_checkpoint_frontier')
            root_source = evidence['root']['source']
            _require(root_source['path']
                     == inventory['sources']['root']['path']
                     and root_source['file_sha256']
                     == hashlib.sha256(root_bytes).hexdigest()
                     and root_source['prefix_bytes'] == len(root_bytes),
                     'serial_checkpoint_root_binding')
            for lane in expected_completed[index]:
                worker_source = evidence['workers'][lane]['source']
                worker_bytes = snapshots[index][lane]
                _require(worker_source['path']
                         == inventory['sources'][lane]['path']
                         and worker_source['file_sha256']
                         == hashlib.sha256(worker_bytes).hexdigest()
                         and worker_source['prefix_bytes'] == len(worker_bytes),
                         'serial_checkpoint_worker_binding')
        first_root = arrivals[0]['evidence']['root']
        second_root = arrivals[1]['evidence']['root']
        _require(_same(arrivals[0]['expectation'], arrivals[1]['expectation'])
                 and all(_same(first_root[key], second_root[key]) for key in (
                     'source', 'identity', 'windows', 'active_prefix'))
                 and set(first_root['worker_actions']) == {first}
                 and set(second_root['worker_actions']) == {'spec', 'standards'}
                 and _same(first_root['worker_actions'][first],
                           second_root['worker_actions'][first])
                 and _same(arrivals[0]['evidence']['workers'][first],
                           arrivals[1]['evidence']['workers'][first]),
                 'serial_checkpoint_stable_prefix')

        advance = projection['advance_report']
        _require(successor.validate_issue94_successor_action_advance_report(
            advance).get('valid') is True
            and advance['status'] == 'PASS'
            and advance['decision'] == 'READY_FOR_NEXT_ACTION'
            and advance['issues'] == []
            and advance['provider_free'] is True
            and [row['program']['operation']
                 for row in advance['controller_transitions']]
            == ['inspect', 'stage'],
                 'serial_checkpoint_advance')
        action = advance['action']
        owner_ids = arrivals[1]['expectation']['sources']['owner']['worker_ids']
        _require(type(action) is dict and action['kind'] == 'continue'
                 and action['lane_ids'] == ['spec']
                 and action['tool_name'] == 'multi_agent_v1__send_input'
                 and action['tool_input']['target'] == owner_ids['spec'],
                 'serial_checkpoint_next_action')
        stage = advance['controller_transitions'][-1]['program']['payload'][
            'stage_program']
        checkpoint_sources = stage['payload']['checkpoint_sources']
        _require(set(checkpoint_sources) == {'coordinator', 'workers'},
                 'serial_checkpoint_sources')
        workers = checkpoint_sources['workers']
        _require(attempt_observer.validate_native_worker_checkpoint_observation(
            workers).get('valid') is True
            and workers['status'] == 'OBSERVED'
            and workers['expectation'] == {
                'sources': arrivals[1]['expectation']['sources'],
                'lanes': arrivals[1]['expectation']['lanes'],
            }
            and _same(workers['evidence']['workers'],
                      arrivals[1]['evidence']['workers']),
                 'serial_checkpoint_aggregate_join')
        coordinator = checkpoint_sources['coordinator']
        _require(coordinator_usage.validate_coordinator_usage(
            coordinator).get('valid') is True
            and coordinator['status'] == 'OBSERVED'
            and coordinator['expectation'] == {
                'sources': arrivals[1]['expectation']['sources'],
                'model': arrivals[1]['expectation']['root']['model'],
                'effort': arrivals[1]['expectation']['root']['effort'],
                'pending_call':
                    arrivals[1]['expectation']['root']['pending_call'],
            }
            and coordinator['evidence']['source']['path']
            == arrivals[1]['evidence']['root']['source']['path']
            and coordinator['evidence']['source']['file_sha256']
            == hashlib.sha256(root_bytes).hexdigest()
            and coordinator['evidence']['source']['prefix_bytes']
            == len(root_bytes)
            and _same(coordinator['evidence']['identity'],
                      arrivals[1]['evidence']['root']['identity'])
            and _same(coordinator['evidence']['windows'],
                      arrivals[1]['evidence']['root']['windows'])
            and _same(coordinator['evidence']['active_prefix'],
                      arrivals[1]['evidence']['root']['active_prefix'])
            and advance['boundary']['native_action_called_by_bridge'] is False,
                 'serial_checkpoint_coordinator_join')

        state = rv.freeze(checkpoint_wait['model_state'])
        source_id = explorer.state_identity(state)
        _require(source_id == checkpoint_wait['graph_mapping'][
            'production_boundary']['target_state_id'],
                 'serial_checkpoint_graph_source')
        choices = [
            {'stage': 'checkpoint.' + first, 'lane': first,
             'outcome': 'accepted', 'variant': 'evidence'},
            {'stage': 'checkpoint.' + second, 'lane': second,
             'outcome': 'accepted', 'variant': 'evidence'},
            {'stage': 'progress', 'lane': 'controller',
             'outcome': 'accepted', 'variant': 'evidence'},
        ]
        observation_sha256s = [
            arrivals[0]['report_sha256'], arrivals[1]['report_sha256'],
            advance['report_sha256'],
        ]
        checkpoint_wait_anchor = _serial_checkpoint_wait_anchor(
            checkpoint_wait)
        checkpoint_wait_sha256 = values.canonical_digest(
            checkpoint_wait_anchor)
        serial_observation_sha256 = values.canonical_digest(projection)
        input_sha256 = values.canonical_digest({
            'checkpoint_wait_sha256': checkpoint_wait_sha256,
            'serial_observation_sha256': serial_observation_sha256,
        })
        comparisons = []
        for index, (choice, observation_sha256) in enumerate(zip(
                choices, observation_sha256s)):
            events = [event for event in model.outgoing_stimuli(state).to_plain()
                      if _same(explorer.abstract_event(event), choice)]
            _require(len(events) == 1, 'serial_checkpoint_model_choice')
            event = events[0]
            reduction = model.reduce(state, event).to_plain()
            successor_state = rv.freeze(reduction['successor'])
            directive = model.legal_directive(successor_state).to_plain()
            _require(_same(reduction['directive'], directive),
                     'serial_checkpoint_model_directive')
            target_facts = successor_state.to_plain()
            if index == 0:
                _require(target_facts['stage'] == 'checkpoint.' + second,
                         'serial_checkpoint_first_target')
            elif index == 1:
                _require(target_facts['stage'] == 'progress',
                         'serial_checkpoint_second_target')
            else:
                _require(target_facts['stage'] == 'continue.spec'
                         and target_facts['progress_admission'] == 'accepted'
                         and target_facts['action']['method'] == 'send_input'
                         and target_facts['action']['lane'] == 'spec',
                         'serial_checkpoint_progress_target')
            target_id = explorer.state_identity(successor_state)
            boundary = {
                'kind': ('observed_' + choice['lane'] + '_checkpoint_arrival'
                         if index < 2 else
                         'checkpoint_progress_admission_to_spec_continuation'),
                'choice': choice,
                'source_state_id': source_id,
                'transition_id': explorer.edge_identity(
                    source_id, event, target_id),
                'target_state_id': target_id,
            }
            comparisons.append({
                'schema':
                    'orch-dork/production-graph-serial-checkpoint-edge/v1',
                'scope': 'serial_raw_checkpoint_frontier_reconstruction',
                'arrival_order': list(order),
                'arrival_index': index,
                'production_observation_sha256': observation_sha256,
                'graph_mapping': {
                    'graph_case': explorer.GRAPH_CASE,
                    'graph_owner': explorer.OWNER,
                    'production_boundary': boundary,
                    'gap': {
                        'status': 'PREFIX_ONLY',
                        'observed_boundary_count': 7 + index,
                        'next_uncovered_choices': [
                            explorer.abstract_event(item) for item in
                            model.outgoing_stimuli(successor_state).to_plain()
                        ],
                        'production_graph_complete': False,
                    },
                },
                'model_state': target_facts,
                'input_sha256': input_sha256,
                **{field: False for field in _SERIAL_FALSE_FIELDS},
            })
            state, source_id = successor_state, target_id
        return rv.freeze({
            'schema':
                'orch-dork/production-graph-serial-checkpoint-order/v1',
            'scope': 'serial_raw_checkpoint_order_reconstruction',
            'arrival_order': list(order),
            'comparisons': comparisons,
            'checkpoint_wait_sha256': checkpoint_wait_sha256,
            'serial_observation_sha256': serial_observation_sha256,
            'input_sha256': input_sha256,
            **{field: False for field in _SERIAL_FALSE_FIELDS},
        })
    except (KeyError, IndexError, TypeError, StopIteration, ValueError) as error:
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_serial_checkpoint_shape'
        ) from error


def capture_serial_checkpoint_arrival_order_comparison(
        checkpoint_wait_report, serial_observation, *, capture_session):
    """Issue one live-source comparison for same-process campaign joining."""
    capture_record = _require_live_observation(
        capture_session, 'serial', serial_observation)
    report = compare_serial_checkpoint_arrival_order(
        checkpoint_wait_report, serial_observation)
    issue_key = report.digest()
    _require(issue_key not in capture_record['issued_serial'],
             'live_capture_duplicate_serial')
    token = object()
    value = SerialCheckpointLiveComparison(
        report=report,
        _authority=_SERIAL_COMPARISON_AUTHORITY,
        _issue_token=token,
    )
    _ISSUED_SERIAL_COMPARISONS[token] = {
        'value': weakref.ref(
            value,
            lambda _: _ISSUED_SERIAL_COMPARISONS.pop(token, None),
        ),
        'pid': os.getpid(),
        'fingerprint': _serial_comparison_fingerprint(value),
        'capture_token': capture_session._capture_token,
    }
    capture_record['issued_serial'].add(issue_key)
    return value


def _validated_serial_checkpoint_order(
        checkpoint_wait_report, retained_comparison, expected_order):
    """Validate a live-source comparison without reopening expired paths."""
    checkpoint_wait = rv.freeze(checkpoint_wait_report).to_plain()
    _require_issued_serial_comparison(retained_comparison)
    report = retained_comparison.report.to_plain()
    try:
        _require(type(expected_order) is tuple and len(expected_order) == 2
                 and set(expected_order) == {'spec', 'standards'},
                 'retained_serial_expected_order')
        _require(type(report) is dict and set(report) == {
            'schema', 'scope', 'arrival_order', 'comparisons',
            'checkpoint_wait_sha256', 'serial_observation_sha256',
            'input_sha256', *_SERIAL_FALSE_FIELDS,
        } and report['schema'] ==
            'orch-dork/production-graph-serial-checkpoint-order/v1'
            and report['scope'] ==
            'serial_raw_checkpoint_order_reconstruction'
            and report['arrival_order'] == list(expected_order)
            and all(report[field] is False
                    for field in _SERIAL_FALSE_FIELDS),
                 'retained_serial_shape')
        checkpoint_wait_anchor = _serial_checkpoint_wait_anchor(
            checkpoint_wait)
        checkpoint_wait_sha256 = values.canonical_digest(
            checkpoint_wait_anchor)
        _require(report['checkpoint_wait_sha256'] == checkpoint_wait_sha256
                 and re.fullmatch(
                     r'[0-9a-f]{64}', report['serial_observation_sha256'])
                 is not None
                 and report['input_sha256'] == values.canonical_digest({
                     'checkpoint_wait_sha256': checkpoint_wait_sha256,
                     'serial_observation_sha256':
                         report['serial_observation_sha256'],
                 }), 'retained_serial_input')
        _require(checkpoint_wait['schema'] ==
                 'orch-dork/production-graph-standards-checkpoint-continuation/v1'
                 and checkpoint_wait['scope'] ==
                 'completed_standards_checkpoint_deferred_continuation_prefix'
                 and checkpoint_wait['graph_mapping']['graph_case']
                 == explorer.GRAPH_CASE
                 and checkpoint_wait['graph_mapping']['graph_owner']
                 == explorer.OWNER
                 and checkpoint_wait['graph_mapping'][
                     'production_boundary']['kind'] ==
                 'completed_standards_checkpoint_deferred_to_checkpoint_wait'
                 and checkpoint_wait['graph_mapping']['gap'][
                     'production_graph_complete'] is False
                 and checkpoint_wait['graph_mapping']['gap'].get(
                     'same_controller_continuation_authorized', False
                 ) is False
                 and all(checkpoint_wait.get(field, False) is False
                         for field in _SERIAL_FALSE_FIELDS),
                 'retained_serial_checkpoint_wait')
        state = rv.freeze(checkpoint_wait['model_state'])
        source_id = explorer.state_identity(state)
        _require(source_id == checkpoint_wait['graph_mapping'][
            'production_boundary']['target_state_id'],
                 'retained_serial_graph_source')
        first, second = expected_order
        choices = (
            {'stage': 'checkpoint.' + first, 'lane': first,
             'outcome': 'accepted', 'variant': 'evidence'},
            {'stage': 'checkpoint.' + second, 'lane': second,
             'outcome': 'accepted', 'variant': 'evidence'},
            {'stage': 'progress', 'lane': 'controller',
             'outcome': 'accepted', 'variant': 'evidence'},
        )
        comparisons = report['comparisons']
        _require(type(comparisons) is list and len(comparisons) == 3,
                 'retained_serial_comparisons')
        observation_sha256s = []
        for index, (comparison, choice) in enumerate(zip(
                comparisons, choices)):
            _require(type(comparison) is dict and set(comparison) == {
                'schema', 'scope', 'arrival_order', 'arrival_index',
                'production_observation_sha256', 'graph_mapping',
                'model_state', 'input_sha256', *_SERIAL_FALSE_FIELDS,
            } and comparison['schema'] ==
                'orch-dork/production-graph-serial-checkpoint-edge/v1'
                and comparison['scope'] ==
                'serial_raw_checkpoint_frontier_reconstruction'
                and comparison['arrival_order'] == list(expected_order)
                and comparison['arrival_index'] == index
                and comparison['input_sha256'] == report['input_sha256']
                and all(comparison[field] is False
                        for field in _SERIAL_FALSE_FIELDS)
                and re.fullmatch(
                    r'[0-9a-f]{64}',
                    comparison['production_observation_sha256']) is not None,
                     'retained_serial_comparison_shape')
            events = [event for event in model.outgoing_stimuli(
                state).to_plain()
                      if _same(explorer.abstract_event(event), choice)]
            _require(len(events) == 1,
                     'retained_serial_model_choice')
            event = events[0]
            reduction = model.reduce(state, event).to_plain()
            successor_state = rv.freeze(reduction['successor'])
            directive = model.legal_directive(successor_state).to_plain()
            _require(_same(reduction['directive'], directive),
                     'retained_serial_model_directive')
            target_id = explorer.state_identity(successor_state)
            boundary = {
                'kind': ('observed_' + choice['lane'] +
                         '_checkpoint_arrival' if index < 2 else
                         'checkpoint_progress_admission_to_spec_continuation'),
                'choice': choice,
                'source_state_id': source_id,
                'transition_id': explorer.edge_identity(
                    source_id, event, target_id),
                'target_state_id': target_id,
            }
            expected_mapping = {
                'graph_case': explorer.GRAPH_CASE,
                'graph_owner': explorer.OWNER,
                'production_boundary': boundary,
                'gap': {
                    'status': 'PREFIX_ONLY',
                    'observed_boundary_count': 7 + index,
                    'next_uncovered_choices': [
                        explorer.abstract_event(item) for item in
                        model.outgoing_stimuli(
                            successor_state).to_plain()
                    ],
                    'production_graph_complete': False,
                },
            }
            _require(_same(comparison['graph_mapping'], expected_mapping)
                     and _same(comparison['model_state'],
                               successor_state.to_plain()),
                     'retained_serial_model_mapping')
            observation_sha256s.append(
                comparison['production_observation_sha256'])
            state, source_id = successor_state, target_id
        _require(len(set(observation_sha256s)) == 3,
                 'retained_serial_observation_identity')
        return report
    except (KeyError, IndexError, TypeError, ValueError,
            OverflowError, RecursionError) as error:
        if isinstance(error, values.LifecycleContractError):
            raise
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_retained_serial_shape'
        ) from error


def _appended_json_rows(before, after, label):
    _serial_raw_fingerprint(before, label + '_before')
    _serial_raw_fingerprint(after, label + '_after')
    _require(len(after) > len(before) and after.startswith(before),
             label + '_prefix')
    suffix = after[len(before):]
    _require(suffix.endswith(b'\n'), label + '_terminator')
    try:
        before_lines = before.decode('utf-8').splitlines()
        _require(bool(before_lines), label + '_prior_rows')
        prior = _strict_json_record(before_lines[-1])
        lines = suffix.decode('utf-8').splitlines()
        rows = [_strict_json_record(line) for line in lines]
        timestamps = [
            datetime.fromisoformat(
                row['timestamp'].replace('Z', '+00:00'))
            for row in (prior, *rows)
        ]
    except (AttributeError, KeyError, TypeError, UnicodeError,
            ValueError) as error:
        raise values.LifecycleContractError(
            'public_native_comparison:' + label + '_json'
        ) from error
    _require(bool(rows) and all(type(row) is dict and set(row) == {
        'type', 'ordinal', 'timestamp', 'payload',
    } and type(row['ordinal']) is int
        and not isinstance(row['ordinal'], bool)
        and type(row['timestamp']) is str and bool(row['timestamp'])
        and type(row['payload']) is dict for row in rows),
             label + '_rows')
    _require([row['ordinal'] for row in rows]
             == list(range(rows[0]['ordinal'],
                           rows[0]['ordinal'] + len(rows))),
             label + '_ordinals')
    _require(type(prior) is dict
             and type(prior.get('ordinal')) is int
             and not isinstance(prior['ordinal'], bool)
             and rows[0]['ordinal'] == prior['ordinal'] + 1,
             label + '_prior_ordinal')
    _require(all(stamp.tzinfo is not None
                 and stamp.utcoffset() is not None
                 for stamp in timestamps),
             label + '_timestamp_timezone')
    _require(timestamps == sorted(timestamps),
             label + '_timestamps')
    return rows


def _final_continuation_input_projection(value):
    _require(type(value) is dict and set(value) == {
        'schema', 'arrival_order', 'checkpoint_collection_batch_id',
        'metadata', 'checkpoint_report',
        'root_snapshots', 'worker_snapshots', 'continuations',
        'owner_records', 'owner_transport_budget', 'owner_cleanup',
        'capacity_before', 'capacity_after', 'authority_before',
        'authority_after', 'final_report',
    }, 'final_continuation_input_shape')
    roots = value['root_snapshots']
    _require(type(roots) is dict and set(roots) == {
        'before', 'after_checkpoint_result', 'after_spec',
        'after_standards',
    }, 'final_continuation_root_shape')
    workers = value['worker_snapshots']
    _require(type(workers) is dict and set(workers) == {'before', 'after'}
             and all(type(workers[boundary]) is dict
                     and set(workers[boundary]) == {'spec', 'standards'}
                     for boundary in ('before', 'after')),
             'final_continuation_worker_shape')
    continuations = value['continuations']
    _require(type(continuations) is list and len(continuations) == 2,
             'final_continuation_steps')
    return {
        'schema': value['schema'],
        'arrival_order': rv.freeze(value['arrival_order']).to_plain(),
        'checkpoint_collection_batch_id':
            value['checkpoint_collection_batch_id'],
        'metadata_sha256': values.canonical_digest(
            rv.freeze(value['metadata']).to_plain()),
        'checkpoint_report_sha256': values.canonical_digest(
            rv.freeze(value['checkpoint_report']).to_plain()),
        'root_snapshots': {
            name: _serial_raw_fingerprint(raw, 'final_root_' + name)
            for name, raw in roots.items()
        },
        'worker_snapshots': {
            boundary: {
                lane: _serial_raw_fingerprint(
                    raw, 'final_worker_' + boundary + '_' + lane)
                for lane, raw in workers[boundary].items()
            }
            for boundary in ('before', 'after')
        },
        'continuation_sha256s': [
            values.canonical_digest(rv.freeze(step).to_plain())
            for step in continuations
        ],
        'owner_records_sha256': values.canonical_digest(
            rv.freeze(value['owner_records']).to_plain()),
        'owner_transport_budget_sha256': values.canonical_digest(
            rv.freeze(value['owner_transport_budget']).to_plain()),
        'owner_cleanup': rv.freeze(value['owner_cleanup']).to_plain(),
        'capacity_before_sha256': values.canonical_digest(
            rv.freeze(value['capacity_before']).to_plain()),
        'capacity_after_sha256': values.canonical_digest(
            rv.freeze(value['capacity_after']).to_plain()),
        'authority_before_sha256': values.canonical_digest(
            rv.freeze(value['authority_before']).to_plain()),
        'authority_after_sha256': values.canonical_digest(
            rv.freeze(value['authority_after']).to_plain()),
        'final_report_sha256': values.canonical_digest(
            rv.freeze(value['final_report']).to_plain()),
    }


def compare_post_progress_deferred_batch(
        checkpoint_wait_report, serial_comparison, serial_observation,
        final_observation, expected_order):
    """Map one exact post-progress continuation batch while roots are live."""

    checkpoint_wait = rv.freeze(checkpoint_wait_report).to_plain()
    _require_issued_serial_comparison(serial_comparison)
    serial_report = _validated_serial_checkpoint_order(
        checkpoint_wait, serial_comparison, expected_order)
    live_serial = compare_serial_checkpoint_arrival_order(
        checkpoint_wait, serial_observation)
    _require(live_serial == serial_comparison.report,
             'final_continuation_serial_parent')
    projection = _final_continuation_input_projection(final_observation)
    try:
        _require(type(expected_order) is tuple and len(expected_order) == 2
                 and set(expected_order) == {'spec', 'standards'}
                 and final_observation['schema'] ==
                 'orch-dork/native-post-progress-deferred-batch/v1'
                 and final_observation['arrival_order']
                 == list(expected_order)
                 and type(final_observation[
                     'checkpoint_collection_batch_id']) is str
                 and bool(final_observation[
                     'checkpoint_collection_batch_id']),
                 'final_continuation_scope')
        metadata = final_observation['metadata']
        checkpoint_report = rv.freeze(
            final_observation['checkpoint_report']).to_plain()
        _require(_same(checkpoint_report,
                       serial_observation['advance_report'])
                 and successor.
                 validate_issue94_successor_action_advance_report(
                     checkpoint_report).get('valid') is True
                 and checkpoint_report['decision']
                 == 'READY_FOR_NEXT_ACTION'
                 and checkpoint_report['action']['lane_ids'] == ['spec']
                 and checkpoint_report['report_sha256']
                 == serial_report['comparisons'][-1][
                     'production_observation_sha256'],
                 'final_continuation_checkpoint_report')
        action = checkpoint_report['action']
        root_id = action['actor_thread_id']
        turn_metadata = metadata['x-codex-turn-metadata']
        _require(metadata['threadId'] == root_id
                 and metadata['callId'] == 'checkpoint-current-call'
                 and metadata['itemId'] == 'checkpoint-current-item'
                 and turn_metadata['thread_id'] == root_id
                 and turn_metadata['session_id'] == root_id
                 and turn_metadata['turn_id'] == 'checkpoint-root-turn',
                 'final_continuation_metadata')

        roots = final_observation['root_snapshots']
        workers = final_observation['worker_snapshots']
        _require(roots['before'] == serial_observation['raw_root']
                 and all(workers['before'][lane]
                         == serial_observation['arrival_raw'][
                             'after_second'][lane]
                         and workers['after'][lane]
                         == workers['before'][lane]
                         for lane in ('spec', 'standards')),
                 'final_continuation_source_join')
        checkpoint_rows = _appended_json_rows(
            roots['before'], roots['after_checkpoint_result'],
            'final_checkpoint_result')
        _require(len(checkpoint_rows) == 1
                 and checkpoint_rows[0]['type'] == 'response_item',
                 'final_checkpoint_result_count')
        checkpoint_payload = checkpoint_rows[0]['payload']
        _require(set(checkpoint_payload) == {
            'type', 'call_id', 'id',
            'internal_chat_message_metadata_passthrough', 'output',
        } and checkpoint_payload['type'] == 'custom_tool_call_output'
            and checkpoint_payload['call_id'] == metadata['callId']
            and checkpoint_payload['id'] == metadata['callId'] + '-result'
            and checkpoint_payload[
                'internal_chat_message_metadata_passthrough'] is None
            and type(checkpoint_payload['output']) is list
            and checkpoint_payload['output'] == [{
                'type': 'input_text',
                'text': checkpoint_payload['output'][0]['text'],
            }]
            and _same(_strict_json_record(
                checkpoint_payload['output'][0]['text']),
                checkpoint_report),
                 'final_checkpoint_result_shape')

        step_inputs = final_observation['continuations']
        root_pairs = (
            (roots['after_checkpoint_result'], roots['after_spec']),
            (roots['after_spec'], roots['after_standards']),
        )
        checked_steps = []
        previous = checkpoint_report['controller_transitions'][-1]['report']
        expected_action = action
        for index, (lane, step, root_pair) in enumerate(zip(
                ('spec', 'standards'), step_inputs, root_pairs)):
            _require(type(step) is dict and set(step) == {
                'lane', 'call_id', 'action', 'raw_response',
                'pre_hook_report', 'post_hook_report', 'advance_report',
            } and step['lane'] == lane
                and step['call_id'] == 'final-continue-' + lane,
                     'final_continuation_step_shape')
            action_step = {key: step[key] for key in (
                'action', 'raw_response', 'pre_hook_report',
                'post_hook_report', 'advance_report',
            )}
            checked = _validated_action_step(
                action_step, expected_action, previous,
                action_kind='continue', lane_ids=[lane],
                outcome='completed', label='final_continuation_' + lane,
            )
            step_action = checked['action']
            raw = checked['raw']
            advance = checked['advance']
            _require(checked['call_id'] == step['call_id']
                     and type(raw) is dict and set(raw) == {'submission_id'}
                     and type(raw['submission_id']) is str
                     and re.fullmatch(
                         r'[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}',
                         raw['submission_id']) is not None
                     and step_action['kind'] == 'continue'
                     and step_action['tool_name']
                     == 'multi_agent_v1__send_input'
                     and step_action['lane_ids'] == [lane]
                     and step_action['batch_kind'] == 'continue'
                     and step_action['batch_phase'] == 'primary'
                     and step_action['batch_index'] == index
                     and step_action['batch_size'] == 2
                     and step_action['batch_lane_ids']
                     == ['spec', 'standards']
                     and step_action['batch_failure_outcome'] is None
                     and checked['pre']['identity']['turn_id']
                     == 'checkpoint-root-turn'
                     and checked['post']['identity']['turn_id']
                     == 'checkpoint-root-turn',
                     'final_continuation_' + lane + '_action')
            rows = _appended_json_rows(
                root_pair[0], root_pair[1],
                'final_continuation_root_' + lane)
            _require(len(rows) == 2
                     and all(row['type'] == 'response_item' for row in rows),
                     'final_continuation_' + lane + '_root_rows')
            call_payload, result_payload = (
                rows[0]['payload'], rows[1]['payload'])
            _require(set(call_payload) == {
                'type', 'call_id', 'id', 'namespace', 'name',
                'internal_chat_message_metadata_passthrough', 'arguments',
            } and call_payload['type'] == 'function_call'
                and call_payload['call_id'] == step['call_id']
                and call_payload['id'] == step['call_id'] + '-item'
                and call_payload['namespace'] == 'multi_agent_v1'
                and call_payload['name'] == 'send_input'
                and call_payload[
                    'internal_chat_message_metadata_passthrough'] is None
                and _same(_strict_json_record(call_payload['arguments']),
                          step_action['tool_input'])
                and set(result_payload) == {
                    'type', 'call_id', 'id',
                    'internal_chat_message_metadata_passthrough', 'output',
                } and result_payload['type'] == 'function_call_output'
                and result_payload['call_id'] == step['call_id']
                and result_payload['id'] == step['call_id'] + '-result'
                and result_payload[
                    'internal_chat_message_metadata_passthrough'] is None
                and _same(_strict_json_record(result_payload['output']), raw),
                     'final_continuation_' + lane + '_root_pair')
            if index == 0:
                next_action = _expected_next_batch_action(step_action)
                _require(advance['decision'] == 'READY_FOR_NEXT_ACTION'
                         and _same(advance['action'], next_action)
                         and advance['worker_results'] == []
                         and advance['review_packet'] is None
                         and checked['controller']['decision']
                         == 'ACTION_AUTHORIZED',
                         'final_continuation_spec_successor')
                expected_action = next_action
            else:
                _require(advance['decision'] == 'AWAITING_WORKER_RESULTS'
                         and advance['action'] is None
                         and advance['review_packet'] is None
                         and checked['controller']['decision']
                         == 'ACTION_OBSERVED',
                         'final_continuation_standards_successor')
            checked_steps.append(checked)
            previous = checked['controller']

        _require(checked_steps[0]['action']['batch_id']
                 == checked_steps[1]['action']['batch_id']
                 and checked_steps[0]['action']['batch_id'] == action['batch_id']
                 and checked_steps[0]['action']['batch_id']
                 != final_observation['checkpoint_collection_batch_id']
                 and checked_steps[0]['raw']['submission_id']
                 != checked_steps[1]['raw']['submission_id'],
                 'final_continuation_batch_identity')
        final_report = rv.freeze(
            final_observation['final_report']).to_plain()
        _require(_same(final_report, checked_steps[1]['advance'])
                 and type(final_report['worker_results']) is list
                 and len(final_report['worker_results']) == 2
                 and [row['binding']['logical_worker_id']
                      for row in final_report['worker_results']]
                 == ['spec', 'standards']
                 and all(row['status'] == 'PENDING'
                         and row['issues'] == ['worker_result:not_found']
                         and row['runtime_observation'] is None
                         and row['handoff_receipt'] is None
                         and row['read_error'] == 'not_found'
                         for row in final_report['worker_results']),
                 'final_continuation_pending_results')

        budget = final_observation['owner_transport_budget']
        owner_records = final_observation['owner_records']
        _require(type(owner_records) is list and bool(owner_records)
                 and all(type(row) is dict and 'error' not in row
                         for row in owner_records)
                 and type(budget) is dict and set(budget) == {
                     'max_calls', 'calls_retained', 'within_bound',
                 } and type(budget['max_calls']) is int
                 and type(budget['calls_retained']) is int
                 and budget['calls_retained'] == len(owner_records)
                 and 0 < budget['calls_retained'] <= budget['max_calls'] <= 256
                 and budget['within_bound'] is True
                 and final_observation['owner_cleanup'] == {
                     'closed': True, 'socket_removed': True,
                 }, 'final_continuation_owner_scope')
        before_authority = final_observation['authority_before']
        after_authority = final_observation['authority_after']
        _require(_same(final_observation['capacity_before'],
                       final_observation['capacity_after'])
                 and _same(before_authority['tip'],
                           checkpoint_report['controller_transitions'][-1][
                               'report']['cursor'])
                 and _same(after_authority['tip'],
                           checked_steps[-1]['after_cursor'])
                 and all(after_authority['lifecycle'][field] is False
                         for field in (
                             'terminal', 'cleanup_required',
                             'pending_intent')),
                 'final_continuation_authority_scope')

        state = rv.freeze(serial_report['comparisons'][-1]['model_state'])
        source_id = explorer.state_identity(state)
        _require(source_id == serial_report['comparisons'][-1][
            'graph_mapping']['production_boundary']['target_state_id'],
                 'final_continuation_graph_source')
        final_observation_sha256 = values.canonical_digest(projection)
        input_sha256 = values.canonical_digest({
            'serial_comparison_sha256': serial_comparison.report.digest(),
            'checkpoint_report_sha256': checkpoint_report['report_sha256'],
            'final_observation_sha256': final_observation_sha256,
        })
        comparisons = []
        for index, (lane, checked) in enumerate(zip(
                ('spec', 'standards'), checked_steps)):
            choice = {
                'stage': 'continue.' + lane,
                'lane': lane,
                'outcome': 'accepted',
                'variant': 'deferred',
            }
            events = [event for event in model.outgoing_stimuli(
                state).to_plain()
                      if _same(explorer.abstract_event(event), choice)]
            _require(len(events) == 1,
                     'final_continuation_model_choice')
            event = events[0]
            reduction = model.reduce(state, event).to_plain()
            successor_state = rv.freeze(reduction['successor'])
            directive = model.legal_directive(successor_state).to_plain()
            _require(_same(reduction['directive'], directive),
                     'final_continuation_model_directive')
            target_facts = successor_state.to_plain()
            if index == 0:
                _require(target_facts['stage'] == 'continue.standards'
                         and target_facts['action']['method'] == 'send_input'
                         and target_facts['action']['lane'] == 'standards'
                         and directive['kind'] == 'action',
                         'final_continuation_spec_target')
            else:
                _require(target_facts['stage'] == 'result.spec'
                         and target_facts['action'] is None
                         and all(target_facts['lanes'][name][
                             'typed_result'] is None
                             for name in ('spec', 'standards'))
                         and directive['kind'] == 'wait_for_observation'
                         and directive['payload']['detail'] == 'typed_result',
                         'final_continuation_standards_target')
            target_id = explorer.state_identity(successor_state)
            boundary = {
                'kind': 'observed_final_' + lane
                        + '_deferred_continuation',
                'choice': choice,
                'source_state_id': source_id,
                'transition_id': explorer.edge_identity(
                    source_id, event, target_id),
                'target_state_id': target_id,
            }
            comparisons.append({
                'schema':
                    'orch-dork/production-graph-final-continuation-edge/v1',
                'scope':
                    'post_progress_deferred_continuation_reconstruction',
                'arrival_order': list(expected_order),
                'continuation_index': index,
                'production_observation_sha256': values.canonical_digest({
                    key: step_inputs[index][key]
                    for key in (
                        'action', 'raw_response', 'pre_hook_report',
                        'post_hook_report', 'advance_report',
                    )
                }),
                'graph_mapping': {
                    'graph_case': explorer.GRAPH_CASE,
                    'graph_owner': explorer.OWNER,
                    'production_boundary': boundary,
                    'gap': {
                        'status': 'PREFIX_ONLY',
                        'observed_boundary_count': 10 + index,
                        'next_uncovered_choices': [
                            explorer.abstract_event(item) for item in
                            model.outgoing_stimuli(
                                successor_state).to_plain()
                        ],
                        'production_graph_complete': False,
                    },
                },
                'model_state': target_facts,
                'input_sha256': input_sha256,
                **{field: False for field in _SERIAL_FALSE_FIELDS},
            })
            state, source_id = successor_state, target_id
        return rv.freeze({
            'schema':
                'orch-dork/production-graph-final-continuation-order/v1',
            'scope': 'post_progress_deferred_continuation_batch',
            'arrival_order': list(expected_order),
            'comparisons': comparisons,
            'serial_comparison_sha256': serial_comparison.report.digest(),
            'checkpoint_report_sha256': checkpoint_report['report_sha256'],
            'final_observation_sha256': final_observation_sha256,
            'input_sha256': input_sha256,
            **{field: False for field in _SERIAL_FALSE_FIELDS},
        })
    except (KeyError, IndexError, TypeError, StopIteration, UnicodeError,
            ValueError, OverflowError, RecursionError) as error:
        if isinstance(error, values.LifecycleContractError):
            raise
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_final_continuation_shape'
        ) from error


def capture_post_progress_deferred_batch_comparison(
        checkpoint_wait_report, serial_comparison, serial_observation,
        final_observation, expected_order, *, capture_session):
    """Issue one final-batch comparison while every raw source still exists."""

    capture_record = _require_live_observation(
        capture_session, 'serial', serial_observation)
    _require_live_observation(capture_session, 'final', final_observation)
    serial_token = (serial_comparison._issue_token
                    if type(serial_comparison)
                    is SerialCheckpointLiveComparison else None)
    serial_record = _ISSUED_SERIAL_COMPARISONS.get(serial_token)
    _require(serial_record is not None
             and serial_record['capture_token']
             is capture_session._capture_token,
             'live_capture_serial_session_join')
    report = compare_post_progress_deferred_batch(
        checkpoint_wait_report, serial_comparison, serial_observation,
        final_observation, expected_order)
    issue_key = (serial_token, report.digest())
    _require(issue_key not in capture_record['issued_final'],
             'live_capture_duplicate_final')
    token = object()
    value = FinalContinuationLiveComparison(
        report=report,
        _serial_parent=serial_comparison,
        _authority=_FINAL_CONTINUATION_AUTHORITY,
        _issue_token=token,
    )
    _ISSUED_FINAL_CONTINUATIONS[token] = {
        'value': weakref.ref(
            value,
            lambda _: _ISSUED_FINAL_CONTINUATIONS.pop(token, None),
        ),
        'pid': os.getpid(),
        'fingerprint': _final_continuation_fingerprint(value),
        'parent': weakref.ref(value._serial_parent),
        'capture_token': capture_session._capture_token,
    }
    capture_record['issued_final'].add(issue_key)
    return value


def _validated_final_continuation_order(
        checkpoint_wait_report, serial_comparison, retained_comparison,
        expected_order):
    """Validate an issued final-batch comparison after its roots expire."""

    _require_issued_serial_comparison(serial_comparison)
    _require_issued_final_continuation(
        retained_comparison, serial_comparison)
    serial_report = _validated_serial_checkpoint_order(
        checkpoint_wait_report, serial_comparison, expected_order)
    report = retained_comparison.report.to_plain()
    try:
        _require(type(report) is dict and set(report) == {
            'schema', 'scope', 'arrival_order', 'comparisons',
            'serial_comparison_sha256', 'checkpoint_report_sha256',
            'final_observation_sha256', 'input_sha256',
            *_SERIAL_FALSE_FIELDS,
        } and report['schema'] ==
            'orch-dork/production-graph-final-continuation-order/v1'
            and report['scope'] ==
            'post_progress_deferred_continuation_batch'
            and report['arrival_order'] == list(expected_order)
            and report['serial_comparison_sha256']
            == serial_comparison.report.digest()
            and report['checkpoint_report_sha256']
            == serial_report['comparisons'][-1][
                'production_observation_sha256']
            and re.fullmatch(
                r'[0-9a-f]{64}', report['final_observation_sha256'])
            is not None
            and report['input_sha256'] == values.canonical_digest({
                'serial_comparison_sha256':
                    report['serial_comparison_sha256'],
                'checkpoint_report_sha256':
                    report['checkpoint_report_sha256'],
                'final_observation_sha256':
                    report['final_observation_sha256'],
            })
            and all(report[field] is False
                    for field in _SERIAL_FALSE_FIELDS),
                 'retained_final_continuation_shape')
        comparisons = report['comparisons']
        _require(type(comparisons) is list and len(comparisons) == 2,
                 'retained_final_continuation_comparisons')
        state = rv.freeze(serial_report['comparisons'][-1]['model_state'])
        source_id = explorer.state_identity(state)
        observations = []
        for index, (lane, comparison) in enumerate(zip(
                ('spec', 'standards'), comparisons)):
            choice = {
                'stage': 'continue.' + lane,
                'lane': lane,
                'outcome': 'accepted',
                'variant': 'deferred',
            }
            _require(type(comparison) is dict and set(comparison) == {
                'schema', 'scope', 'arrival_order', 'continuation_index',
                'production_observation_sha256', 'graph_mapping',
                'model_state', 'input_sha256', *_SERIAL_FALSE_FIELDS,
            } and comparison['schema'] ==
                'orch-dork/production-graph-final-continuation-edge/v1'
                and comparison['scope'] ==
                'post_progress_deferred_continuation_reconstruction'
                and comparison['arrival_order'] == list(expected_order)
                and comparison['continuation_index'] == index
                and comparison['input_sha256'] == report['input_sha256']
                and re.fullmatch(
                    r'[0-9a-f]{64}',
                    comparison['production_observation_sha256']) is not None
                and all(comparison[field] is False
                        for field in _SERIAL_FALSE_FIELDS),
                     'retained_final_continuation_comparison_shape')
            events = [event for event in model.outgoing_stimuli(
                state).to_plain()
                      if _same(explorer.abstract_event(event), choice)]
            _require(len(events) == 1,
                     'retained_final_continuation_model_choice')
            event = events[0]
            reduction = model.reduce(state, event).to_plain()
            successor_state = rv.freeze(reduction['successor'])
            directive = model.legal_directive(successor_state).to_plain()
            _require(_same(reduction['directive'], directive),
                     'retained_final_continuation_directive')
            target_facts = successor_state.to_plain()
            if index == 0:
                _require(target_facts['stage'] == 'continue.standards'
                         and target_facts['action']['method'] == 'send_input'
                         and target_facts['action']['lane'] == 'standards'
                         and directive['kind'] == 'action',
                         'retained_final_continuation_spec_target')
            else:
                _require(target_facts['stage'] == 'result.spec'
                         and target_facts['action'] is None
                         and all(target_facts['lanes'][name][
                             'typed_result'] is None
                             for name in ('spec', 'standards'))
                         and directive['kind'] == 'wait_for_observation'
                         and directive['payload']['detail'] == 'typed_result',
                         'retained_final_continuation_standards_target')
            target_id = explorer.state_identity(successor_state)
            expected_mapping = {
                'graph_case': explorer.GRAPH_CASE,
                'graph_owner': explorer.OWNER,
                'production_boundary': {
                    'kind': 'observed_final_' + lane
                            + '_deferred_continuation',
                    'choice': choice,
                    'source_state_id': source_id,
                    'transition_id': explorer.edge_identity(
                        source_id, event, target_id),
                    'target_state_id': target_id,
                },
                'gap': {
                    'status': 'PREFIX_ONLY',
                    'observed_boundary_count': 10 + index,
                    'next_uncovered_choices': [
                        explorer.abstract_event(item) for item in
                        model.outgoing_stimuli(successor_state).to_plain()
                    ],
                    'production_graph_complete': False,
                },
            }
            _require(_same(comparison['graph_mapping'], expected_mapping)
                     and _same(comparison['model_state'], target_facts),
                     'retained_final_continuation_mapping')
            observations.append(
                comparison['production_observation_sha256'])
            state, source_id = successor_state, target_id
        _require(len(set(observations)) == 2,
                 'retained_final_continuation_observation_identity')
        return report
    except (KeyError, IndexError, TypeError, ValueError,
            OverflowError, RecursionError) as error:
        if isinstance(error, values.LifecycleContractError):
            raise
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_retained_final_shape'
        ) from error


def _spec_result_input_projection(value):
    _require(type(value) is dict and set(value) == {
        'schema', 'arrival_order', 'metadata', 'predecessor_final_report',
        'root_snapshots', 'worker_snapshots', 'handoff_receipt',
        'checkpoint_sources', 'final_sources', 'advance_report',
        'owner_records', 'owner_transport_budget', 'owner_cleanup',
        'capacity_before', 'capacity_after', 'authority_before',
        'authority_after',
    }, 'spec_result_input_shape')
    roots = value['root_snapshots']
    workers = value['worker_snapshots']
    _require(type(roots) is dict and set(roots) == {'before', 'after'}
             and type(workers) is dict
             and set(workers) == {'before', 'after'}
             and all(type(workers[boundary]) is dict
                     and set(workers[boundary]) == {'spec', 'standards'}
                     for boundary in ('before', 'after')),
             'spec_result_snapshot_shape')
    return {
        'schema': value['schema'],
        'arrival_order': rv.freeze(value['arrival_order']).to_plain(),
        'metadata_sha256': values.canonical_digest(
            rv.freeze(value['metadata']).to_plain()),
        'predecessor_final_report_sha256': values.canonical_digest(
            rv.freeze(value['predecessor_final_report']).to_plain()),
        'root_snapshots': {
            name: _serial_raw_fingerprint(raw, 'spec_result_root_' + name)
            for name, raw in roots.items()
        },
        'worker_snapshots': {
            boundary: {
                lane: _serial_raw_fingerprint(
                    raw, 'spec_result_worker_' + boundary + '_' + lane)
                for lane, raw in workers[boundary].items()
            }
            for boundary in ('before', 'after')
        },
        'handoff_receipt_sha256': values.canonical_digest(
            rv.freeze(value['handoff_receipt']).to_plain()),
        'checkpoint_sources_sha256': values.canonical_digest(
            rv.freeze(value['checkpoint_sources']).to_plain()),
        'final_sources_sha256': values.canonical_digest(
            rv.freeze(value['final_sources']).to_plain()),
        'advance_report_sha256': values.canonical_digest(
            rv.freeze(value['advance_report']).to_plain()),
        'owner_records_sha256': values.canonical_digest(
            rv.freeze(value['owner_records']).to_plain()),
        'owner_transport_budget_sha256': values.canonical_digest(
            rv.freeze(value['owner_transport_budget']).to_plain()),
        'owner_cleanup': rv.freeze(value['owner_cleanup']).to_plain(),
        'capacity_before_sha256': values.canonical_digest(
            rv.freeze(value['capacity_before']).to_plain()),
        'capacity_after_sha256': values.canonical_digest(
            rv.freeze(value['capacity_after']).to_plain()),
        'authority_before_sha256': values.canonical_digest(
            rv.freeze(value['authority_before']).to_plain()),
        'authority_after_sha256': values.canonical_digest(
            rv.freeze(value['authority_after']).to_plain()),
    }


def compare_spec_typed_result(
        checkpoint_wait_report, serial_comparison, final_comparison,
        serial_observation, final_observation, spec_observation,
        expected_order):
    """Map one owner-bound spec final without retaining controller authority."""

    _require_issued_serial_comparison(serial_comparison)
    _require_issued_final_continuation(
        final_comparison, serial_comparison)
    final_report = _validated_final_continuation_order(
        checkpoint_wait_report, serial_comparison, final_comparison,
        expected_order)
    live_final = compare_post_progress_deferred_batch(
        checkpoint_wait_report, serial_comparison, serial_observation,
        final_observation, expected_order)
    _require(live_final == final_comparison.report,
             'spec_result_final_parent')
    projection = _spec_result_input_projection(spec_observation)
    try:
        _require(type(expected_order) is tuple and len(expected_order) == 2
                 and set(expected_order) == {'spec', 'standards'}
                 and spec_observation['schema']
                 == 'orch-dork/native-spec-result-observation/v1'
                 and spec_observation['arrival_order']
                 == list(expected_order),
                 'spec_result_scope')
        predecessor = rv.freeze(
            spec_observation['predecessor_final_report']).to_plain()
        _require(_same(predecessor, final_observation['final_report'])
                 and predecessor['decision'] == 'AWAITING_WORKER_RESULTS'
                 and predecessor['action'] is None
                 and predecessor['review_packet'] is None
                 and [row['status'] for row in predecessor['worker_results']]
                 == ['PENDING', 'PENDING'],
                 'spec_result_predecessor')
        metadata = spec_observation['metadata']
        _require(_same(metadata, final_observation['metadata']),
                 'spec_result_metadata')

        roots = spec_observation['root_snapshots']
        workers = spec_observation['worker_snapshots']
        final_workers = final_observation['worker_snapshots']['after']
        _require(roots['before']
                 == final_observation['root_snapshots']['after_standards']
                 and roots['after'] == roots['before']
                 and workers['before'] == final_workers
                 and workers['after']['standards']
                 == workers['before']['standards'],
                 'spec_result_source_join')
        rows = _appended_json_rows(
            workers['before']['spec'], workers['after']['spec'],
            'spec_result_worker_spec')
        _require(len(rows) == 5
                 and rows[-1]['type'] == 'event_msg'
                 and rows[-1]['payload'].get('type') == 'task_complete'
                 and type(rows[-1]['payload'].get(
                     'last_agent_message')) is str
                 and _same(_strict_json_record(
                     rows[-1]['payload']['last_agent_message']),
                     spec_observation['handoff_receipt']),
                 'spec_result_terminal_rows')

        checkpoint_sources = rv.freeze(
            spec_observation['checkpoint_sources']).to_plain()
        final_sources = rv.freeze(
            spec_observation['final_sources']).to_plain()
        predecessor_bindings = predecessor['controller_transitions'][-1][
            'report']['stage_report']['receipt']['bindings']
        _require(predecessor_bindings['checkpoint_sources_sha256']
                 == values.canonical_digest(checkpoint_sources),
                 'spec_result_checkpoint_source_join')
        _require(worker_finals.validate_native_worker_final_arrivals(
            final_sources, checkpoint_sources).get('valid') is True
            and final_sources['status'] == 'OBSERVED'
            and final_sources['issues'] == []
            and final_sources['completed_lane_ids'] == ['spec']
            and final_sources['pending_lane_ids'] == ['standards']
            and final_sources['raw_final_custody_observed'] is True
            and all(final_sources[field] is False
                    for field in _SERIAL_FALSE_FIELDS),
                 'spec_result_final_sources')
        source_workers = final_sources['evidence']['workers']
        _require(set(source_workers) == {'spec'},
                 'spec_result_source_lanes')
        source_spec = source_workers['spec']
        spec_report = source_spec['result_report']
        pending_spec, pending_standards = predecessor['worker_results']
        _require(qualification_results.validate_worker_result_report(
            spec_report).get('valid') is True
            and spec_report['status'] == 'OBSERVED'
            and spec_report['issues'] == []
            and spec_report['read_error'] is None
            and spec_report['task_spec'] == pending_spec['task_spec']
            and spec_report['binding'] == pending_spec['binding']
            and spec_report['handoff_receipt']
            == spec_observation['handoff_receipt']
            and source_spec['observed_checkpoint_sha256']
            == hashlib.sha256(workers['before']['spec']).hexdigest()
            and source_spec['source']['file_sha256']
            == hashlib.sha256(workers['after']['spec']).hexdigest()
            and source_spec['source']['prefix_bytes']
            == len(workers['after']['spec'])
            and spec_report['runtime_observation']['source_sha256']
            == source_spec['source']['file_sha256'],
                 'spec_result_worker_binding')

        advance = rv.freeze(spec_observation['advance_report']).to_plain()
        result_rows = advance['worker_results']
        _require(successor.validate_issue94_successor_action_advance_report(
            advance).get('valid') is True
            and advance['status'] == 'PASS'
            and advance['decision'] == 'AWAITING_WORKER_RESULTS'
            and advance['action'] is None
            and advance['review_packet'] is None
            and [row['status'] for row in result_rows]
            == ['OBSERVED', 'PENDING']
            and result_rows[0] == spec_report
            and result_rows[1] == pending_standards
            and [row['program']['operation']
                 for row in advance['controller_transitions']]
            == ['inspect']
            and advance['boundary']['native_action_called_by_bridge'] is False
            and advance['boundary']['controller_stage_advanced'] is False
            and advance['counters']['controller_stages'] == 0
            and advance['counters']['native_actions'] == 0,
                 'spec_result_advance')

        budget = spec_observation['owner_transport_budget']
        owner_records = spec_observation['owner_records']
        _require(type(owner_records) is list and bool(owner_records)
                 and all(type(row) is dict and 'error' not in row
                         for row in owner_records)
                 and type(budget) is dict and set(budget) == {
                     'max_calls', 'calls_retained', 'within_bound',
                 }
                 and budget['calls_retained'] == len(owner_records)
                 and 0 < budget['calls_retained'] <= budget['max_calls'] <= 256
                 and budget['within_bound'] is True
                 and spec_observation['owner_cleanup'] == {
                     'closed': True, 'socket_removed': True,
                 }, 'spec_result_owner_scope')
        _require(_same(spec_observation['capacity_before'],
                       final_observation['capacity_after'])
                 and _same(spec_observation['capacity_after'],
                           spec_observation['capacity_before'])
                 and _same(spec_observation['authority_before'],
                           final_observation['authority_after'])
                 and _same(spec_observation['authority_after'],
                           spec_observation['authority_before']),
                 'spec_result_authority_scope')

        state = rv.freeze(final_report['comparisons'][-1]['model_state'])
        source_id = explorer.state_identity(state)
        _require(source_id == final_report['comparisons'][-1][
            'graph_mapping']['production_boundary']['target_state_id'],
                 'spec_result_graph_source')
        choice = {
            'stage': 'result.spec', 'lane': 'spec',
            'outcome': 'accepted', 'variant': 'evidence',
        }
        events = [event for event in model.outgoing_stimuli(state).to_plain()
                  if _same(explorer.abstract_event(event), choice)]
        _require(len(events) == 1, 'spec_result_model_choice')
        event = events[0]
        reduction = model.reduce(state, event).to_plain()
        successor_state = rv.freeze(reduction['successor'])
        directive = model.legal_directive(successor_state).to_plain()
        _require(_same(reduction['directive'], directive),
                 'spec_result_model_directive')
        target_facts = successor_state.to_plain()
        _require(target_facts['stage'] == 'result.standards'
                 and target_facts['action'] is None
                 and target_facts['lanes']['spec']['typed_result']
                 is not None
                 and target_facts['lanes']['standards']['typed_result']
                 is None
                 and directive['kind'] == 'wait_for_observation'
                 and directive['payload']['detail'] == 'typed_result',
                 'spec_result_model_target')
        target_id = explorer.state_identity(successor_state)
        spec_observation_sha256 = values.canonical_digest(projection)
        input_sha256 = values.canonical_digest({
            'final_continuation_sha256': final_comparison.report.digest(),
            'spec_observation_sha256': spec_observation_sha256,
        })
        comparison = {
            'schema': 'orch-dork/production-graph-spec-result-edge/v1',
            'scope': 'owner_bound_spec_typed_result_reconstruction',
            'arrival_order': list(expected_order),
            'production_observation_sha256': advance['report_sha256'],
            'graph_mapping': {
                'graph_case': explorer.GRAPH_CASE,
                'graph_owner': explorer.OWNER,
                'production_boundary': {
                    'kind': 'observed_spec_typed_result',
                    'choice': choice,
                    'source_state_id': source_id,
                    'transition_id': explorer.edge_identity(
                        source_id, event, target_id),
                    'target_state_id': target_id,
                },
                'gap': {
                    'status': 'PREFIX_ONLY',
                    'observed_boundary_count': 12,
                    'next_uncovered_choices': [
                        explorer.abstract_event(item) for item in
                        model.outgoing_stimuli(successor_state).to_plain()
                    ],
                    'production_graph_complete': False,
                },
            },
            'model_state': target_facts,
            'input_sha256': input_sha256,
            **{field: False for field in _SERIAL_FALSE_FIELDS},
        }
        return rv.freeze({
            'schema': 'orch-dork/production-graph-spec-result-order/v1',
            'scope': 'spec_typed_result_frontier',
            'arrival_order': list(expected_order),
            'comparisons': [comparison],
            'final_continuation_sha256': final_comparison.report.digest(),
            'spec_observation_sha256': spec_observation_sha256,
            'input_sha256': input_sha256,
            **{field: False for field in _SERIAL_FALSE_FIELDS},
        })
    except (KeyError, IndexError, TypeError, StopIteration, UnicodeError,
            ValueError, OverflowError, RecursionError) as error:
        if isinstance(error, values.LifecycleContractError):
            raise
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_spec_result_shape'
        ) from error


def capture_spec_typed_result_comparison(
        checkpoint_wait_report, serial_comparison, final_comparison,
        serial_observation, final_observation, spec_observation,
        expected_order, *, capture_session):
    """Issue one spec-result comparison while its raw sources still exist."""

    capture_record = _require_live_observation(
        capture_session, 'serial', serial_observation)
    _require_live_observation(capture_session, 'final', final_observation)
    _require_live_observation(capture_session, 'spec', spec_observation)
    final_token = (final_comparison._issue_token
                   if type(final_comparison)
                   is FinalContinuationLiveComparison else None)
    final_record = _ISSUED_FINAL_CONTINUATIONS.get(final_token)
    _require(final_record is not None
             and final_record['capture_token']
             is capture_session._capture_token,
             'live_capture_final_session_join')
    report = compare_spec_typed_result(
        checkpoint_wait_report, serial_comparison, final_comparison,
        serial_observation, final_observation, spec_observation,
        expected_order)
    issue_key = (final_token, report.digest())
    _require(issue_key not in capture_record['issued_spec'],
             'live_capture_duplicate_spec_result')
    token = object()
    value = SpecResultLiveComparison(
        report=report,
        _final_parent=final_comparison,
        _authority=_SPEC_RESULT_AUTHORITY,
        _issue_token=token,
    )
    _ISSUED_SPEC_RESULTS[token] = {
        'value': weakref.ref(
            value,
            lambda _: _ISSUED_SPEC_RESULTS.pop(token, None),
        ),
        'pid': os.getpid(),
        'fingerprint': _spec_result_fingerprint(value),
        'parent': weakref.ref(value._final_parent),
        'capture_token': capture_session._capture_token,
    }
    capture_record['issued_spec'].add(issue_key)
    return value


def _validated_spec_result_order(
        checkpoint_wait_report, serial_comparison, final_comparison,
        retained_comparison, expected_order):
    """Validate an issued spec-result comparison after its sources expire."""

    _require_issued_serial_comparison(serial_comparison)
    _require_issued_final_continuation(final_comparison, serial_comparison)
    _require_issued_spec_result(retained_comparison, final_comparison)
    final_report = _validated_final_continuation_order(
        checkpoint_wait_report, serial_comparison, final_comparison,
        expected_order)
    report = retained_comparison.report.to_plain()
    try:
        _require(type(report) is dict and set(report) == {
            'schema', 'scope', 'arrival_order', 'comparisons',
            'final_continuation_sha256', 'spec_observation_sha256',
            'input_sha256', *_SERIAL_FALSE_FIELDS,
        } and report['schema']
            == 'orch-dork/production-graph-spec-result-order/v1'
            and report['scope'] == 'spec_typed_result_frontier'
            and report['arrival_order'] == list(expected_order)
            and report['final_continuation_sha256']
            == final_comparison.report.digest()
            and re.fullmatch(
                r'[0-9a-f]{64}', report['spec_observation_sha256'])
            is not None
            and report['input_sha256'] == values.canonical_digest({
                'final_continuation_sha256':
                    report['final_continuation_sha256'],
                'spec_observation_sha256':
                    report['spec_observation_sha256'],
            })
            and all(report[field] is False
                    for field in _SERIAL_FALSE_FIELDS),
                 'retained_spec_result_shape')
        comparisons = report['comparisons']
        _require(type(comparisons) is list and len(comparisons) == 1,
                 'retained_spec_result_comparisons')
        comparison = comparisons[0]
        choice = {
            'stage': 'result.spec', 'lane': 'spec',
            'outcome': 'accepted', 'variant': 'evidence',
        }
        _require(type(comparison) is dict and set(comparison) == {
            'schema', 'scope', 'arrival_order',
            'production_observation_sha256', 'graph_mapping',
            'model_state', 'input_sha256', *_SERIAL_FALSE_FIELDS,
        } and comparison['schema']
            == 'orch-dork/production-graph-spec-result-edge/v1'
            and comparison['scope']
            == 'owner_bound_spec_typed_result_reconstruction'
            and comparison['arrival_order'] == list(expected_order)
            and comparison['input_sha256'] == report['input_sha256']
            and re.fullmatch(
                r'[0-9a-f]{64}',
                comparison['production_observation_sha256']) is not None
            and all(comparison[field] is False
                    for field in _SERIAL_FALSE_FIELDS),
                 'retained_spec_result_comparison_shape')
        state = rv.freeze(final_report['comparisons'][-1]['model_state'])
        source_id = explorer.state_identity(state)
        events = [event for event in model.outgoing_stimuli(state).to_plain()
                  if _same(explorer.abstract_event(event), choice)]
        _require(len(events) == 1, 'retained_spec_result_model_choice')
        event = events[0]
        reduction = model.reduce(state, event).to_plain()
        successor_state = rv.freeze(reduction['successor'])
        directive = model.legal_directive(successor_state).to_plain()
        _require(_same(reduction['directive'], directive),
                 'retained_spec_result_directive')
        target_id = explorer.state_identity(successor_state)
        expected_mapping = {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': {
                'kind': 'observed_spec_typed_result',
                'choice': choice,
                'source_state_id': source_id,
                'transition_id': explorer.edge_identity(
                    source_id, event, target_id),
                'target_state_id': target_id,
            },
            'gap': {
                'status': 'PREFIX_ONLY',
                'observed_boundary_count': 12,
                'next_uncovered_choices': [
                    explorer.abstract_event(item) for item in
                    model.outgoing_stimuli(successor_state).to_plain()
                ],
                'production_graph_complete': False,
            },
        }
        _require(_same(comparison['graph_mapping'], expected_mapping)
                 and _same(comparison['model_state'],
                           successor_state.to_plain()),
                 'retained_spec_result_mapping')
        return report
    except (KeyError, IndexError, TypeError, ValueError,
            OverflowError, RecursionError) as error:
        if isinstance(error, values.LifecycleContractError):
            raise
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_retained_spec_result_shape'
        ) from error


def _standards_result_input_projection(value):
    _require(type(value) is dict and set(value) == {
        'schema', 'arrival_order', 'metadata',
        'predecessor_spec_observation', 'root_snapshots',
        'worker_snapshots', 'handoff_receipt', 'checkpoint_sources',
        'final_source_observations', 'retention_source_observation_count',
        'aggregation_source_observation_count', 'final_sources',
        'retention_report',
        'aggregation_report', 'owner_records', 'owner_transport_budget',
        'owner_cleanup', 'capacity_before', 'capacity_after_retention',
        'capacity_after', 'authority_before', 'authority_after_retention',
        'authority_after',
    }, 'standards_result_input_shape')
    roots = value['root_snapshots']
    workers = value['worker_snapshots']
    _require(type(roots) is dict and set(roots) == {'before', 'after'}
             and type(workers) is dict
             and set(workers) == {'before', 'after'}
             and all(type(workers[boundary]) is dict
                     and set(workers[boundary]) == {'spec', 'standards'}
                     for boundary in ('before', 'after')),
             'standards_result_snapshot_shape')
    return {
        'schema': value['schema'],
        'arrival_order': rv.freeze(value['arrival_order']).to_plain(),
        'metadata_sha256': values.canonical_digest(
            rv.freeze(value['metadata']).to_plain()),
        'predecessor_spec_observation_sha256': values.canonical_digest(
            _spec_result_input_projection(
                value['predecessor_spec_observation'])),
        'root_snapshots': {
            name: _serial_raw_fingerprint(
                raw, 'standards_result_root_' + name)
            for name, raw in roots.items()
        },
        'worker_snapshots': {
            boundary: {
                lane: _serial_raw_fingerprint(
                    raw, 'standards_result_worker_' + boundary + '_' + lane)
                for lane, raw in workers[boundary].items()
            }
            for boundary in ('before', 'after')
        },
        'handoff_receipt_sha256': values.canonical_digest(
            rv.freeze(value['handoff_receipt']).to_plain()),
        'checkpoint_sources_sha256': values.canonical_digest(
            rv.freeze(value['checkpoint_sources']).to_plain()),
        'final_source_observations_sha256': values.canonical_digest(
            rv.freeze(value['final_source_observations']).to_plain()),
        'retention_source_observation_count':
            value['retention_source_observation_count'],
        'aggregation_source_observation_count':
            value['aggregation_source_observation_count'],
        'final_sources_sha256': values.canonical_digest(
            rv.freeze(value['final_sources']).to_plain()),
        'retention_report_sha256': values.canonical_digest(
            rv.freeze(value['retention_report']).to_plain()),
        'aggregation_report_sha256': values.canonical_digest(
            rv.freeze(value['aggregation_report']).to_plain()),
        'owner_records_sha256': values.canonical_digest(
            rv.freeze(value['owner_records']).to_plain()),
        'owner_transport_budget_sha256': values.canonical_digest(
            rv.freeze(value['owner_transport_budget']).to_plain()),
        'owner_cleanup': rv.freeze(value['owner_cleanup']).to_plain(),
        'capacity_before_sha256': values.canonical_digest(
            rv.freeze(value['capacity_before']).to_plain()),
        'capacity_after_retention_sha256': values.canonical_digest(
            rv.freeze(value['capacity_after_retention']).to_plain()),
        'capacity_after_sha256': values.canonical_digest(
            rv.freeze(value['capacity_after']).to_plain()),
        'authority_before_sha256': values.canonical_digest(
            rv.freeze(value['authority_before']).to_plain()),
        'authority_after_retention_sha256': values.canonical_digest(
            rv.freeze(value['authority_after_retention']).to_plain()),
        'authority_after_sha256': values.canonical_digest(
            rv.freeze(value['authority_after']).to_plain()),
    }


def _stage_authority_projection(authority, cursor, label):
    _require(type(authority) is dict and set(authority) == {
        'status', 'owner', 'identity', 'tip', 'lifecycle', 'policy',
        'hook_projection', 'ground_state_sha256',
        'store_identity_sha256',
    } and authority['status'] == 'VERIFIED'
        and type(authority['owner']) is dict
        and type(authority['identity']) is dict
        and type(authority['hook_projection']) is dict
        and type(cursor) is dict
        and authority['tip'] == cursor,
             label + '_shape')
    owner = authority['owner']
    identity = authority['identity']
    hook = authority['hook_projection']
    hook_core = {
        'schema': native_contract.HOOK_BINDING_SCHEMA,
        'controller_id': owner['controller_id'],
        'controller_run_id': cursor['run_id'],
        'controller_seq': cursor['seq'],
        'controller_event_hash': cursor['event_hash'],
        'root_thread_id': identity['root_thread_id'],
        'root_session_id': identity['root_session_id'],
        'root_model': identity['root_model'],
        'hook_definition_sha256': identity['hook_definition_sha256'],
        'hook_registration_sha256': identity[
            'hook_registration_sha256'],
        'store_identity_sha256': authority['store_identity_sha256'],
        'ground_state_sha256': authority['ground_state_sha256'],
        'status': 'WAITING',
        'action': None,
    }
    expected_binding_sha256 = hashlib.sha256(
        host_adapter.canonical_bytes(hook_core)).hexdigest()
    _require(set(hook) == {
        'controller_id', 'controller_run_id', 'controller_seq',
        'controller_event_hash', 'binding_sha256',
    } and owner['controller_id'] == identity['controller_id']
             == hook['controller_id']
             and owner['controller_run_id']
             == identity['controller_run_id']
             == hook['controller_run_id'] == cursor['run_id']
             and hook['controller_seq'] == cursor['seq']
             and hook['controller_event_hash'] == cursor['event_hash']
             and hook['binding_sha256'] == expected_binding_sha256,
             label + '_cursor')
    return {
        'authority': {
            key: rv.freeze(authority[key]).to_plain()
            for key in (
                'status', 'owner', 'identity', 'lifecycle', 'policy',
                'ground_state_sha256', 'store_identity_sha256',
            )
        },
        'hook': {
            key: rv.freeze(value).to_plain()
            for key, value in hook.items()
            if key not in {
                'controller_seq', 'controller_event_hash', 'binding_sha256',
            }
        },
    }


def _semantic_review_input_projection(value):
    _require(type(value) is dict and set(value) == {
        'schema', 'outcome', 'arrival_order',
        'predecessor_standards_observation', 'checkpoint_metadata',
        'review_metadata', 'review_packet', 'verifications', 'submission',
        'submission_context', 'call_arguments', 'acknowledgement',
        'expectation', 'root_snapshots', 'worker_snapshots',
        'submitted_report', 'pending_reports', 'final_report',
        'review_source_observations', 'review_owner_snapshots',
        'review_owner_records', 'review_owner_transport_budgets',
        'review_owner_cleanups',
        'review_query_counts', 'worker_final_source_observation_count',
        'post_outcome_replay_report', 'post_outcome_replay_query_count',
        'submission_owner_records', 'submission_owner_transport_budget',
        'submission_owner_cleanup', 'submission_refusal_attempts',
        'capacity_before',
        'capacity_after_submission', 'capacity_after_pending',
        'capacity_after', 'capacity_after_replay', 'authority_before',
        'authority_after_submission', 'authority_after_pending',
        'authority_after', 'authority_after_replay',
    }, 'semantic_review_input_shape')
    roots = value['root_snapshots']
    workers = value['worker_snapshots']
    _require(type(roots) is dict
             and set(roots) == {'before', 'after_submission', 'after'}
             and type(workers) is dict
             and set(workers) == {'before', 'after'}
             and all(type(workers[boundary]) is dict
                     and set(workers[boundary]) == {'spec', 'standards'}
                     for boundary in ('before', 'after')),
             'semantic_review_snapshot_shape')

    def digest(value):
        return values.canonical_digest(rv.freeze(value).to_plain())

    def digest_with_raw_bytes(value, label):
        def project(current, path):
            if type(current) is bytes:
                return {
                    'kind': 'raw-bytes',
                    **_serial_raw_fingerprint(
                        current, label + '_' + '_'.join(path)),
                }
            if type(current) is list:
                return [
                    project(child, (*path, str(index)))
                    for index, child in enumerate(current)
                ]
            if type(current) is dict:
                _require(all(type(key) is str for key in current),
                         'semantic_review_' + label + '_key')
                return {
                    key: project(child, (*path, key))
                    for key, child in current.items()
                }
            return rv.freeze(current).to_plain()

        return values.canonical_digest(project(value, ()))

    return {
        'schema': value['schema'],
        'outcome': value['outcome'],
        'arrival_order': rv.freeze(value['arrival_order']).to_plain(),
        'predecessor_standards_observation_sha256':
            values.canonical_digest(_standards_result_input_projection(
                value['predecessor_standards_observation'])),
        'checkpoint_metadata_sha256': digest(value['checkpoint_metadata']),
        'review_metadata_sha256': digest(value['review_metadata']),
        'review_packet_sha256': digest(value['review_packet']),
        'verifications_sha256': digest(value['verifications']),
        'submission_sha256': digest(value['submission']),
        'submission_context_sha256': digest(value['submission_context']),
        'call_arguments_sha256': digest(value['call_arguments']),
        'acknowledgement_sha256': digest(value['acknowledgement']),
        'expectation_sha256': digest(value['expectation']),
        'root_snapshots': {
            name: _serial_raw_fingerprint(
                raw, 'semantic_review_root_' + name)
            for name, raw in roots.items()
        },
        'worker_snapshots': {
            boundary: {
                lane: _serial_raw_fingerprint(
                    raw, 'semantic_review_worker_' + boundary + '_' + lane)
                for lane, raw in workers[boundary].items()
            }
            for boundary in ('before', 'after')
        },
        'submitted_report_sha256': digest(value['submitted_report']),
        'pending_reports_sha256': digest(value['pending_reports']),
        'final_report_sha256': digest(value['final_report']),
        'review_source_observations_sha256': digest(
            value['review_source_observations']),
        'review_owner_snapshots_sha256': digest(
            value['review_owner_snapshots']),
        'review_owner_records_sha256': digest(
            value['review_owner_records']),
        'review_owner_transport_budgets': rv.freeze(
            value['review_owner_transport_budgets']).to_plain(),
        'review_owner_cleanups': rv.freeze(
            value['review_owner_cleanups']).to_plain(),
        'review_query_counts': rv.freeze(
            value['review_query_counts']).to_plain(),
        'worker_final_source_observation_count':
            value['worker_final_source_observation_count'],
        'post_outcome_replay_report_sha256': digest(
            value['post_outcome_replay_report']),
        'post_outcome_replay_query_count':
            value['post_outcome_replay_query_count'],
        'submission_owner_records_sha256': digest(
            value['submission_owner_records']),
        'submission_owner_transport_budget_sha256': digest(
            value['submission_owner_transport_budget']),
        'submission_owner_cleanup': rv.freeze(
            value['submission_owner_cleanup']).to_plain(),
        'submission_refusal_attempts_sha256': digest_with_raw_bytes(
            value['submission_refusal_attempts'], 'submission_refusal'),
        'capacity_before_sha256': digest(value['capacity_before']),
        'capacity_after_submission_sha256': digest(
            value['capacity_after_submission']),
        'capacity_after_pending_sha256': digest(
            value['capacity_after_pending']),
        'capacity_after_sha256': digest(value['capacity_after']),
        'capacity_after_replay_sha256': digest(
            value['capacity_after_replay']),
        'authority_before_sha256': digest(value['authority_before']),
        'authority_after_submission_sha256': digest(
            value['authority_after_submission']),
        'authority_after_pending_sha256': digest(
            value['authority_after_pending']),
        'authority_after_sha256': digest(value['authority_after']),
        'authority_after_replay_sha256': digest(
            value['authority_after_replay']),
    }


def _terminal_cleanup_input_projection(value):
    _require(type(value) is dict and set(value) == {
        'schema', 'review_outcome', 'cleanup_outcomes', 'arrival_order',
        'predecessor_review_observation', 'verification_report',
        'cleanup_authorization_report', 'close_steps', 'root_snapshots',
        'worker_snapshots', 'worker_final_source_observation_count',
        'controller_state_before', 'controller_state_after',
        'controller_rows_after', 'capacity_before',
        'capacity_after_verification', 'capacity_after_authorization',
        'capacity_after', 'authority_before', 'authority_after_verification',
        'authority_after_authorization', 'authority_after',
    }, 'terminal_cleanup_input_shape')
    roots = value['root_snapshots']
    workers = value['worker_snapshots']
    _require(type(roots) is dict and set(roots) == {'before', 'after'}
             and type(workers) is dict
             and set(workers) == {'before', 'after'}
             and all(type(workers[boundary]) is dict
                     and set(workers[boundary]) == {'spec', 'standards'}
                     for boundary in ('before', 'after')),
             'terminal_cleanup_snapshot_shape')

    def digest(current):
        return values.canonical_digest(rv.freeze(current).to_plain())

    return {
        'schema': value['schema'],
        'review_outcome': value['review_outcome'],
        'cleanup_outcomes': rv.freeze(value['cleanup_outcomes']).to_plain(),
        'arrival_order': rv.freeze(value['arrival_order']).to_plain(),
        'predecessor_review_observation_sha256': values.canonical_digest(
            _semantic_review_input_projection(
                value['predecessor_review_observation'])),
        'verification_report_sha256': digest(value['verification_report']),
        'cleanup_authorization_report_sha256': digest(
            value['cleanup_authorization_report']),
        'close_steps_sha256': digest(value['close_steps']),
        'root_snapshots': {
            boundary: _serial_raw_fingerprint(
                roots[boundary], 'terminal_cleanup_root_' + boundary)
            for boundary in ('before', 'after')
        },
        'worker_snapshots': {
            boundary: {
                lane: _serial_raw_fingerprint(
                    workers[boundary][lane],
                    'terminal_cleanup_worker_' + boundary + '_' + lane)
                for lane in ('spec', 'standards')
            }
            for boundary in ('before', 'after')
        },
        'worker_final_source_observation_count':
            value['worker_final_source_observation_count'],
        'controller_state_before_sha256': digest(
            value['controller_state_before']),
        'controller_state_after_sha256': digest(
            value['controller_state_after']),
        'controller_rows_after_sha256': digest(
            value['controller_rows_after']),
        'capacity_before_sha256': digest(value['capacity_before']),
        'capacity_after_verification_sha256': digest(
            value['capacity_after_verification']),
        'capacity_after_authorization_sha256': digest(
            value['capacity_after_authorization']),
        'capacity_after_sha256': digest(value['capacity_after']),
        'authority_before_sha256': digest(value['authority_before']),
        'authority_after_verification_sha256': digest(
            value['authority_after_verification']),
        'authority_after_authorization_sha256': digest(
            value['authority_after_authorization']),
        'authority_after_sha256': digest(value['authority_after']),
    }


def compare_standards_typed_result_and_aggregation(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, serial_observation, final_observation,
        spec_observation, standards_observation, expected_order):
    """Map the standards final and retained aggregation to review wait."""

    _require_issued_serial_comparison(serial_comparison)
    _require_issued_final_continuation(final_comparison, serial_comparison)
    _require_issued_spec_result(spec_comparison, final_comparison)
    spec_report = _validated_spec_result_order(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, expected_order)
    live_spec = compare_spec_typed_result(
        checkpoint_wait_report, serial_comparison, final_comparison,
        serial_observation, final_observation, spec_observation,
        expected_order)
    _require(live_spec == spec_comparison.report,
             'standards_result_spec_parent')
    projection = _standards_result_input_projection(standards_observation)
    try:
        _require(type(expected_order) is tuple and len(expected_order) == 2
                 and set(expected_order) == {'spec', 'standards'}
                 and standards_observation['schema']
                 == ('orch-dork/native-standards-result-aggregation-'
                     'observation/v1')
                 and standards_observation['arrival_order']
                 == list(expected_order),
                 'standards_result_scope')
        predecessor = standards_observation[
            'predecessor_spec_observation']
        _require(predecessor == spec_observation
                 and predecessor['advance_report']['decision']
                 == 'AWAITING_WORKER_RESULTS'
                 and [row['status'] for row in
                      predecessor['advance_report']['worker_results']]
                 == ['OBSERVED', 'PENDING'],
                 'standards_result_predecessor')
        _require(_same(standards_observation['metadata'],
                       spec_observation['metadata'])
                 and _same(standards_observation['checkpoint_sources'],
                           spec_observation['checkpoint_sources']),
                 'standards_result_source_context')

        roots = standards_observation['root_snapshots']
        workers = standards_observation['worker_snapshots']
        spec_after = spec_observation['worker_snapshots']['after']
        _require(roots['before'] == spec_observation['root_snapshots']['after']
                 and roots['after'] == roots['before']
                 and workers['before'] == spec_after
                 and workers['after']['spec'] == workers['before']['spec'],
                 'standards_result_source_join')
        rows = _appended_json_rows(
            workers['before']['standards'], workers['after']['standards'],
            'standards_result_worker_standards')
        _require(len(rows) == 5
                 and rows[-1]['type'] == 'event_msg'
                 and rows[-1]['payload'].get('type') == 'task_complete'
                 and type(rows[-1]['payload'].get(
                     'last_agent_message')) is str
                 and _same(_strict_json_record(
                     rows[-1]['payload']['last_agent_message']),
                     standards_observation['handoff_receipt']),
                 'standards_result_terminal_rows')

        checkpoint_sources = rv.freeze(
            standards_observation['checkpoint_sources']).to_plain()
        source_reads = rv.freeze(
            standards_observation['final_source_observations']).to_plain()
        final_sources = rv.freeze(
            standards_observation['final_sources']).to_plain()
        _require(type(source_reads) is list and len(source_reads) == 2
                 and source_reads[0] == source_reads[1] == final_sources
                 and standards_observation[
                     'retention_source_observation_count'] == 2
                 and standards_observation[
                     'aggregation_source_observation_count'] == 2
                 and worker_finals.validate_complete_native_worker_finals(
                     final_sources, checkpoint_sources).get('valid') is True
                 and final_sources['status'] == 'OBSERVED'
                 and final_sources['issues'] == []
                 and final_sources['continuation_permitted'] is False
                 and final_sources['terminal_claim_permitted'] is False
                 and final_sources['provider_free'] is True
                 and final_sources['native_calls'] == 0
                 and final_sources['model_calls'] == 0
                 and final_sources['cost_usd'] is None,
                 'standards_result_final_sources')
        source_workers = final_sources['evidence']['workers']
        _require(set(source_workers) == {'spec', 'standards'},
                 'standards_result_source_lanes')
        source_results = [
            source_workers[lane]['result_report']
            for lane in ('spec', 'standards')
        ]
        prior_results = predecessor['advance_report']['worker_results']
        source_standards = source_workers['standards']
        standards_result = source_standards['result_report']
        _require(source_results[0] == prior_results[0]
                 and qualification_results.validate_worker_result_report(
                     standards_result).get('valid') is True
                 and standards_result['status'] == 'OBSERVED'
                 and standards_result['issues'] == []
                 and standards_result['read_error'] is None
                 and standards_result['task_spec']
                 == prior_results[1]['task_spec']
                 and standards_result['binding']
                 == prior_results[1]['binding']
                 and standards_result['handoff_receipt']
                 == standards_observation['handoff_receipt']
                 and source_standards['observed_checkpoint_sha256']
                 == hashlib.sha256(
                     workers['before']['standards']).hexdigest()
                 and source_standards['source']['file_sha256']
                 == hashlib.sha256(
                     workers['after']['standards']).hexdigest()
                 and source_standards['source']['prefix_bytes']
                 == len(workers['after']['standards'])
                 and standards_result['runtime_observation']['source_sha256']
                 == source_standards['source']['file_sha256'],
                 'standards_result_worker_binding')

        retention = rv.freeze(
            standards_observation['retention_report']).to_plain()
        aggregation = rv.freeze(
            standards_observation['aggregation_report']).to_plain()
        retained_results = retention['worker_results']
        retention_stage = retention['controller_transitions'][-1][
            'report']['stage_report']
        aggregation_stage = aggregation['controller_transitions'][-1][
            'report']['stage_report']
        _require(successor.validate_issue94_successor_action_advance_report(
            retention).get('valid') is True
            and retention['status'] == 'PASS'
            and retention['decision'] == 'AWAITING_RESULT_AGGREGATION'
            and retention['action'] is None
            and retention['review_packet'] is None
            and retained_results == source_results
            and [row['program']['operation']
                 for row in retention['controller_transitions']]
            == ['inspect', 'stage']
            and retention_stage['receipt']['stage'] == 'worker_results'
            and retention_stage['receipt']['bindings']['worker_results']
            == source_results
            and retention['boundary']['native_action_called_by_bridge']
            is False
            and retention['boundary']['controller_stage_advanced'] is True
            and retention['counters']['controller_stages'] == 1
            and retention['counters']['native_actions'] == 0,
                 'standards_result_retention')
        _require(successor.validate_issue94_successor_action_advance_report(
            aggregation).get('valid') is True
            and aggregation['status'] == 'PASS'
            and aggregation['decision'] == 'AWAITING_SOL_REVIEW'
            and aggregation['action'] is None
            and aggregation['worker_results'] == retained_results
            and [row['program']['operation']
                 for row in aggregation['controller_transitions']]
            == ['inspect', 'stage']
            and aggregation_stage['receipt']['stage']
            == 'result_aggregation'
            and aggregation_stage['receipt']['bindings']['worker_results']
            == retained_results
            and qualification_review.validate_review_packet(
                aggregation['review_packet']).get('valid') is True
            and aggregation['boundary']['native_action_called_by_bridge']
            is False
            and aggregation['boundary']['controller_stage_advanced'] is True
            and aggregation['counters']['controller_stages'] == 1
            and aggregation['counters']['native_actions'] == 0,
                 'standards_result_aggregation')

        budget = standards_observation['owner_transport_budget']
        owner_records = standards_observation['owner_records']
        _require(type(owner_records) is list and bool(owner_records)
                 and all(type(row) is dict and 'error' not in row
                         for row in owner_records)
                 and type(budget) is dict and set(budget) == {
                     'max_calls', 'calls_retained', 'within_bound',
                 }
                 and budget['calls_retained'] == len(owner_records)
                 and 0 < budget['calls_retained'] <= budget['max_calls'] <= 256
                 and budget['within_bound'] is True
                 and standards_observation['owner_cleanup'] == {
                     'closed': True, 'socket_removed': True,
                 }, 'standards_result_owner_scope')
        before_authority = standards_observation['authority_before']
        retention_authority = standards_observation[
            'authority_after_retention']
        after_authority = standards_observation['authority_after']
        retention_cursor = retention['controller_transitions'][-1][
            'report']['cursor']
        aggregation_cursor = aggregation['controller_transitions'][-1][
            'report']['cursor']
        before_projection = _stage_authority_projection(
            before_authority, retention['authority_before']['tip'],
            'standards_result_authority_before')
        retention_projection = _stage_authority_projection(
            retention_authority, retention_cursor,
            'standards_result_authority_after_retention')
        after_projection = _stage_authority_projection(
            after_authority, aggregation_cursor,
            'standards_result_authority_after_aggregation')
        _require(_same(standards_observation['capacity_before'],
                       spec_observation['capacity_after'])
                 and _same(
                     standards_observation['capacity_after_retention'],
                     standards_observation['capacity_before'])
                 and _same(standards_observation['capacity_after'],
                           standards_observation['capacity_before'])
                 and _same(before_authority,
                           spec_observation['authority_after'])
                 and _same(retention['authority_before'], before_authority)
                 and _same(aggregation['authority_before'],
                           retention_authority)
                 and before_projection == retention_projection
                 == after_projection,
                 'standards_result_authority_scope')

        state = rv.freeze(spec_report['comparisons'][-1]['model_state'])
        source_id = explorer.state_identity(state)
        _require(source_id == spec_report['comparisons'][-1][
            'graph_mapping']['production_boundary']['target_state_id'],
                 'standards_result_graph_source')
        choices = ({
            'stage': 'result.standards', 'lane': 'standards',
            'outcome': 'accepted', 'variant': 'evidence',
        }, {
            'stage': 'aggregate', 'lane': 'controller',
            'outcome': 'accepted', 'variant': 'evidence',
        })
        observations = (
            retention['report_sha256'], aggregation['report_sha256'])
        kinds = ('observed_standards_typed_result',
                 'completed_result_aggregation')
        scopes = ('owner_bound_standards_typed_result_reconstruction',
                  'retained_result_aggregation_reconstruction')
        schemas = ('orch-dork/production-graph-standards-result-edge/v1',
                   'orch-dork/production-graph-result-aggregation-edge/v1')
        standards_observation_sha256 = values.canonical_digest(projection)
        input_sha256 = values.canonical_digest({
            'spec_result_sha256': spec_comparison.report.digest(),
            'standards_observation_sha256': standards_observation_sha256,
        })
        comparisons = []
        for index, choice in enumerate(choices):
            events = [
                event for event in model.outgoing_stimuli(state).to_plain()
                if _same(explorer.abstract_event(event), choice)
            ]
            _require(len(events) == 1,
                     'standards_result_model_choice_' + str(index))
            event = events[0]
            reduction = model.reduce(state, event).to_plain()
            successor_state = rv.freeze(reduction['successor'])
            directive = model.legal_directive(successor_state).to_plain()
            _require(_same(reduction['directive'], directive),
                     'standards_result_model_directive_' + str(index))
            target_facts = successor_state.to_plain()
            expected_stage = ('aggregate' if index == 0 else 'review')
            expected_detail = ('aggregate' if index == 0 else 'sol_review')
            _require(target_facts['stage'] == expected_stage
                     and target_facts['action'] is None
                     and all(target_facts['lanes'][lane]['typed_result']
                             is not None
                             for lane in ('spec', 'standards'))
                     and target_facts['aggregation']
                     == ('pending' if index == 0 else 'accepted')
                     and target_facts['sol_review'] == 'pending'
                     and directive['kind'] == 'wait_for_observation'
                     and directive['payload']['detail'] == expected_detail,
                     'standards_result_model_target_' + str(index))
            target_id = explorer.state_identity(successor_state)
            comparisons.append({
                'schema': schemas[index],
                'scope': scopes[index],
                'arrival_order': list(expected_order),
                'production_observation_sha256': observations[index],
                'graph_mapping': {
                    'graph_case': explorer.GRAPH_CASE,
                    'graph_owner': explorer.OWNER,
                    'production_boundary': {
                        'kind': kinds[index],
                        'choice': choice,
                        'source_state_id': source_id,
                        'transition_id': explorer.edge_identity(
                            source_id, event, target_id),
                        'target_state_id': target_id,
                    },
                    'gap': {
                        'status': 'PREFIX_ONLY',
                        'observed_boundary_count': 13 + index,
                        'next_uncovered_choices': [
                            explorer.abstract_event(item) for item in
                            model.outgoing_stimuli(
                                successor_state).to_plain()
                        ],
                        'production_graph_complete': False,
                    },
                },
                'model_state': target_facts,
                'input_sha256': input_sha256,
                **{field: False for field in _SERIAL_FALSE_FIELDS},
            })
            state, source_id = successor_state, target_id
        return rv.freeze({
            'schema': 'orch-dork/production-graph-standards-result-order/v1',
            'scope': 'standards_result_to_review_frontier',
            'arrival_order': list(expected_order),
            'comparisons': comparisons,
            'spec_result_sha256': spec_comparison.report.digest(),
            'standards_observation_sha256': standards_observation_sha256,
            'input_sha256': input_sha256,
            **{field: False for field in _SERIAL_FALSE_FIELDS},
        })
    except (KeyError, IndexError, TypeError, StopIteration, UnicodeError,
            ValueError, OverflowError, RecursionError) as error:
        if isinstance(error, values.LifecycleContractError):
            raise
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_standards_result_shape'
        ) from error


def capture_standards_typed_result_and_aggregation_comparison(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, serial_observation, final_observation,
        spec_observation, standards_observation, expected_order, *,
        capture_session):
    """Issue one standards/aggregation comparison from live raw sources."""

    capture_record = _require_live_observation(
        capture_session, 'serial', serial_observation)
    _require_live_observation(capture_session, 'final', final_observation)
    _require_live_observation(capture_session, 'spec', spec_observation)
    _require_live_observation(
        capture_session, 'standards', standards_observation)
    spec_token = (spec_comparison._issue_token
                  if type(spec_comparison) is SpecResultLiveComparison
                  else None)
    spec_record = _ISSUED_SPEC_RESULTS.get(spec_token)
    _require(spec_record is not None
             and spec_record['capture_token']
             is capture_session._capture_token,
             'live_capture_spec_session_join')
    report = compare_standards_typed_result_and_aggregation(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, serial_observation, final_observation,
        spec_observation, standards_observation, expected_order)
    issue_key = spec_token
    _require(issue_key not in capture_record['issued_standards'],
             'live_capture_duplicate_standards_result')
    token = object()
    value = StandardsResultLiveComparison(
        report=report,
        _spec_parent=spec_comparison,
        _authority=_STANDARDS_RESULT_AUTHORITY,
        _issue_token=token,
    )
    _ISSUED_STANDARDS_RESULTS[token] = {
        'value': weakref.ref(
            value,
            lambda _: _ISSUED_STANDARDS_RESULTS.pop(token, None),
        ),
        'pid': os.getpid(),
        'fingerprint': _standards_result_fingerprint(value),
        'parent': weakref.ref(value._spec_parent),
        'capture_token': capture_session._capture_token,
    }
    capture_record['issued_standards'].add(issue_key)
    return value


def _validated_standards_result_order(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, retained_comparison, expected_order):
    """Validate an issued standards-result comparison after source expiry."""

    _require_issued_serial_comparison(serial_comparison)
    _require_issued_final_continuation(final_comparison, serial_comparison)
    _require_issued_spec_result(spec_comparison, final_comparison)
    _require_issued_standards_result(retained_comparison, spec_comparison)
    spec_report = _validated_spec_result_order(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, expected_order)
    report = retained_comparison.report.to_plain()
    try:
        _require(type(report) is dict and set(report) == {
            'schema', 'scope', 'arrival_order', 'comparisons',
            'spec_result_sha256', 'standards_observation_sha256',
            'input_sha256', *_SERIAL_FALSE_FIELDS,
        } and report['schema']
            == 'orch-dork/production-graph-standards-result-order/v1'
            and report['scope'] == 'standards_result_to_review_frontier'
            and report['arrival_order'] == list(expected_order)
            and report['spec_result_sha256']
            == spec_comparison.report.digest()
            and re.fullmatch(
                r'[0-9a-f]{64}', report['standards_observation_sha256'])
            is not None
            and report['input_sha256'] == values.canonical_digest({
                'spec_result_sha256': report['spec_result_sha256'],
                'standards_observation_sha256':
                    report['standards_observation_sha256'],
            })
            and all(report[field] is False
                    for field in _SERIAL_FALSE_FIELDS),
                 'retained_standards_result_shape')
        comparisons = report['comparisons']
        _require(type(comparisons) is list and len(comparisons) == 2,
                 'retained_standards_result_comparisons')
        state = rv.freeze(spec_report['comparisons'][-1]['model_state'])
        source_id = explorer.state_identity(state)
        choices = ({
            'stage': 'result.standards', 'lane': 'standards',
            'outcome': 'accepted', 'variant': 'evidence',
        }, {
            'stage': 'aggregate', 'lane': 'controller',
            'outcome': 'accepted', 'variant': 'evidence',
        })
        schemas = ('orch-dork/production-graph-standards-result-edge/v1',
                   'orch-dork/production-graph-result-aggregation-edge/v1')
        scopes = ('owner_bound_standards_typed_result_reconstruction',
                  'retained_result_aggregation_reconstruction')
        kinds = ('observed_standards_typed_result',
                 'completed_result_aggregation')
        for index, (comparison, choice) in enumerate(
                zip(comparisons, choices)):
            _require(type(comparison) is dict and set(comparison) == {
                'schema', 'scope', 'arrival_order',
                'production_observation_sha256', 'graph_mapping',
                'model_state', 'input_sha256', *_SERIAL_FALSE_FIELDS,
            } and comparison['schema'] == schemas[index]
                and comparison['scope'] == scopes[index]
                and comparison['arrival_order'] == list(expected_order)
                and comparison['input_sha256'] == report['input_sha256']
                and re.fullmatch(
                    r'[0-9a-f]{64}',
                    comparison['production_observation_sha256']) is not None
                and all(comparison[field] is False
                        for field in _SERIAL_FALSE_FIELDS),
                     'retained_standards_comparison_shape_' + str(index))
            events = [
                event for event in model.outgoing_stimuli(state).to_plain()
                if _same(explorer.abstract_event(event), choice)
            ]
            _require(len(events) == 1,
                     'retained_standards_model_choice_' + str(index))
            event = events[0]
            reduction = model.reduce(state, event).to_plain()
            successor_state = rv.freeze(reduction['successor'])
            directive = model.legal_directive(successor_state).to_plain()
            _require(_same(reduction['directive'], directive),
                     'retained_standards_directive_' + str(index))
            target_id = explorer.state_identity(successor_state)
            expected_mapping = {
                'graph_case': explorer.GRAPH_CASE,
                'graph_owner': explorer.OWNER,
                'production_boundary': {
                    'kind': kinds[index],
                    'choice': choice,
                    'source_state_id': source_id,
                    'transition_id': explorer.edge_identity(
                        source_id, event, target_id),
                    'target_state_id': target_id,
                },
                'gap': {
                    'status': 'PREFIX_ONLY',
                    'observed_boundary_count': 13 + index,
                    'next_uncovered_choices': [
                        explorer.abstract_event(item) for item in
                        model.outgoing_stimuli(successor_state).to_plain()
                    ],
                    'production_graph_complete': False,
                },
            }
            _require(_same(comparison['graph_mapping'], expected_mapping)
                     and _same(comparison['model_state'],
                               successor_state.to_plain()),
                     'retained_standards_mapping_' + str(index))
            state, source_id = successor_state, target_id
        return report
    except (KeyError, IndexError, TypeError, ValueError,
            OverflowError, RecursionError) as error:
        if isinstance(error, values.LifecycleContractError):
            raise
        raise values.LifecycleContractError(
            'public_native_comparison:'
            'unsupported_retained_standards_result_shape'
        ) from error


def compare_semantic_review_outcome(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, standards_comparison, serial_observation,
        final_observation, spec_observation, standards_observation,
        review_observation, expected_order):
    """Map one source-bound semantic review outcome from the review frontier."""

    _require_issued_serial_comparison(serial_comparison)
    _require_issued_final_continuation(final_comparison, serial_comparison)
    _require_issued_spec_result(spec_comparison, final_comparison)
    _require_issued_standards_result(standards_comparison, spec_comparison)
    standards_report = _validated_standards_result_order(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, standards_comparison, expected_order)
    live_standards = compare_standards_typed_result_and_aggregation(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, serial_observation, final_observation,
        spec_observation, standards_observation, expected_order)
    _require(live_standards == standards_comparison.report,
             'semantic_review_standards_parent')
    projection = _semantic_review_input_projection(review_observation)
    try:
        _require(type(expected_order) is tuple and len(expected_order) == 2
                 and set(expected_order) == {'spec', 'standards'}
                 and review_observation['schema']
                 == 'orch-dork/native-semantic-review-observation/v1'
                 and review_observation['arrival_order']
                 == list(expected_order)
                 and review_observation[
                     'predecessor_standards_observation']
                 == standards_observation,
                 'semantic_review_scope')
        predecessor = review_observation[
            'predecessor_standards_observation']
        aggregation = predecessor['aggregation_report']
        retained_results = aggregation['worker_results']
        packet = review_observation['review_packet']
        verifications = review_observation['verifications']
        submission = review_observation['submission']
        context = review_observation['submission_context']
        acknowledgement = review_observation['acknowledgement']
        expectation = review_observation['expectation']
        _require(aggregation['decision'] == 'AWAITING_SOL_REVIEW'
                 and aggregation['review_packet'] == packet
                 and qualification_review.validate_review_packet(
                     packet).get('valid') is True
                 and type(verifications) is list
                 and [row.get('logical_worker_id')
                      for row in verifications] == ['spec', 'standards']
                 and qualification_review.build_review_submission(
                     packet, verifications) == submission
                 and qualification_review.validate_review_submission(
                     packet, submission).get('valid') is True
                 and qualification_review.build_review_acknowledgement(
                     packet, submission, context) == acknowledgement
                 and qualification_review.review_call_arguments(
                     packet, submission, context)
                 == review_observation['call_arguments']
                 and qualification_review.review_observation_expectation(
                     packet, submission, context) == expectation,
                 'semantic_review_submission')
        _require(host_adapter.mcp_call_context(
                     review_observation['review_metadata'])
                 == context['native_call']
                 and _same(review_observation['checkpoint_metadata'],
                           standards_observation['metadata'])
                 and expectation['arguments']
                 == review_observation['call_arguments']
                 and expectation['structured_result'] == acknowledgement,
                 'semantic_review_transport_context')

        roots = review_observation['root_snapshots']
        workers = review_observation['worker_snapshots']
        _require(roots['before']
                 == standards_observation['root_snapshots']['after']
                 and roots['after'] == roots['after_submission']
                 and workers['before']
                 == standards_observation['worker_snapshots']['after']
                 and workers['after'] == workers['before'],
                 'semantic_review_source_join')
        rows = _appended_json_rows(
            roots['before'], roots['after_submission'],
            'semantic_review_root')
        _require(len(rows) == 2
                 and rows[0].get('type') == 'response_item'
                 and set(rows[0].get('payload', {})) == {
                     'type', 'call_id', 'id', 'namespace', 'name',
                     'internal_chat_message_metadata_passthrough',
                     'arguments'}
                 and rows[0]['payload']['type'] == 'function_call'
                 and rows[0]['payload']['call_id']
                 == expectation['tool_call_id']
                 and rows[0]['payload']['id']
                 == expectation['tool_call_id'] + '-item'
                 and rows[0]['payload']['namespace']
                 == 'mcp__' + expectation['server']
                 and rows[0]['payload']['name'] == expectation['tool']
                 and rows[0]['payload'][
                     'internal_chat_message_metadata_passthrough'] is None
                 and _same(_strict_json_record(
                     rows[0]['payload']['arguments']),
                     expectation['arguments'])
                 and rows[1].get('type') == 'response_item'
                 and set(rows[1].get('payload', {})) == {
                     'type', 'call_id', 'id',
                     'internal_chat_message_metadata_passthrough', 'output'}
                 and rows[1]['payload']['type']
                 == 'function_call_output'
                 and rows[1]['payload']['call_id']
                 == expectation['tool_call_id']
                 and rows[1]['payload']['id']
                 == expectation['tool_call_id'] + '-result'
                 and rows[1]['payload'][
                     'internal_chat_message_metadata_passthrough'] is None
                 and _same(_strict_json_record(
                     rows[1]['payload']['output']), acknowledgement),
                 'semantic_review_root_call')

        submitted = review_observation['submitted_report']
        submitted_receipt = submitted['receipt']
        submitted_bindings = submitted_receipt['bindings']
        _require(successor.governed_attempt.validate_post_batch_report(
                     submitted).get('valid') is True
                 and submitted_receipt['stage'] == 'review_submission'
                 and submitted['next_action'] == 'observe_sol_review'
                 and submitted['terminal_claim_permitted'] is False
                 and submitted_bindings['quality_phase']
                 == 'review_submission'
                 and submitted_bindings['worker_results']
                 == retained_results
                 and submitted_bindings['review_packet'] == packet
                 and submitted_bindings['review_submission'] == submission
                 and submitted_bindings['review_context'] == context
                 and submitted_bindings['review_acknowledgement']
                 == acknowledgement,
                 'semantic_review_submitted_state')
        owner_records = review_observation['submission_owner_records']
        owner_budget = review_observation[
            'submission_owner_transport_budget']
        _require(type(owner_records) is list and bool(owner_records)
                 and all(type(row) is dict and 'error' not in row
                         for row in owner_records)
                 and type(owner_budget) is dict
                 and set(owner_budget) == {
                     'max_calls', 'calls_retained', 'within_bound'}
                 and type(owner_budget['max_calls']) is int
                 and type(owner_budget['calls_retained']) is int
                 and owner_budget['calls_retained'] == len(owner_records)
                 and 0 < owner_budget['calls_retained']
                 <= owner_budget['max_calls'] <= 256
                 and owner_budget['within_bound'] is True
                 and review_observation['submission_owner_cleanup'] == {
                     'closed': True, 'socket_removed': True},
                 'semantic_review_submission_owner')

        def validate_submission_refusal(
                attempt, name, expected_authority, expected_capacity):
            expected_error = (
                'successor_review:native_context_invalid'
                if name == 'wrong_metadata'
                else 'successor_review:submission_refused')
            _require(type(attempt) is dict and set(attempt) == {
                         'name', 'refused', 'error_type', 'error_message',
                         'authority_before', 'authority_after',
                         'state_before', 'state_after',
                         'capacity_before', 'capacity_after',
                         'root_before', 'root_after',
                         'workers_before', 'workers_after',
                         'owner_records', 'owner_cleanup'}
                     and attempt['name'] == name
                     and attempt['refused'] is True
                     and attempt['error_type']
                     == 'QualificationSuccessorError'
                     and attempt['error_message'] == expected_error
                     and _same(attempt['authority_before'],
                               expected_authority)
                     and _same(attempt['authority_after'],
                               expected_authority)
                     and _same(attempt['state_before'],
                               attempt['state_after'])
                     and _same(attempt['capacity_before'],
                               expected_capacity)
                     and _same(attempt['capacity_after'],
                               expected_capacity)
                     and attempt['root_before'] == roots['before']
                     and attempt['root_after'] == roots['before']
                     and attempt['workers_before'] == workers['before']
                     and attempt['workers_after'] == workers['before']
                     and attempt['owner_records'] == []
                     and attempt['owner_cleanup'] == {
                         'closed': True, 'socket_removed': True},
                     'semantic_review_submission_refusal_' + name)

        refusal_attempts = review_observation[
            'submission_refusal_attempts']
        _require(type(refusal_attempts) is list
                 and len(refusal_attempts) == 4,
                 'semantic_review_submission_refusal_count')
        for attempt, name in zip(refusal_attempts, (
                'wrong_subject', 'wrong_verification', 'wrong_metadata',
                'replayed_submission')):
            validate_submission_refusal(
                attempt, name,
                review_observation[
                    'authority_after_submission'
                    if name == 'replayed_submission'
                    else 'authority_before'],
                review_observation[
                    'capacity_after_submission'
                    if name == 'replayed_submission'
                    else 'capacity_before'])

        pending_reports = review_observation['pending_reports']
        sources = review_observation['review_source_observations']
        snapshots = review_observation['review_owner_snapshots']
        owner_record_sets = review_observation['review_owner_records']
        owner_budgets = review_observation[
            'review_owner_transport_budgets']
        owner_cleanups = review_observation['review_owner_cleanups']
        query_counts = review_observation['review_query_counts']
        _require(type(pending_reports) is list and len(pending_reports) == 2
                 and type(sources) is list and len(sources) == 3
                 and type(snapshots) is list and len(snapshots) == 3
                 and type(owner_record_sets) is list
                 and len(owner_record_sets) == 3
                 and type(owner_budgets) is list
                 and len(owner_budgets) == 3
                 and type(owner_cleanups) is list
                 and len(owner_cleanups) == 3
                 and type(query_counts) is list
                 and len(query_counts) == 3
                 and all(type(count) is int and count == 1
                         for count in query_counts)
                 and type(review_observation[
                     'worker_final_source_observation_count']) is int
                 and review_observation[
                     'worker_final_source_observation_count'] == 0,
                 'semantic_review_observation_counts')
        expected_record_sequence = [
            ('connection', None),
            ('request', 'initialize'),
            ('notification', 'initialized'),
            ('request', 'thread/read'),
            ('request', 'thread/loaded/list'),
            ('request', 'thread/list'),
            ('request', 'hooks/list'),
        ]
        for index, (snapshot, source, records, budget, cleanup) in enumerate(
                zip(snapshots, sources, owner_record_sets, owner_budgets,
                    owner_cleanups)):
            _require(type(snapshot) is dict and set(snapshot) == {
                         'thread', 'loaded', 'descendants',
                         'owner_identity_sha256', 'owner_invocation',
                         'thread_read_sha256', 'hook_inventory'}
                     and type(records) is list and len(records) == 7
                     and all(type(record) is dict
                             and 'error' not in record
                             for record in records)
                     and [(record.get('kind'), record.get('method'))
                          for record in records]
                     == expected_record_sequence
                     and records[0].get('closed') is True
                     and records[3].get('result') == {
                         'thread': snapshot['thread']}
                     and records[4].get('result') == snapshot['loaded']
                     and records[5].get('result') == snapshot['descendants']
                     and records[6].get('result')
                     == snapshot['hook_inventory']
                     and snapshot['thread_read_sha256']
                     == qualification_review.local_runtime._sha256(
                         records[3]['result'])
                     and type(budget) is dict and set(budget) == {
                         'max_calls', 'calls_retained', 'within_bound'}
                     and type(budget['max_calls']) is int
                     and type(budget['calls_retained']) is int
                     and budget['calls_retained'] == len(records)
                     and 0 < budget['calls_retained']
                     <= budget['max_calls'] <= 256
                     and budget['within_bound'] is True
                     and cleanup == {
                         'closed': True, 'socket_removed': True},
                     'semantic_review_owner_transport_' + str(index))
            try:
                reconstructed = (
                    qualification_review.local_runtime
                    ._completed_mcp_observation(expectation, snapshot))
            except qualification_review.local_runtime.LocalTaskRuntimeError \
                    as error:
                issue = str(error)
                if not issue.startswith('mcp_observation:'):
                    issue = 'mcp_observation:owner_unavailable'
                expected_source = {
                    'status': 'REFUSED', 'issues': [issue],
                    'observation': None,
                }
            else:
                expected_source = {
                    'status': ('OBSERVED' if reconstructed is not None
                               else 'PENDING'),
                    'issues': ([] if reconstructed is not None else [
                        'mcp_observation:awaiting_completed_call']),
                    'observation': reconstructed,
                }
            _require(all(source[field] == expected_source[field]
                         for field in expected_source),
                     'semantic_review_owner_source_join_' + str(index))
        submission_authority = review_observation[
            'authority_after_submission']
        submission_cursor = submission_authority['tip']
        for index, report in enumerate(pending_reports):
            native = report['controller_transitions'][-1]['report']
            _require(successor.validate_issue94_successor_action_advance_report(
                         report).get('valid') is True
                     and report['decision']
                     == 'AWAITING_SOL_REVIEW_OBSERVATION'
                     and report['action'] is None
                     and [row['program']['operation']
                          for row in report['controller_transitions']]
                     == ['inspect', 'stage']
                     and type(report['counters'][
                         'controller_stages']) is int
                     and report['counters']['controller_stages'] == 0
                     and report['boundary'][
                         'controller_stage_advanced'] is False
                     and native['decision']
                     == 'REVIEW_OBSERVATION_PENDING'
                     and native['cursor'] == submission_cursor
                     and native['stage_report'] == submitted
                     and native['review_observation'] == sources[index]
                     and sources[index]['status'] == 'PENDING'
                     and sources[index]['observation'] is None
                     and qualification_review.local_runtime
                         .validate_current_local_task_mcp_observation(
                             sources[index]).get('valid') is True
                     and sources[index]['expectation'] == expectation,
                     'semantic_review_pending_' + str(index))

        final_report = review_observation['final_report']
        final_native = final_report['controller_transitions'][-1]['report']
        final_stage = final_native['stage_report']
        final_bindings = final_stage['receipt']['bindings']
        final_source = sources[-1]
        derived_outcome = qualification_review.review_observation_decision(
            packet, submission, context, final_source)
        _require(derived_outcome in {
                     'accepted', 'rejected', 'evidence_required'}
                 and review_observation['outcome'] == derived_outcome
                 and qualification_review.local_runtime
                     .validate_current_local_task_mcp_observation(
                         final_source).get('valid') is True
                 and final_source['expectation'] == expectation
                 and final_source['status'] == (
                     'REFUSED' if derived_outcome == 'evidence_required'
                     else 'OBSERVED')
                 and successor.validate_issue94_successor_action_advance_report(
                     final_report).get('valid') is True
                 and final_report['decision'] == (
                     'SOL_REVIEW_EVIDENCE_REQUIRED'
                     if derived_outcome == 'evidence_required'
                     else 'AWAITING_TERMINAL_VERIFICATION')
                 and final_report['action'] is None
                 and [row['program']['operation']
                      for row in final_report['controller_transitions']]
                 == ['inspect', 'stage']
                 and type(final_report['counters'][
                     'controller_stages']) is int
                 and final_report['counters']['controller_stages'] == 1
                 and final_native['status'] == 'PASS'
                 and final_native['decision'] == 'STAGE_ADVANCED'
                 and successor.governed_attempt.validate_post_batch_report(
                     final_stage).get('valid') is True
                 and final_stage['receipt']['stage'] == 'semantic_review'
                 and final_stage['next_action'] == (
                     'review_evidence'
                     if derived_outcome == 'evidence_required' else 'verify')
                 and final_stage['terminal_claim_permitted'] is False
                 and final_bindings['quality_phase'] == 'semantic_review'
                 and final_bindings['worker_results'] == retained_results
                 and final_bindings['review_packet'] == packet
                 and final_bindings['review_submission'] == submission
                 and final_bindings['review_context'] == context
                 and final_bindings['review_acknowledgement']
                 == acknowledgement
                 and final_bindings['review_observation'] == final_source
                 and final_bindings['review_outcome'] == derived_outcome,
                 'semantic_review_final')

        replay = review_observation['post_outcome_replay_report']
        _require(replay['status'] == 'BLOCKED'
                 and replay['decision'] == 'STAGE_REFUSED'
                 and replay['cursor'] == final_native['cursor']
                 and replay['stage_report'] == final_stage
                 and type(review_observation[
                     'post_outcome_replay_query_count']) is int
                 and review_observation[
                     'post_outcome_replay_query_count'] == 0,
                 'semantic_review_replay')
        before_capacity = review_observation['capacity_before']
        _require(_same(before_capacity,
                       standards_observation['capacity_after'])
                 and all(_same(value, before_capacity) for value in (
                     review_observation['capacity_after_submission'],
                     *review_observation['capacity_after_pending'],
                     review_observation['capacity_after'],
                     review_observation['capacity_after_replay']))
                 and len(review_observation[
                     'capacity_after_pending']) == 2,
                 'semantic_review_capacity')
        before_authority = review_observation['authority_before']
        pending_authority = review_observation['authority_after_pending']
        final_authority = review_observation['authority_after']
        _require(_same(before_authority,
                       standards_observation['authority_after'])
                 and type(pending_authority) is list
                 and len(pending_authority) == 2
                 and all(_same(value, submission_authority)
                         for value in pending_authority)
                 and _same(review_observation['authority_after_replay'],
                           final_authority),
                 'semantic_review_authority_continuity')
        parent_cursor = aggregation['controller_transitions'][-1][
            'report']['cursor']
        final_cursor = final_native['cursor']
        authority_projections = [
            _stage_authority_projection(
                before_authority, parent_cursor,
                'semantic_review_authority_before'),
            _stage_authority_projection(
                submission_authority, submission_cursor,
                'semantic_review_authority_submission'),
            _stage_authority_projection(
                final_authority, final_cursor,
                'semantic_review_authority_final'),
        ]
        _require(authority_projections[0]
                 == authority_projections[1]
                 == authority_projections[2],
                 'semantic_review_authority_static')

        state = rv.freeze(
            standards_report['comparisons'][-1]['model_state'])
        source_id = explorer.state_identity(state)
        model_outcome = {
            'accepted': 'accepted',
            'rejected': 'failed',
            'evidence_required': 'unknown',
        }[derived_outcome]
        choice = {
            'stage': 'review', 'lane': 'controller',
            'outcome': model_outcome, 'variant': 'evidence',
        }
        events = [
            event for event in model.outgoing_stimuli(state).to_plain()
            if _same(explorer.abstract_event(event), choice)
        ]
        _require(len(events) == 1, 'semantic_review_model_choice')
        event = events[0]
        reduction = model.reduce(state, event).to_plain()
        successor_state = rv.freeze(reduction['successor'])
        directive = model.legal_directive(successor_state).to_plain()
        target_facts = successor_state.to_plain()
        _require(_same(reduction['directive'], directive)
                 and (derived_outcome != 'accepted'
                      or target_facts['stage'] == 'verify'
                      and target_facts['sol_review'] == 'accepted')
                 and (derived_outcome != 'rejected'
                      or target_facts['stage'] == 'verify'
                      and target_facts['outcome'] == 'failure')
                 and (derived_outcome != 'evidence_required'
                      or target_facts['stage'] == 'review'
                      and target_facts['requirement']['observation']
                      == 'unknown'),
                 'semantic_review_model_target')
        target_id = explorer.state_identity(successor_state)
        observation_sha256 = values.canonical_digest(projection)
        input_sha256 = values.canonical_digest({
            'standards_result_sha256': standards_comparison.report.digest(),
            'production_observation_sha256': observation_sha256,
        })
        graph_mapping = {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': {
                'kind': 'observed_semantic_review_' + derived_outcome,
                'choice': choice,
                'source_state_id': source_id,
                'transition_id': explorer.edge_identity(
                    source_id, event, target_id),
                'target_state_id': target_id,
            },
            'gap': {
                'status': 'PREFIX_ONLY',
                'observed_boundary_count': 15,
                'next_uncovered_choices': [
                    explorer.abstract_event(item) for item in
                    model.outgoing_stimuli(successor_state).to_plain()
                ],
                'production_graph_complete': False,
            },
        }
        return rv.freeze({
            'schema':
                'orch-dork/production-graph-semantic-review-outcome-edge/v1',
            'scope': 'source_bound_semantic_review_outcome_reconstruction',
            'arrival_order': list(expected_order),
            'production_outcome': derived_outcome,
            'production_observation_sha256': observation_sha256,
            'standards_result_sha256': standards_comparison.report.digest(),
            'graph_mapping': graph_mapping,
            'model_state': target_facts,
            'input_sha256': input_sha256,
            **{field: False for field in _SERIAL_FALSE_FIELDS},
        })
    except (KeyError, IndexError, TypeError, StopIteration, UnicodeError,
            ValueError, OverflowError, RecursionError) as error:
        if isinstance(error, values.LifecycleContractError):
            raise
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_semantic_review_shape'
        ) from error


def capture_semantic_review_outcome_comparison(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, standards_comparison, serial_observation,
        final_observation, spec_observation, standards_observation,
        review_observation, expected_order, *, capture_session):
    """Issue one review comparison from the exact live review source."""

    capture_record = _require_live_observation(
        capture_session, 'serial', serial_observation)
    _require_live_observation(capture_session, 'final', final_observation)
    _require_live_observation(capture_session, 'spec', spec_observation)
    _require_live_observation(
        capture_session, 'standards', standards_observation)
    _require_live_observation(capture_session, 'review', review_observation)
    standards_token = (
        standards_comparison._issue_token
        if type(standards_comparison) is StandardsResultLiveComparison
        else None)
    standards_record = _ISSUED_STANDARDS_RESULTS.get(standards_token)
    _require(standards_record is not None
             and standards_record['capture_token']
             is capture_session._capture_token,
             'live_capture_standards_session_join')
    report = compare_semantic_review_outcome(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, standards_comparison, serial_observation,
        final_observation, spec_observation, standards_observation,
        review_observation, expected_order)
    issue_key = standards_token
    _require(issue_key not in capture_record['issued_reviews'],
             'live_capture_duplicate_semantic_review')
    token = object()
    value = SemanticReviewOutcomeLiveComparison(
        report=report,
        _standards_parent=standards_comparison,
        _authority=_SEMANTIC_REVIEW_AUTHORITY,
        _issue_token=token,
    )
    _ISSUED_SEMANTIC_REVIEWS[token] = {
        'value': weakref.ref(
            value,
            lambda _: _ISSUED_SEMANTIC_REVIEWS.pop(token, None)),
        'pid': os.getpid(),
        'fingerprint': _semantic_review_fingerprint(value),
        'parent': weakref.ref(value._standards_parent),
        'capture_token': capture_session._capture_token,
    }
    capture_record['issued_reviews'].add(issue_key)
    return value


def _validated_semantic_review_outcome_order(
        checkpoint_wait_report, retained_comparison, expected_order):
    """Validate one issued review outcome after its source session expires."""

    standards = (retained_comparison._standards_parent
                 if type(retained_comparison)
                 is SemanticReviewOutcomeLiveComparison else None)
    spec = (standards._spec_parent
            if type(standards) is StandardsResultLiveComparison else None)
    final = (spec._final_parent
             if type(spec) is SpecResultLiveComparison else None)
    serial = (final._serial_parent
              if type(final) is FinalContinuationLiveComparison else None)
    _require_issued_serial_comparison(serial)
    _require_issued_final_continuation(final, serial)
    _require_issued_spec_result(spec, final)
    _require_issued_standards_result(standards, spec)
    _require_issued_semantic_review(retained_comparison, standards)
    standards_report = _validated_standards_result_order(
        checkpoint_wait_report, serial, final, spec, standards,
        expected_order)
    report = retained_comparison.report.to_plain()
    try:
        _require(type(report) is dict and set(report) == {
            'schema', 'scope', 'arrival_order', 'production_outcome',
            'production_observation_sha256', 'standards_result_sha256',
            'graph_mapping', 'model_state', 'input_sha256',
            *_SERIAL_FALSE_FIELDS,
        } and report['schema']
            == 'orch-dork/production-graph-semantic-review-outcome-edge/v1'
            and report['scope']
            == 'source_bound_semantic_review_outcome_reconstruction'
            and report['arrival_order'] == list(expected_order)
            and report['production_outcome'] in {
                'accepted', 'rejected', 'evidence_required'}
            and re.fullmatch(
                r'[0-9a-f]{64}',
                report['production_observation_sha256']) is not None
            and report['standards_result_sha256'] == standards.report.digest()
            and report['input_sha256'] == values.canonical_digest({
                'standards_result_sha256': report[
                    'standards_result_sha256'],
                'production_observation_sha256': report[
                    'production_observation_sha256'],
            })
            and all(report[field] is False
                    for field in _SERIAL_FALSE_FIELDS),
                 'retained_semantic_review_shape')
        state = rv.freeze(
            standards_report['comparisons'][-1]['model_state'])
        source_id = explorer.state_identity(state)
        choice = {
            'stage': 'review', 'lane': 'controller',
            'outcome': {
                'accepted': 'accepted',
                'rejected': 'failed',
                'evidence_required': 'unknown',
            }[report['production_outcome']],
            'variant': 'evidence',
        }
        events = [
            event for event in model.outgoing_stimuli(state).to_plain()
            if _same(explorer.abstract_event(event), choice)
        ]
        _require(len(events) == 1,
                 'retained_semantic_review_model_choice')
        event = events[0]
        reduction = model.reduce(state, event).to_plain()
        successor_state = rv.freeze(reduction['successor'])
        directive = model.legal_directive(successor_state).to_plain()
        target_id = explorer.state_identity(successor_state)
        expected_mapping = {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': {
                'kind': ('observed_semantic_review_'
                         + report['production_outcome']),
                'choice': choice,
                'source_state_id': source_id,
                'transition_id': explorer.edge_identity(
                    source_id, event, target_id),
                'target_state_id': target_id,
            },
            'gap': {
                'status': 'PREFIX_ONLY',
                'observed_boundary_count': 15,
                'next_uncovered_choices': [
                    explorer.abstract_event(item) for item in
                    model.outgoing_stimuli(successor_state).to_plain()
                ],
                'production_graph_complete': False,
            },
        }
        _require(_same(reduction['directive'], directive)
                 and _same(report['graph_mapping'], expected_mapping)
                 and _same(report['model_state'],
                           successor_state.to_plain()),
                 'retained_semantic_review_mapping')
        return report
    except (KeyError, IndexError, TypeError, ValueError,
            OverflowError, RecursionError) as error:
        if isinstance(error, values.LifecycleContractError):
            raise
        raise values.LifecycleContractError(
            'public_native_comparison:'
            'unsupported_retained_semantic_review_shape'
        ) from error


def _terminal_cleanup_model_choices(cleanup_outcomes):
    _require(type(cleanup_outcomes) is list
             and len(cleanup_outcomes) in {1, 2}
             and all(type(outcome) is str and outcome in {
                         'completed', 'failed', 'cancelled', 'timed_out',
                         'unknown',
                     }
                     for outcome in cleanup_outcomes)
             and (cleanup_outcomes[0] == 'completed'
                  or len(cleanup_outcomes) == 1),
             'terminal_cleanup_outcomes')
    mapped = {
        'completed': 'accepted',
        'failed': 'failed',
        'cancelled': 'failed',
        'timed_out': 'failed',
        'unknown': 'unknown',
    }
    choices = [
        {
            'stage': 'verify', 'lane': 'controller',
            'outcome': 'accepted', 'variant': 'evidence',
        },
        {
            'stage': 'cleanup', 'lane': 'spec',
            'outcome': 'accepted', 'variant': 'evidence',
        },
        {
            'stage': 'close.spec', 'lane': 'spec',
            'outcome': mapped[cleanup_outcomes[0]], 'variant': 'evidence',
        },
    ]
    if len(cleanup_outcomes) == 2:
        choices.extend((
            {
                'stage': 'cleanup', 'lane': 'standards',
                'outcome': 'accepted', 'variant': 'evidence',
            },
            {
                'stage': 'close.standards', 'lane': 'standards',
                'outcome': mapped[cleanup_outcomes[1]],
                'variant': 'evidence',
            },
        ))
    return choices


def _terminal_cleanup_model_bridge(review_state, cleanup_outcomes):
    state = rv.freeze(review_state)
    states = [explorer.state_identity(state)]
    transitions = []
    steps = []
    choices = _terminal_cleanup_model_choices(cleanup_outcomes)
    for choice in choices:
        events = [
            event for event in model.outgoing_stimuli(state).to_plain()
            if _same(explorer.abstract_event(event), choice)
        ]
        _require(len(events) == 1, 'terminal_cleanup_model_choice')
        event = events[0]
        reduction = model.reduce(state, event).to_plain()
        successor_state = rv.freeze(reduction['successor'])
        target_id = explorer.state_identity(successor_state)
        directive = model.legal_directive(successor_state).to_plain()
        _require(_same(reduction['directive'], directive),
                 'terminal_cleanup_model_directive')
        transition_id = explorer.edge_identity(
            states[-1], event, target_id)
        transitions.append(transition_id)
        steps.append({
            'source_state_id': states[-1],
            'choice': explorer.abstract_event(event),
            'transition_id': transition_id,
            'target_state_id': target_id,
            'directive': directive,
        })
        states.append(target_id)
        state = successor_state
    return choices, states, transitions, steps, state


def _terminal_authority_cursor_join(
        authority, cursor, label, *, expected_status, expected_action,
        expected_grant_state, expected_tool_use_id):
    """Bind one captured authority snapshot to one exact controller cursor."""

    _require(type(authority) is dict and set(authority) == {
                 'status', 'owner', 'identity', 'tip', 'lifecycle', 'policy',
                 'hook_projection', 'ground_state_sha256',
                 'store_identity_sha256',
             }
             and authority['status'] == 'VERIFIED'
             and type(cursor) is dict
             and authority['tip'] == cursor,
             label + '_shape')
    owner = authority['owner']
    identity = authority['identity']
    hook = authority['hook_projection']
    lifecycle = authority['lifecycle']
    _require(
        expected_status in {'WAITING', 'ACTIVE', 'TERMINAL'}
        and (expected_action is not None) == (expected_status == 'ACTIVE'),
        label + '_expected_lifecycle')
    _require(
        (
            expected_status != 'ACTIVE'
            and expected_grant_state is None
            and expected_tool_use_id is None
        ) or (
            expected_status == 'ACTIVE'
            and (
                expected_grant_state == 'AUTHORIZED'
                and expected_tool_use_id is None
                or expected_grant_state == 'POST_OBSERVED'
                and type(expected_tool_use_id) is str
                and bool(expected_tool_use_id)
            )
        ),
        label + '_expected_grant_phase')
    hook_action = None
    if expected_action is not None:
        hook_action = {
            'action_id': expected_action['action_id'],
            'action_sha256': expected_action['action_sha256'],
            'kind': expected_action['kind'],
            'actor_thread_id': expected_action['actor_thread_id'],
            'lane_ids': list(expected_action['lane_ids']),
            'tool_name': expected_action['tool_name'],
            'tool_input_sha256': expected_action['tool_input_sha256'],
        }
    expected_lifecycle = {
        'terminal': expected_status == 'TERMINAL',
        'terminal_qualified': False,
        'terminal_evidence_sha256': None,
        'pending_intent': False,
        'cleanup_required': expected_status == 'TERMINAL',
        'action_sha256': (
            expected_action['action_sha256']
            if expected_action is not None else None),
        'grant_state': expected_grant_state,
        'tool_use_id': expected_tool_use_id,
        'expected_binding_status': expected_status,
    }
    hook_core = {
        'schema': native_contract.HOOK_BINDING_SCHEMA,
        'controller_id': owner['controller_id'],
        'controller_run_id': cursor['run_id'],
        'controller_seq': cursor['seq'],
        'controller_event_hash': cursor['event_hash'],
        'root_thread_id': identity['root_thread_id'],
        'root_session_id': identity['root_session_id'],
        'root_model': identity['root_model'],
        'hook_definition_sha256': identity['hook_definition_sha256'],
        'hook_registration_sha256': identity[
            'hook_registration_sha256'],
        'store_identity_sha256': authority['store_identity_sha256'],
        'ground_state_sha256': authority['ground_state_sha256'],
        'status': expected_status,
        'action': hook_action,
    }
    _require(type(owner) is dict and type(identity) is dict
             and type(hook) is dict and type(lifecycle) is dict
             and set(hook) == {
                 'controller_id', 'controller_run_id', 'controller_seq',
                 'controller_event_hash', 'binding_sha256',
             }
             and owner['controller_id'] == identity['controller_id']
                 == hook['controller_id']
             and owner['controller_run_id']
                 == identity['controller_run_id']
                 == hook['controller_run_id'] == cursor['run_id']
             and hook['controller_seq'] == cursor['seq']
             and hook['controller_event_hash'] == cursor['event_hash']
             and hook['binding_sha256']
                 == hashlib.sha256(
                     host_adapter.canonical_bytes(hook_core)).hexdigest()
             and lifecycle == expected_lifecycle,
             label + '_cursor')


def _validated_terminal_stage_chain(
        report, authority_before, authority_after, label, *,
        after_status, after_action):
    """Join one validated inspect/stage report to captured authority states."""

    _require(_same(report['authority_before'], authority_before),
             label + '_authority_before')
    cursor = authority_before['tip']
    _terminal_authority_cursor_join(
        authority_before, cursor, label + '_before',
        expected_status='WAITING', expected_action=None,
        expected_grant_state=None, expected_tool_use_id=None)
    transitions = report['controller_transitions']
    _require(type(transitions) is list and bool(transitions),
             label + '_transitions')
    for index, transition in enumerate(transitions):
        program = transition['program']
        controller = transition['report']
        operation = program['operation']
        after_cursor = controller['cursor']
        _require(program['expected_cursor'] == cursor,
                 label + '_expected_cursor_' + str(index))
        if operation == 'inspect':
            _require(after_cursor == cursor,
                     label + '_inspect_cursor_' + str(index))
        else:
            _require(after_cursor['run_id'] == cursor['run_id']
                     and type(after_cursor['seq']) is int
                     and type(cursor['seq']) is int
                     and after_cursor['seq'] > cursor['seq']
                     and after_cursor['event_hash'] != cursor['event_hash'],
                     label + '_advanced_cursor_' + str(index))
        cursor = after_cursor
    _terminal_authority_cursor_join(
        authority_after, cursor, label + '_after',
        expected_status=after_status, expected_action=after_action,
        expected_grant_state=(
            'AUTHORIZED' if after_action is not None else None),
        expected_tool_use_id=None)
    return transitions[-1]['report']


def compare_terminal_cleanup(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, standards_comparison, review_comparison,
        serial_observation, final_observation, spec_observation,
        standards_observation, review_observation, terminal_observation,
        expected_order):
    """Map terminal verification and source-owned cleanup from one review."""

    _require_issued_serial_comparison(serial_comparison)
    _require_issued_final_continuation(final_comparison, serial_comparison)
    _require_issued_spec_result(spec_comparison, final_comparison)
    _require_issued_standards_result(standards_comparison, spec_comparison)
    _require_issued_semantic_review(review_comparison, standards_comparison)
    review_report = _validated_semantic_review_outcome_order(
        checkpoint_wait_report, review_comparison, expected_order)
    live_review = compare_semantic_review_outcome(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, standards_comparison, serial_observation,
        final_observation, spec_observation, standards_observation,
        review_observation, expected_order)
    _require(live_review == review_comparison.report,
             'terminal_cleanup_review_parent')
    projection = _terminal_cleanup_input_projection(terminal_observation)
    try:
        cleanup_outcomes = terminal_observation['cleanup_outcomes']
        _terminal_cleanup_model_choices(cleanup_outcomes)
        review_outcome = terminal_observation['review_outcome']
        _require(type(expected_order) is tuple and len(expected_order) == 2
                 and set(expected_order) == {'spec', 'standards'}
                 and terminal_observation['schema']
                 == 'orch-dork/native-terminal-cleanup-observation/v1'
                 and terminal_observation['arrival_order']
                 == list(expected_order)
                 and review_outcome in {'accepted', 'rejected'}
                 and review_outcome == review_report['production_outcome']
                 and terminal_observation[
                     'predecessor_review_observation'] == review_observation,
                 'terminal_cleanup_scope')

        roots = terminal_observation['root_snapshots']
        workers = terminal_observation['worker_snapshots']
        _require(roots['before']
                 == review_observation['root_snapshots']['after']
                 and roots['after'] == roots['before']
                 and workers['before']
                 == review_observation['worker_snapshots']['after']
                 and workers['after'] == workers['before']
                 and type(terminal_observation[
                     'worker_final_source_observation_count']) is int
                 and terminal_observation[
                     'worker_final_source_observation_count'] == 0,
                 'terminal_cleanup_source_join')

        verification = terminal_observation['verification_report']
        authorization = terminal_observation[
            'cleanup_authorization_report']
        _require(successor.validate_issue94_successor_action_advance_report(
                     verification).get('valid') is True
                 and verification['decision']
                     == 'AWAITING_LIFECYCLE_CLEANUP'
                 and verification['action'] is None
                 and [row.get('program', {}).get('operation')
                      for row in verification['controller_transitions']]
                     == ['inspect', 'stage']
                 and verification['controller_transitions'][-1]['report'][
                     'stage_report']['receipt']['stage']
                     == 'terminal_verification'
                 and verification['controller_transitions'][-1]['report'][
                     'stage_report']['next_action'] == 'cleanup'
                 and verification['controller_transitions'][-1]['report'][
                     'stage_report']['terminal_claim_permitted'] is False,
                 'terminal_cleanup_verification')
        _require(successor.validate_issue94_successor_action_advance_report(
                     authorization).get('valid') is True
                 and authorization['decision'] == 'READY_FOR_NEXT_ACTION'
                 and [row.get('program', {}).get('operation')
                      for row in authorization['controller_transitions']]
                     == ['inspect', 'stage']
                 and authorization['controller_transitions'][-1]['report'][
                     'stage_report']['receipt']['stage'] == 'cleanup'
                 and authorization['controller_transitions'][-1]['report'][
                     'stage_report']['next_action'] == 'stop'
                 and authorization['controller_transitions'][-1]['report'][
                     'stage_report']['terminal_claim_permitted'] is False
                 and verification['worker_results']
                     == review_observation['final_report']['worker_results']
                 and authorization['worker_results']
                     == review_observation['final_report']['worker_results'],
                 'terminal_cleanup_authorization')

        steps = terminal_observation['close_steps']
        _require(type(steps) is list
                 and len(steps) == len(cleanup_outcomes),
                 'terminal_cleanup_steps')
        expected_action = authorization['action']
        for index, (step, raw_outcome) in enumerate(
                zip(steps, cleanup_outcomes)):
            lane = ('spec', 'standards')[index]
            _require(type(step) is dict and set(step) == {
                         'lane', 'expected_outcome', 'action', 'raw_response',
                         'pre_hook_report', 'post_hook_report',
                         'advance_report', 'error_type', 'error_message',
                         'transport_calls', 'fake_calls',
                     }
                     and step['lane'] == lane
                     and step['expected_outcome'] == raw_outcome
                     and step['action'] == expected_action
                     and step['action']['kind'] == 'stop'
                     and step['action']['lane_ids'] == [lane]
                     and step['action']['tool_name']
                         == 'multi_agent_v1__close_agent'
                     and step['post_hook_report']['native_controller'][
                         'outcome'] == raw_outcome
                     and type(step['transport_calls']) is int
                     and step['transport_calls'] == 1
                     and type(step['fake_calls']) is int
                     and step['fake_calls'] == 1,
                     'terminal_cleanup_step_' + lane)
            if raw_outcome == 'completed':
                _require(step['error_type'] is None
                         and step['error_message'] is None
                         and step['raw_response']
                             == {'previous_status': {
                                 'completed': 'shutdown'}}
                         and successor
                             .validate_issue94_successor_action_advance_report(
                                 step['advance_report']).get('valid') is True,
                         'terminal_cleanup_completed_' + lane)
                expected_action = step['advance_report']['action']
            else:
                _require(step['raw_response'] == {'status': raw_outcome}
                         and step['advance_report'] is None
                         and step['error_type']
                             == 'QualificationSuccessorError'
                         and step['error_message']
                             == ('successor_action_advance:'
                                 'observation_refused'),
                         'terminal_cleanup_stopped_' + lane)
                expected_action = None

        before_capacity = terminal_observation['capacity_before']
        _require(_same(before_capacity,
                       review_observation['capacity_after'])
                 and all(_same(value, before_capacity) for value in (
                     terminal_observation['capacity_after_verification'],
                     terminal_observation['capacity_after_authorization'],
                     terminal_observation['capacity_after'])),
                 'terminal_cleanup_capacity')
        static_authority_fields = {
            'status', 'owner', 'identity', 'policy',
            'ground_state_sha256', 'store_identity_sha256',
        }

        def static_authority(authority):
            _require(type(authority) is dict
                     and static_authority_fields.issubset(authority),
                     'terminal_cleanup_authority_shape')
            return {
                field: rv.freeze(authority[field]).to_plain()
                for field in static_authority_fields
            }

        before_authority = terminal_observation['authority_before']
        _require(_same(before_authority,
                       review_observation['authority_after'])
                 and all(static_authority(authority)
                         == static_authority(before_authority)
                         for authority in (
                             terminal_observation[
                                 'authority_after_verification'],
                             terminal_observation[
                                 'authority_after_authorization'],
                             terminal_observation['authority_after'])),
                 'terminal_cleanup_authority')
        review_controller = review_observation['final_report'][
            'controller_transitions'][-1]['report']
        _terminal_authority_cursor_join(
            before_authority, review_controller['cursor'],
            'terminal_cleanup_review_authority',
            expected_status='WAITING', expected_action=None,
            expected_grant_state=None, expected_tool_use_id=None)
        verification_controller = _validated_terminal_stage_chain(
            verification,
            before_authority,
            terminal_observation['authority_after_verification'],
            'terminal_cleanup_verification_chain',
            after_status='WAITING', after_action=None,
        )
        authorization_controller = _validated_terminal_stage_chain(
            authorization,
            terminal_observation['authority_after_verification'],
            terminal_observation['authority_after_authorization'],
            'terminal_cleanup_authorization_chain',
            after_status='ACTIVE', after_action=authorization['action'],
        )
        _require(
            verification_controller['cursor']
            == terminal_observation['authority_after_verification']['tip']
            and authorization_controller['cursor']
            == terminal_observation['authority_after_authorization']['tip'],
            'terminal_cleanup_stage_chain',
        )

        before_state = terminal_observation['controller_state_before']
        after_state = terminal_observation['controller_state_after']
        controller_rows = terminal_observation['controller_rows_after']
        _require(type(before_state) is dict and type(after_state) is dict
                 and type(before_state.get('action_evidence')) is list
                 and type(after_state.get('action_evidence')) is list
                 and len(after_state['action_evidence'])
                     == len(before_state['action_evidence']) + len(steps)
                 and type(controller_rows) is list
                 and _same(native_contract._reduce(
                     native_contract._controller_events(controller_rows)),
                     {
                         key: value for key, value in after_state.items()
                         if key not in {'grant_state', 'grant'}
                     }),
                 'terminal_cleanup_controller_state')
        evidence_offset = len(before_state['action_evidence'])
        previous_controller_report = authorization_controller
        expected_action = authorization['action']
        final_action_parent_cursor = None
        terminal_step_expectations = []
        for index, (step, raw_outcome) in enumerate(
                zip(steps, cleanup_outcomes)):
            lane = ('spec', 'standards')[index]
            final_action_parent_cursor = previous_controller_report['cursor']
            hook_binding = _validated_terminal_hook_step(
                step, expected_action, previous_controller_report,
                after_state['action_evidence'][evidence_offset + index],
                lane=lane, outcome=raw_outcome,
                label='terminal_cleanup_hook_' + lane)
            normalized = hook_binding['normalized']
            terminal_step_expectations.append({
                'action': expected_action,
                'outcome': raw_outcome,
                'parent_cursor': final_action_parent_cursor,
                'evidence': after_state['action_evidence'][
                    evidence_offset + index],
                'hook_binding': hook_binding,
                'step': step,
            })
            if raw_outcome == 'completed':
                checked = _validated_action_step(
                    {
                        key: step[key] for key in (
                            'action', 'raw_response', 'pre_hook_report',
                            'post_hook_report', 'advance_report')
                    },
                    expected_action,
                    previous_controller_report,
                    action_kind='stop', lane_ids=[lane],
                    outcome='completed',
                    label='terminal_cleanup_completed_hook_' + lane,
                )
                _require(_same(checked['normalized'], normalized),
                         'terminal_cleanup_completed_hook_binding_' + lane)
                _terminal_authority_cursor_join(
                    checked['authority'], checked['before_cursor'],
                    'terminal_cleanup_completed_authority_' + lane,
                    expected_status='ACTIVE',
                    expected_action=expected_action,
                    expected_grant_state='POST_OBSERVED',
                    expected_tool_use_id=checked['call_id'])
                previous_controller_report = checked['controller']
                expected_action = step['advance_report']['action']
            else:
                expected_action = None
        completed = cleanup_outcomes == ['completed', 'completed']
        try:
            verified_sequences = run_engine.verify_event_chain(
                controller_rows)
        except (TypeError, run_engine.RunKernelError) as error:
            raise values.LifecycleContractError(
                'public_native_comparison:'
                'terminal_cleanup_controller_chain') from error
        ordered_rows = sorted(
            controller_rows, key=lambda row: row['seq'])
        controller_event_rows = []
        for index, row in enumerate(ordered_rows):
            _require(row.get('origin')
                         == run_store.runtime_origin(row['kind'])
                     and row.get('note') is None
                     and (
                         row['kind'] == run_engine.KIND_STARTED
                         and row.get('actor_key') == 'kernel'
                         or row['kind'] == run_engine.KIND_APPLIED
                         and row.get('actor_key') == 'controller'
                     ),
                     'terminal_cleanup_controller_origin_' + str(index))
            if row['kind'] != run_engine.KIND_APPLIED:
                continue
            facts = _strict_json_record(row['payload'])
            raw_event = facts.get('deliverables', {}).get(
                'controller_event')
            event = _strict_json_record(raw_event)
            _require(set(facts) == {
                         'roles', 'status', 'deliverables', 'evidence',
                     }
                     and facts['roles'] == ['controller']
                     and facts['status'] == 'SUCCESS'
                     and set(facts['deliverables']) == {
                         'controller_event',
                     }
                     and facts['evidence'] == {
                         'controller_event': event['event_sha256'],
                     },
                     'terminal_cleanup_controller_envelope_' + str(index))
            controller_event_rows.append((row, event))
        _require(type(final_action_parent_cursor) is dict
                 and verified_sequences
                     == [row['seq'] for row in ordered_rows]
                 and all(row['run_id']
                         == final_action_parent_cursor['run_id']
                         for row in ordered_rows),
                 'terminal_cleanup_controller_chain')
        parent_rows = [
            row for row in ordered_rows
            if row['seq'] == final_action_parent_cursor['seq']
        ]
        _require(len(parent_rows) == 1
                 and parent_rows[0]['event_hash']
                     == final_action_parent_cursor['event_hash'],
                 'terminal_cleanup_parent_cursor')
        for index, expectation in enumerate(terminal_step_expectations):
            action = expectation['action']
            outcome = expectation['outcome']
            parent_cursor = expectation['parent_cursor']
            evidence = expectation['evidence']
            hook_binding = expectation['hook_binding']
            step = expectation['step']
            post_native = step['post_hook_report']['native_controller']
            native_receipt = {
                'schema': native_contract.NATIVE_ACTION_RECEIPT_SCHEMA,
                'action_id': action['action_id'],
                'outcome': outcome,
                'tool_name': action['tool_name'],
                'tool_input_sha256': action['tool_input_sha256'],
                'tool_use_id': hook_binding['call_id'],
                'result_sha256': post_native['result_sha256'],
                'result_binding': hook_binding['normalized'],
                'source_pointer': (
                    'project-ground-durable-event#'
                    + hook_binding['post_durable'][
                        'durable_record_sha256']),
            }
            observation = {
                'schema': native_contract.ACTION_OBSERVATION_SCHEMA,
                'action_id': action['action_id'],
                'tool_name': action['tool_name'],
                'tool_input_sha256': action['tool_input_sha256'],
                'tool_use_id': hook_binding['call_id'],
                'outcome': outcome,
                'hook_report_sha256': step['post_hook_report'][
                    'report_sha256'],
                'native_receipt': native_receipt,
            }
            intent_matches = [
                (position, row, event)
                for position, (row, event) in enumerate(
                    controller_event_rows)
                if event['event_type'] == 'action_observation_intent'
                and event['payload'].get('action_id')
                    == action['action_id']
            ]
            _require(len(intent_matches) == 1,
                     'terminal_cleanup_intent_count_' + str(index))
            position, intent_row, intent_event = intent_matches[0]
            intent_cursor = {
                'run_id': intent_row['run_id'],
                'seq': intent_row['seq'],
                'event_hash': intent_row['event_hash'],
            }
            _require(intent_event['payload'] == {
                         'action_id': action['action_id'],
                         'observation_sha256': native_contract._sha(
                             observation),
                     }
                     and intent_cursor['run_id'] == parent_cursor['run_id']
                     and intent_cursor['seq'] == parent_cursor['seq'] + 1
                     and intent_row['prev_hash']
                         == parent_cursor['event_hash']
                     and position + 1 < len(controller_event_rows),
                     'terminal_cleanup_intent_' + str(index))
            observed_row, observed_event = controller_event_rows[
                position + 1]
            next_action = (
                step['advance_report']['action']
                if outcome == 'completed' else None
            )
            batch_result = None
            batch_outcome = outcome
            cleanup_required = outcome != 'completed'
            terminal = cleanup_required
            if outcome == 'completed':
                final_batch_action = (
                    action['batch_index'] + 1 == action['batch_size'])
                batch_outcome = (
                    'completed' if final_batch_action else 'pending')
                if final_batch_action:
                    batch_result = native_contract.GovernedNativeController \
                        ._aggregate_batch_result(
                            after_state['action_evidence'][
                                :evidence_offset + index + 1],
                            action,
                        )
                    _require(type(batch_result) is dict,
                             'terminal_cleanup_batch_result_' + str(index))
            elif action.get('batch_failure_outcome') is not None:
                batch_outcome = (
                    'unknown'
                    if 'unknown' in (
                        action['batch_failure_outcome'], outcome)
                    else action['batch_failure_outcome']
                )
            expected_observed = {
                'intent_cursor': intent_cursor,
                'action_id': action['action_id'],
                'outcome': outcome,
                'native_receipt_sha256': native_contract._sha(
                    native_receipt),
                'hook_report_sha256': step['post_hook_report'][
                    'report_sha256'],
                'tool_use_id': hook_binding['call_id'],
                'hook_evidence': evidence,
                'next_action': next_action,
                'next_capacity_guard': None,
                'batch_result': batch_result,
                'batch_outcome': batch_outcome,
                'cleanup_required': cleanup_required,
                'terminal': terminal,
            }
            _require(observed_event['event_type'] == 'action_observed'
                     and observed_event['payload'] == expected_observed
                     and observed_row['run_id'] == intent_cursor['run_id']
                     and observed_row['seq'] == intent_cursor['seq'] + 1
                     and observed_row['prev_hash']
                         == intent_cursor['event_hash'],
                     'terminal_cleanup_observed_' + str(index))
        final_row = ordered_rows[-1]
        final_cursor = {
            'run_id': final_row['run_id'],
            'seq': final_row['seq'],
            'event_hash': final_row['event_hash'],
        }
        if completed:
            _require(final_cursor == previous_controller_report['cursor'],
                     'terminal_cleanup_final_completed_cursor')
        else:
            _require(final_cursor['run_id']
                         == final_action_parent_cursor['run_id']
                     and final_cursor['seq']
                         == final_action_parent_cursor['seq'] + 2
                     and final_cursor['event_hash']
                         != final_action_parent_cursor['event_hash'],
                     'terminal_cleanup_final_stopped_cursor')
        _terminal_authority_cursor_join(
            terminal_observation['authority_after'], final_cursor,
            'terminal_cleanup_final_authority',
            expected_status='WAITING' if completed else 'TERMINAL',
            expected_action=None, expected_grant_state=None,
            expected_tool_use_id=None)
        if completed:
            _require(steps[0]['advance_report']['decision']
                         == 'READY_FOR_NEXT_ACTION'
                     and steps[0]['advance_report']['action']['lane_ids']
                         == ['standards']
                     and steps[1]['advance_report']['decision']
                         == 'ACTION_BATCH_OBSERVED'
                     and steps[1]['advance_report']['action'] is None
                     and after_state.get('terminal') is False
                     and after_state.get('cleanup_required') is False
                     and after_state.get('action') is None
                     and after_state.get('last_batch_result', {}).get('kind')
                         == 'stop'
                     and after_state.get('stage_report', {}).get(
                         'receipt', {}).get('stage') == 'cleanup'
                     and terminal_observation['authority_after'].get(
                         'lifecycle', {}).get('expected_binding_status')
                         == 'WAITING',
                     'terminal_cleanup_completed_boundary')
        elif cleanup_outcomes[-1] != 'completed':
            _require(after_state.get('terminal') is True
                     and after_state.get('cleanup_required') is True
                     and after_state.get('action') is None
                     and after_state.get('action_outcome')
                         == cleanup_outcomes[-1]
                     and after_state.get('stage_report', {}).get(
                         'receipt', {}).get('stage') == 'cleanup'
                     and terminal_observation['authority_after'].get(
                         'lifecycle', {}).get('expected_binding_status')
                         == 'TERMINAL'
                     and terminal_observation['authority_after'].get(
                         'lifecycle', {}).get('cleanup_required') is True,
                     'terminal_cleanup_failed_boundary')

        choices, state_ids, transition_ids, model_steps, model_state = (
            _terminal_cleanup_model_bridge(
                review_report['model_state'], cleanup_outcomes)
        )
        model_facts = model_state.to_plain()
        if completed:
            _require(model_facts['stage'] == 'process'
                     and model_facts['process_group'] == 'unproven'
                     and model_facts['capacity_settlement'] == 'pending'
                     and model_facts['attempt_closure'] is None
                     and model_facts['controller']['owner_disposition']
                         == 'retained',
                     'terminal_cleanup_model_success_frontier')
        elif cleanup_outcomes[-1] != 'completed':
            _require(model_facts['requirement'] is not None
                     and model.legal_directive(model_state).to_plain()[
                         'kind'] == 'external_authority_required',
                     'terminal_cleanup_model_failure_frontier')

        observation_sha256 = values.canonical_digest(projection)
        input_sha256 = values.canonical_digest({
            'review_outcome_sha256': review_comparison.report.digest(),
            'production_observation_sha256': observation_sha256,
        })
        graph_mapping = {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': {
                'kind': 'observed_terminal_cleanup_path',
                'source_state_id': state_ids[0],
                'target_state_id': state_ids[-1],
                'model_bridge_state_ids': state_ids,
                'model_bridge_transition_ids': transition_ids,
                'model_bridge_steps': model_steps,
            },
            'gap': {
                'status': 'PREFIX_ONLY',
                'observed_boundary_count': 15 + len(choices),
                'next_uncovered_choices': [
                    explorer.abstract_event(item) for item in
                    model.outgoing_stimuli(model_state).to_plain()
                ],
                'production_graph_complete': False,
            },
        }
        return rv.freeze({
            'schema':
                'orch-dork/production-graph-terminal-cleanup-path/v1',
            'scope': 'source_bound_terminal_cleanup_reconstruction',
            'arrival_order': list(expected_order),
            'review_outcome': review_outcome,
            'production_cleanup_outcomes': list(cleanup_outcomes),
            'model_cleanup_outcomes': [
                choice['outcome'] for choice in choices
                if choice['stage'].startswith('close.')
            ],
            'production_observation_sha256': observation_sha256,
            'review_outcome_sha256': review_comparison.report.digest(),
            'graph_mapping': graph_mapping,
            'model_state': model_facts,
            'input_sha256': input_sha256,
            **{field: False for field in _SERIAL_FALSE_FIELDS},
        })
    except (KeyError, IndexError, TypeError, StopIteration, UnicodeError,
            ValueError, OverflowError, RecursionError) as error:
        if isinstance(error, values.LifecycleContractError):
            raise
        raise values.LifecycleContractError(
            'public_native_comparison:unsupported_terminal_cleanup_shape'
        ) from error


def capture_terminal_cleanup_comparison(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, standards_comparison, review_comparison,
        serial_observation, final_observation, spec_observation,
        standards_observation, review_observation, terminal_observation,
        expected_order, *, capture_session):
    """Issue one terminal-cleanup comparison from its exact live source."""

    capture_record = _require_live_observation(
        capture_session, 'serial', serial_observation)
    for kind, observation in (
            ('final', final_observation), ('spec', spec_observation),
            ('standards', standards_observation),
            ('review', review_observation),
            ('terminal_cleanup', terminal_observation)):
        _require_live_observation(capture_session, kind, observation)
    review_token = (review_comparison._issue_token
                    if type(review_comparison)
                    is SemanticReviewOutcomeLiveComparison else None)
    review_record = _ISSUED_SEMANTIC_REVIEWS.get(review_token)
    _require(review_record is not None
             and review_record['capture_token']
                 is capture_session._capture_token,
             'live_capture_review_session_join')
    report = compare_terminal_cleanup(
        checkpoint_wait_report, serial_comparison, final_comparison,
        spec_comparison, standards_comparison, review_comparison,
        serial_observation, final_observation, spec_observation,
        standards_observation, review_observation, terminal_observation,
        expected_order)
    _require(review_token not in capture_record['issued_terminal_cleanup'],
             'live_capture_duplicate_terminal_cleanup')
    token = object()
    value = TerminalCleanupLiveComparison(
        report=report,
        _review_parent=review_comparison,
        _authority=_TERMINAL_CLEANUP_AUTHORITY,
        _issue_token=token,
    )
    _ISSUED_TERMINAL_CLEANUPS[token] = {
        'value': weakref.ref(
            value,
            lambda _: _ISSUED_TERMINAL_CLEANUPS.pop(token, None)),
        'pid': os.getpid(),
        'fingerprint': _terminal_cleanup_fingerprint(value),
        'parent': weakref.ref(value._review_parent),
        'capture_token': capture_session._capture_token,
    }
    capture_record['issued_terminal_cleanup'].add(review_token)
    return value


def _terminal_settlement_model_bridge(cleanup_state, review_outcome):
    """Advance one completed cleanup frontier through observed owner rotation."""

    _require(review_outcome in {'accepted', 'rejected'},
             'terminal_settlement_review_outcome')
    state = rv.freeze(cleanup_state)
    states = [explorer.state_identity(state)]
    transitions = []
    steps = []
    choices = [
        {'stage': 'process', 'lane': 'controller',
         'outcome': 'accepted', 'variant': 'evidence'},
        {'stage': 'settle', 'lane': 'controller',
         'outcome': 'accepted', 'variant': 'evidence'},
        {'stage': ('final_qualification' if review_outcome == 'accepted'
                   else 'failure_closure'),
         'lane': 'controller', 'outcome': 'accepted',
         'variant': 'evidence'},
        {'stage': 'rotate', 'lane': 'controller',
         'outcome': 'accepted', 'variant': 'evidence'},
    ]
    for choice in choices:
        events = [
            event for event in model.outgoing_stimuli(state).to_plain()
            if _same(explorer.abstract_event(event), choice)
        ]
        _require(len(events) == 1,
                 'terminal_settlement_model_choice')
        event = events[0]
        reduction = model.reduce(state, event).to_plain()
        successor_state = rv.freeze(reduction['successor'])
        target_id = explorer.state_identity(successor_state)
        directive = model.legal_directive(successor_state).to_plain()
        _require(_same(reduction['directive'], directive),
                 'terminal_settlement_model_directive')
        transition_id = explorer.edge_identity(
            states[-1], event, target_id)
        transitions.append(transition_id)
        steps.append({
            'source_state_id': states[-1],
            'choice': explorer.abstract_event(event),
            'transition_id': transition_id,
            'target_state_id': target_id,
            'directive': directive,
        })
        states.append(target_id)
        state = successor_state
    return choices, states, transitions, steps, state


def _source_snapshot_projection(value):
    """Make exact binary source snapshots canonical without retaining bytes."""

    if type(value) is bytes:
        return {
            'size_bytes': len(value),
            'sha256': hashlib.sha256(value).hexdigest(),
        }
    if type(value) is dict:
        return {
            key: _source_snapshot_projection(child)
            for key, child in sorted(value.items())
        }
    if type(value) is list:
        return [_source_snapshot_projection(child) for child in value]
    _require(type(value) in {str, int, bool, type(None)},
             'terminal_settlement_source_snapshot_value')
    return value


def _terminal_settlement_projection(observation):
    """Select the canonical, JSON-safe producer reports used by I.2."""

    projection = {
        key: deepcopy(observation[key])
        for key in (
            'schema', 'review_outcome',
            'completion_capture', 'completion_owner_records',
            'completion_owner_transport_budget', 'completion_owner_cleanup',
            'successor_trust_owner_records',
            'successor_trust_owner_transport_budget',
            'successor_trust_owner_cleanup',
            'process_pending_observation',
            'process_observation', 'settlement_report', 'closure_program',
            'closure_report', 'owner_disposition_program',
            'owner_disposition_report', 'predecessor_owner',
            'predecessor_cursor', 'predecessor_authority',
            'pre_rotation_observation', 'successor_activation_program',
            'successor_activation_report', 'rotation_observation',
            'capacity_before', 'capacity_after', 'authority_before',
            'authority_after', 'grants_before', 'grants_after',
            'terminal_claim_permitted',
        )
    }
    projection['parent_terminal_cleanup'] = (
        _terminal_cleanup_input_projection(
            observation['parent_terminal_cleanup']))
    projection['source_snapshots'] = _source_snapshot_projection(
        observation['source_snapshots'])
    return projection


def compare_terminal_settlement(
        terminal_comparison, terminal_observation,
        settlement_observation, expected_order):
    """Map exact process cleanup, settlement, closure and owner rotation."""

    review = (terminal_comparison._review_parent
              if type(terminal_comparison)
              is TerminalCleanupLiveComparison else None)
    _require_issued_terminal_cleanup(terminal_comparison, review)
    cleanup_report = terminal_comparison.report.to_plain()
    try:
        expected_fields = {
            'schema', 'review_outcome', 'parent_terminal_cleanup',
            'completion_capture', 'completion_owner_records',
            'completion_owner_transport_budget', 'completion_owner_cleanup',
            'successor_trust_owner_records',
            'successor_trust_owner_transport_budget',
            'successor_trust_owner_cleanup',
            'process_pending_observation',
            'process_observation', 'settlement_report', 'closure_program',
            'closure_report', 'owner_disposition_program',
            'owner_disposition_report', 'predecessor_owner',
            'predecessor_cursor', 'predecessor_authority',
            'pre_rotation_observation', 'successor_activation_program',
            'successor_activation_report', 'rotation_observation',
            'capacity_before', 'capacity_after', 'authority_before',
            'authority_after', 'grants_before', 'grants_after',
            'source_snapshots', 'terminal_claim_permitted',
        }
        _require(type(settlement_observation) is dict
                 and set(settlement_observation) == expected_fields
                 and settlement_observation['schema'] == (
                     'orch-dork/native-terminal-settlement-observation/v1')
                 and settlement_observation['review_outcome']
                     in {'accepted', 'rejected'}
                 and settlement_observation['review_outcome']
                     == cleanup_report['review_outcome']
                 and cleanup_report['arrival_order']
                     == list(expected_order)
                 and cleanup_report['production_cleanup_outcomes']
                     == ['completed', 'completed']
                 and _same(_terminal_cleanup_input_projection(
                     settlement_observation['parent_terminal_cleanup']),
                     _terminal_cleanup_input_projection(
                         terminal_observation)),
                 'terminal_settlement_observation_shape')
        observation = settlement_observation
        capture = observation['completion_capture']
        completion_owner_records = observation['completion_owner_records']
        completion_owner_budget = observation[
            'completion_owner_transport_budget']
        successor_trust_owner_records = observation[
            'successor_trust_owner_records']
        successor_trust_owner_budget = observation[
            'successor_trust_owner_transport_budget']
        pending = observation['process_pending_observation']
        process = observation['process_observation']
        settled = observation['settlement_report']
        closure_program = observation['closure_program']
        closure = observation['closure_report']
        disposition_program = observation['owner_disposition_program']
        disposition = observation['owner_disposition_report']
        activation_program = observation['successor_activation_program']
        activation = observation['successor_activation_report']
        rotation = observation['rotation_observation']
        final_cleanup_controller = terminal_observation[
            'close_steps'][-1]['advance_report'][
                'controller_transitions'][-1]['report']
        snapshots = observation['source_snapshots']
        _require(type(snapshots) is dict
                 and set(snapshots) == {'before', 'after'}
                 and all(type(snapshots[point]) is dict
                         and set(snapshots[point])
                         == {'root', 'spec', 'standards'}
                         and all(type(value) is bytes
                                 for value in snapshots[point].values())
                         for point in ('before', 'after'))
                 and snapshots['before']['root']
                     == terminal_observation['root_snapshots']['after']
                 and snapshots['before']['spec']
                     == terminal_observation[
                         'worker_snapshots']['after']['spec']
                 and snapshots['before']['standards']
                     == terminal_observation[
                         'worker_snapshots']['after']['standards']
                 and snapshots['after']['root'].startswith(
                     snapshots['before']['root'])
                 and len(snapshots['after']['root'])
                     > len(snapshots['before']['root'])
                 and snapshots['after']['spec']
                     == snapshots['before']['spec']
                 and snapshots['after']['standards']
                     == snapshots['before']['standards'],
                 'terminal_settlement_source_snapshots')

        _require(native_contract.validate_verified_completion_source_capture(
                     capture).get('valid') is True
                 and capture['status'] == 'OBSERVED'
                 and capture['terminal_claim_permitted'] is False
                 and all(_same(capture['controller_report'][field],
                               final_cleanup_controller[field])
                         for field in (
                             'controller_id', 'cursor', 'stage_report',
                             'controller_state'))
                 and _same(capture['authority_before'],
                           terminal_observation['authority_after'])
                 and _same(capture['authority_after'],
                           terminal_observation['authority_after'])
                 and _same(capture['action_evidence'], [
                     row for row in terminal_observation[
                         'controller_state_after']['action_evidence']
                     if row['action']['kind'] == 'stop'
                 ])
                 and hashlib.sha256(
                     snapshots['after']['root']).hexdigest()
                     == capture['source_observation']['evidence'][
                         'roles']['root']['file_sha256'],
                 'terminal_settlement_completion_capture')
        _require(type(completion_owner_records) is list
                 and len(completion_owner_records) == 45
                 and all(type(record) is dict and 'error' not in record
                         for record in completion_owner_records)
                 and [(record.get('kind'), record.get('method'))
                      for record in completion_owner_records] == ([
                     ('connection', None),
                     ('request', 'initialize'),
                     ('notification', 'initialized'),
                     ('request', 'thread/read'),
                     ('request', 'thread/read'),
                     ('request', 'thread/read'),
                     ('request', 'thread/loaded/list'),
                     ('request', 'hooks/list'),
                     ('request', 'thread/read'),
                     ('request', 'thread/read'),
                     ('request', 'thread/read'),
                     ('request', 'thread/loaded/list'),
                     ('request', 'hooks/list'),
                     ('peer_identity', None),
                     ('peer_invocation', None),
                 ] * 3)
                 and all(record.get('closed') is True
                         for record in completion_owner_records
                         if record.get('kind') == 'connection')
                 and type(completion_owner_budget) is dict
                 and set(completion_owner_budget) == {
                     'max_calls', 'calls_retained', 'within_bound',
                 }
                 and completion_owner_budget['max_calls'] == 256
                 and completion_owner_budget['calls_retained'] == 45
                 and completion_owner_budget['within_bound'] is True
                 and observation['completion_owner_cleanup'] == {
                     'closed': True, 'socket_removed': True,
                 },
                 'terminal_settlement_completion_owner_scope')
        _require(type(successor_trust_owner_records) is list
                 and len(successor_trust_owner_records) == 7
                 and all(type(record) is dict and 'error' not in record
                         for record in successor_trust_owner_records)
                 and [(record.get('kind'), record.get('method'))
                      for record in successor_trust_owner_records] == [
                     ('connection', None),
                     ('request', 'initialize'),
                     ('notification', 'initialized'),
                     ('request', 'thread/read'),
                     ('request', 'thread/loaded/list'),
                     ('request', 'thread/list'),
                     ('request', 'hooks/list'),
                 ]
                 and successor_trust_owner_records[0].get('closed') is True
                 and type(successor_trust_owner_budget) is dict
                 and set(successor_trust_owner_budget) == {
                     'max_calls', 'calls_retained', 'within_bound',
                 }
                 and successor_trust_owner_budget['max_calls'] == 256
                 and successor_trust_owner_budget['calls_retained'] == 7
                 and successor_trust_owner_budget['within_bound'] is True
                 and observation['successor_trust_owner_cleanup'] == {
                     'closed': True, 'socket_removed': True,
                 },
                 'terminal_settlement_successor_trust_owner_scope')
        _require(completion_process.validate_completion_process_observation(
                     pending, capture).get('valid') is True
                 and pending['status'] == 'PENDING'
                 and pending['observation']['group_absent'] is False
                 and completion_process.validate_completion_process_observation(
                     process, capture).get('valid') is True
                 and process['status'] == 'OBSERVED'
                 and process['observation']['group_absent'] is True
                 and process['observation']['group_members'] == 0
                 and _same(pending['binding'], process['binding']),
                 'terminal_settlement_process')
        _require(completion_settlement.validate_completed_capacity_settlement(
                     settled).get('valid') is True
                 and settled['status'] == 'PASS'
                 and settled['resource_release_proven'] is True
                 and settled['terminal_claim_permitted'] is False
                 and _same(settled['completion_capture'], capture)
                 and _same(settled['process_observation'], process)
                 and _same(settled['capacity_before'],
                           observation['capacity_before'])
                 and _same(settled['capacity_after'],
                           observation['capacity_after'])
                 and settled['capacity_after']['state'][
                     'active_lane_ids'] == []
                 and len(settled['release_receipts']) == 2,
                 'terminal_settlement_capacity')

        review_outcome = observation['review_outcome']
        expected_operation = ('final_qualification'
                              if review_outcome == 'accepted'
                              else 'failure_closure')
        identity = closure_program['identity']
        if expected_operation == 'final_qualification':
            expected_closure_program = (
                final_qualification.build_final_qualification_program(
                    identity, settled,
                    closure_program['payload']['pre_spawn_program']))
            closure_validation = (
                final_qualification.validate_final_qualification_report(
                    closure['stage_report']))
            closure_disposition = 'FINAL_QUALIFICATION_VERIFIED'
        else:
            expected_closure_program = (
                failure_closure.build_failure_closure_program(
                    identity, settled))
            closure_validation = (
                failure_closure.validate_failure_closure_report(
                    closure['stage_report']))
            closure_disposition = 'VERIFIED_FAILURE_CLOSED'
        _require(closure_program['operation'] == expected_operation
                 and _same(closure_program, expected_closure_program)
                 and native_contract.validate_governed_native_controller_report(
                     closure).get('valid') is True
                 and closure['status'] == 'PASS'
                 and closure['stage_report']['operation']
                     == expected_operation
                 and closure['stage_report']['disposition']
                     == closure_disposition
                 and closure['next_stage_action'] == 'owner_disposition'
                 and closure['stage_report']['terminal_claim_permitted']
                     is False
                 and closure_validation.get('valid') is True
                 and closure['cursor']['run_id']
                     == settled['native_result']['cursor']['run_id']
                 and closure['cursor']['seq']
                     > settled['native_result']['cursor']['seq'],
                 'terminal_settlement_closure')
        expected_disposition_program = (
            owner_disposition.build_owner_disposition_program(
                identity, closure['stage_report']))
        _require(_same(disposition_program,
                       expected_disposition_program)
                 and native_contract.validate_governed_native_controller_report(
                     disposition).get('valid') is True
                 and disposition['status'] == 'PASS'
                 and disposition['stage_report']['disposition']
                     == 'CONTROLLER_QUIESCENT'
                 and disposition['next_stage_action']
                     == 'await_successor_owner'
                 and disposition['controller_state']['terminal'] is True
                 and disposition['action'] is None
                 and disposition['controller_state'][
                     'cleanup_required'] is False
                 and disposition['stage_report'][
                     'terminal_claim_permitted'] is False
                 and owner_disposition.validate_owner_disposition_report(
                     disposition['stage_report']).get('valid') is True,
                 'terminal_settlement_owner_disposition')

        predecessor = observation['predecessor_owner']
        predecessor_cursor = observation['predecessor_cursor']
        refused_rotation = observation['pre_rotation_observation']
        _require(owner_rotation.validate_owner_rotation_observation(
                     refused_rotation).get('valid') is True
                 and refused_rotation['status'] == 'REFUSED'
                 and refused_rotation['owner_released'] is False
                 and _same(observation['predecessor_authority']['owner'],
                           predecessor)
                 and _same(observation['predecessor_authority']['tip'],
                           predecessor_cursor)
                 and _same(observation['authority_before'],
                           observation['predecessor_authority'])
                 and disposition['controller_id']
                     == predecessor['controller_id']
                 and _same(disposition['cursor'], predecessor_cursor)
                 and _same(observation['authority_before']['tip'],
                           disposition['cursor']),
                 'terminal_settlement_pre_rotation')
        _require(activation_program['operation'] == 'activate'
                 and activation_program['expected_cursor'] is None
                 and native_contract.validate_governed_native_controller_report(
                     activation).get('valid') is True
                 and activation['status'] == 'PASS'
                 and activation['decision'] == 'ACTIVATED_READ_ONLY'
                 and activation['controller_id']
                     == activation_program['controller_id']
                 and activation['controller_id']
                     != predecessor['controller_id']
                 and owner_rotation.validate_owner_rotation_observation(
                     rotation).get('valid') is True
                 and rotation['status'] == 'OBSERVED'
                 and rotation['owner_released'] is True
                 and rotation['terminal_claim_permitted'] is False
                 and _same(rotation['snapshot']['predecessor']['owner'],
                           predecessor)
                 and _same(rotation['snapshot']['predecessor']['cursor'],
                           predecessor_cursor)
                 and _same(rotation['snapshot']['successor']['authority'],
                           observation['authority_after'])
                 and _same(observation['authority_after']['tip'],
                           activation['cursor'])
                 and observation['authority_after']['owner'][
                     'controller_id'] == activation['controller_id']
                 and observation['grants_after'][
                     'unsettled_grant_count'] == 0
                 and observation['terminal_claim_permitted'] is False,
                 'terminal_settlement_rotation')
        _require(_same(observation['grants_before']['owner'],
                       predecessor)
                 and observation['grants_before'][
                     'unsettled_grant_count'] == 0
                 and _same(observation['capacity_before'],
                           terminal_observation['capacity_after'])
                 and _same(observation['capacity_after'],
                           rotation['snapshot']['capacity']),
                 'terminal_settlement_resources')

        choices, state_ids, transition_ids, model_steps, model_state = (
            _terminal_settlement_model_bridge(
                cleanup_report['model_state'], review_outcome))
        model_facts = model_state.to_plain()
        _require(model_facts['stage'] == 'terminal'
                 and model_facts['process_group']
                     == 'zero_owned_descendants'
                 and model_facts['capacity_settlement'] == 'released'
                 and model_facts['controller']['owner_disposition']
                     == 'rotated'
                 and model_facts['requirement'] is None
                 and model.legal_directive(model_state).to_plain()[
                     'kind'] == 'terminal_closure',
                 'terminal_settlement_model_terminal')
        projection = _terminal_settlement_projection(observation)
        observation_sha256 = values.canonical_digest(projection)
        input_sha256 = values.canonical_digest({
            'terminal_cleanup_sha256': terminal_comparison.report.digest(),
            'production_observation_sha256': observation_sha256,
        })
        graph_mapping = {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': {
                'kind': 'observed_terminal_settlement_and_owner_rotation',
                'source_state_id': state_ids[0],
                'target_state_id': state_ids[-1],
                'model_bridge_state_ids': state_ids,
                'model_bridge_transition_ids': transition_ids,
                'model_bridge_steps': model_steps,
            },
            'gap': {
                'status': 'TERMINAL_PATH',
                'observed_boundary_count': (
                    cleanup_report['graph_mapping']['gap'][
                        'observed_boundary_count'] + len(choices)),
                'next_uncovered_choices': [],
                'production_graph_complete': False,
            },
        }
        return rv.freeze({
            'schema':
                'orch-dork/production-graph-terminal-settlement-path/v1',
            'scope':
                'source_bound_terminal_settlement_reconstruction',
            'arrival_order': list(expected_order),
            'review_outcome': review_outcome,
            'closure_operation': expected_operation,
            'process_group_absent': True,
            'resource_release_proven': True,
            'owner_rotation_observed': True,
            'source_terminal_claim_permitted': False,
            'production_observation_sha256': observation_sha256,
            'terminal_cleanup_sha256': terminal_comparison.report.digest(),
            'graph_mapping': graph_mapping,
            'model_state': model_facts,
            'input_sha256': input_sha256,
            **{field: False for field in _SERIAL_FALSE_FIELDS},
        })
    except (KeyError, IndexError, TypeError, StopIteration, UnicodeError,
            ValueError, OverflowError, RecursionError) as error:
        if isinstance(error, values.LifecycleContractError):
            raise
        raise values.LifecycleContractError(
            'public_native_comparison:'
            'unsupported_terminal_settlement_shape') from error


def capture_terminal_settlement_comparison(
        terminal_comparison, terminal_observation,
        settlement_observation, expected_order, *, capture_session):
    """Issue one terminal settlement from the exact live I.2 session."""

    capture_record = _require_live_observation(
        capture_session, 'terminal_cleanup', terminal_observation)
    _require_live_observation(
        capture_session, 'terminal_settlement', settlement_observation)
    cleanup_token = (terminal_comparison._issue_token
                     if type(terminal_comparison)
                     is TerminalCleanupLiveComparison else None)
    cleanup_record = _ISSUED_TERMINAL_CLEANUPS.get(cleanup_token)
    _require(cleanup_record is not None
             and cleanup_record['capture_token']
                 is capture_session._capture_token,
             'live_capture_terminal_cleanup_session_join')
    _require(cleanup_token not in capture_record[
                 'issued_terminal_settlement'],
             'live_capture_duplicate_terminal_settlement')
    report = compare_terminal_settlement(
        terminal_comparison, terminal_observation,
        settlement_observation, expected_order)
    token = object()
    value = TerminalSettlementLiveComparison(
        report=report,
        _cleanup_parent=terminal_comparison,
        _authority=_TERMINAL_SETTLEMENT_AUTHORITY,
        _issue_token=token,
    )
    _ISSUED_TERMINAL_SETTLEMENTS[token] = {
        'value': weakref.ref(
            value,
            lambda _: _ISSUED_TERMINAL_SETTLEMENTS.pop(token, None)),
        'pid': os.getpid(),
        'fingerprint': _terminal_settlement_fingerprint(value),
        'parent': weakref.ref(value._cleanup_parent),
        'capture_token': capture_session._capture_token,
    }
    capture_record['issued_terminal_settlement'].add(cleanup_token)
    return value


def _validated_terminal_cleanup_order(
        checkpoint_wait_report, retained_comparison, expected_order):
    """Validate one issued terminal-cleanup path after source expiry."""

    review = (retained_comparison._review_parent
              if type(retained_comparison)
              is TerminalCleanupLiveComparison else None)
    standards = (review._standards_parent
                 if type(review) is SemanticReviewOutcomeLiveComparison
                 else None)
    spec = (standards._spec_parent
            if type(standards) is StandardsResultLiveComparison else None)
    final = (spec._final_parent
             if type(spec) is SpecResultLiveComparison else None)
    serial = (final._serial_parent
              if type(final) is FinalContinuationLiveComparison else None)
    _require_issued_serial_comparison(serial)
    _require_issued_final_continuation(final, serial)
    _require_issued_spec_result(spec, final)
    _require_issued_standards_result(standards, spec)
    _require_issued_semantic_review(review, standards)
    _require_issued_terminal_cleanup(retained_comparison, review)
    review_report = _validated_semantic_review_outcome_order(
        checkpoint_wait_report, review, expected_order)
    report = retained_comparison.report.to_plain()
    try:
        _require(type(report) is dict and set(report) == {
            'schema', 'scope', 'arrival_order', 'review_outcome',
            'production_cleanup_outcomes', 'model_cleanup_outcomes',
            'production_observation_sha256', 'review_outcome_sha256',
            'graph_mapping', 'model_state', 'input_sha256',
            *_SERIAL_FALSE_FIELDS,
        } and report['schema']
            == 'orch-dork/production-graph-terminal-cleanup-path/v1'
            and report['scope']
            == 'source_bound_terminal_cleanup_reconstruction'
            and report['arrival_order'] == list(expected_order)
            and report['review_outcome'] in {'accepted', 'rejected'}
            and report['review_outcome']
                == review_report['production_outcome']
            and re.fullmatch(
                r'[0-9a-f]{64}',
                report['production_observation_sha256']) is not None
            and report['review_outcome_sha256'] == review.report.digest()
            and report['input_sha256'] == values.canonical_digest({
                'review_outcome_sha256': report['review_outcome_sha256'],
                'production_observation_sha256': report[
                    'production_observation_sha256'],
            })
            and all(report[field] is False
                    for field in _SERIAL_FALSE_FIELDS),
                 'retained_terminal_cleanup_shape')
        choices, states, transitions, steps, model_state = (
            _terminal_cleanup_model_bridge(
                review_report['model_state'],
                report['production_cleanup_outcomes'])
        )
        expected_mapping = {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': {
                'kind': 'observed_terminal_cleanup_path',
                'source_state_id': states[0],
                'target_state_id': states[-1],
                'model_bridge_state_ids': states,
                'model_bridge_transition_ids': transitions,
                'model_bridge_steps': steps,
            },
            'gap': {
                'status': 'PREFIX_ONLY',
                'observed_boundary_count': 15 + len(choices),
                'next_uncovered_choices': [
                    explorer.abstract_event(item) for item in
                    model.outgoing_stimuli(model_state).to_plain()
                ],
                'production_graph_complete': False,
            },
        }
        _require(report['model_cleanup_outcomes'] == [
                     choice['outcome'] for choice in choices
                     if choice['stage'].startswith('close.')]
                 and _same(report['graph_mapping'], expected_mapping)
                 and _same(report['model_state'], model_state.to_plain()),
                 'retained_terminal_cleanup_mapping')
        return report
    except (KeyError, IndexError, TypeError, ValueError,
            OverflowError, RecursionError) as error:
        if isinstance(error, values.LifecycleContractError):
            raise
        raise values.LifecycleContractError(
            'public_native_comparison:'
            'unsupported_retained_terminal_cleanup_shape'
        ) from error


def _validated_terminal_settlement_order(
        checkpoint_wait_report, retained_comparison, expected_order):
    """Validate one issued I.2 terminal path after its live sources expire."""

    cleanup = (retained_comparison._cleanup_parent
               if type(retained_comparison)
               is TerminalSettlementLiveComparison else None)
    review = (cleanup._review_parent
              if type(cleanup) is TerminalCleanupLiveComparison else None)
    _require_issued_terminal_cleanup(cleanup, review)
    _require_issued_terminal_settlement(retained_comparison, cleanup)
    cleanup_report = _validated_terminal_cleanup_order(
        checkpoint_wait_report, cleanup, expected_order)
    report = retained_comparison.report.to_plain()
    try:
        _require(type(report) is dict and set(report) == {
            'schema', 'scope', 'arrival_order', 'review_outcome',
            'closure_operation', 'process_group_absent',
            'resource_release_proven', 'owner_rotation_observed',
            'source_terminal_claim_permitted',
            'production_observation_sha256', 'terminal_cleanup_sha256',
            'graph_mapping', 'model_state', 'input_sha256',
            *_SERIAL_FALSE_FIELDS,
        } and report['schema'] == (
            'orch-dork/production-graph-terminal-settlement-path/v1')
            and report['scope'] == (
                'source_bound_terminal_settlement_reconstruction')
            and report['arrival_order'] == list(expected_order)
            and report['review_outcome']
                == cleanup_report['review_outcome']
            and report['closure_operation'] == (
                'final_qualification'
                if report['review_outcome'] == 'accepted'
                else 'failure_closure')
            and report['process_group_absent'] is True
            and report['resource_release_proven'] is True
            and report['owner_rotation_observed'] is True
            and report['source_terminal_claim_permitted'] is False
            and report['terminal_cleanup_sha256']
                == cleanup.report.digest()
            and re.fullmatch(
                r'[0-9a-f]{64}',
                report['production_observation_sha256']) is not None
            and report['input_sha256'] == values.canonical_digest({
                'terminal_cleanup_sha256':
                    report['terminal_cleanup_sha256'],
                'production_observation_sha256':
                    report['production_observation_sha256'],
            })
            and all(report[field] is False
                    for field in _SERIAL_FALSE_FIELDS),
                 'retained_terminal_settlement_shape')
        choices, states, transitions, steps, model_state = (
            _terminal_settlement_model_bridge(
                cleanup_report['model_state'], report['review_outcome']))
        expected_mapping = {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'production_boundary': {
                'kind': 'observed_terminal_settlement_and_owner_rotation',
                'source_state_id': states[0],
                'target_state_id': states[-1],
                'model_bridge_state_ids': states,
                'model_bridge_transition_ids': transitions,
                'model_bridge_steps': steps,
            },
            'gap': {
                'status': 'TERMINAL_PATH',
                'observed_boundary_count': (
                    cleanup_report['graph_mapping']['gap'][
                        'observed_boundary_count'] + len(choices)),
                'next_uncovered_choices': [],
                'production_graph_complete': False,
            },
        }
        facts = model_state.to_plain()
        _require(_same(report['graph_mapping'], expected_mapping)
                 and _same(report['model_state'], facts)
                 and facts['stage'] == 'terminal'
                 and model.legal_directive(model_state).to_plain()[
                     'kind'] == 'terminal_closure',
                 'retained_terminal_settlement_mapping')
        return report
    except (KeyError, IndexError, TypeError, ValueError,
            OverflowError, RecursionError) as error:
        if isinstance(error, values.LifecycleContractError):
            raise
        raise values.LifecycleContractError(
            'public_native_comparison:'
            'unsupported_retained_terminal_settlement_shape'
        ) from error


def _source_binding(sources):
    _require(type(sources) is dict and bool(sources), 'evidence_sources')
    hashes = {}
    for path, source in sorted(sources.items()):
        _require(type(path) is str and path and not path.startswith('/')
                 and '\\' not in path
                 and all(part not in ('', '.', '..') for part in path.split('/')),
                 'evidence_source_path')
        _require(type(source) is str, 'evidence_source_text')
        hashes[path] = hashlib.sha256(source.encode('utf-8')).hexdigest()
    _require(all(path in hashes for path in SOURCE_PATHS),
             'evidence_source_dependency')
    return ({path: hashes[path] for path in SOURCE_PATHS},
            values.canonical_digest(hashes))


def _mapping_ids(report):
    graph = report['graph_mapping']
    boundary = graph['production_boundary']
    states = boundary.get('model_bridge_state_ids')
    transitions = boundary.get('model_bridge_transition_ids')
    steps = boundary.get('model_bridge_steps')
    if graph.get('schema') == 'orch-dork/production-graph-prefix/v2':
        _require(set(boundary) == {
            'kind', 'source_state_id', 'target_state_id',
            'model_bridge_state_ids', 'model_bridge_transition_ids',
            'model_bridge_steps',
        } and boundary['kind'] ==
            'completed_first_spawn_to_next_authorized_spawn'
            and type(report.get('model_choices')) is list,
            'evidence_mapping_bridge_shape')

        state = model.initial_state(graph['graph_case'])
        reconstructed_states = [explorer.state_identity(state)]
        reconstructed_transitions = []
        reconstructed_steps = []
        for choice in report['model_choices']:
            _require(type(choice) is dict,
                     'evidence_mapping_bridge_choice')
            events = [
                event for event in model.outgoing_stimuli(state).to_plain()
                if _same(explorer.abstract_event(event), choice)
            ]
            _require(len(events) == 1,
                     'evidence_mapping_bridge_choice')
            event = events[0]
            reduction = model.reduce(state, event).to_plain()
            successor_state = rv.freeze(reduction['successor'])
            target_state_id = explorer.state_identity(successor_state)
            directive = model.legal_directive(successor_state).to_plain()
            _require(_same(reduction['directive'], directive),
                     'evidence_mapping_bridge_directive')
            transition_id = explorer.edge_identity(
                reconstructed_states[-1], event, target_state_id)
            reconstructed_transitions.append(transition_id)
            reconstructed_steps.append({
                'source_state_id': reconstructed_states[-1],
                'choice': explorer.abstract_event(event),
                'transition_id': transition_id,
                'target_state_id': target_state_id,
                'directive': directive,
            })
            reconstructed_states.append(target_state_id)
            state = successor_state

        _require(_same(state.to_plain(), report.get('model_state')),
                 'evidence_mapping_bridge_target')
        source_indexes = [
            index for index, state_id in enumerate(reconstructed_states)
            if state_id == boundary['source_state_id']
        ]
        _require(len(source_indexes) == 1,
                 'evidence_mapping_bridge_source')
        source_index = source_indexes[0]
        expected_states = reconstructed_states[source_index:]
        expected_transitions = reconstructed_transitions[source_index:]
        expected_steps = reconstructed_steps[source_index:]
        _require(_same(states, expected_states)
                 and _same(transitions, expected_transitions)
                 and _same(steps, expected_steps),
                 'evidence_mapping_bridge_reconstruction')
    if states is None:
        _require(steps is None, 'evidence_mapping_steps_without_bridge')
        states = [boundary['source_state_id'], boundary['target_state_id']]
    if transitions is None:
        transitions = [boundary['transition_id']]
    _require(type(states) is list and len(states) >= 2
             and type(transitions) is list and bool(transitions)
             and len(transitions) == len(states) - 1
             and states[0] == boundary['source_state_id']
             and states[-1] == boundary['target_state_id'],
             'evidence_mapping_ids')
    if steps is not None:
        _require(type(steps) is list and len(steps) == len(transitions),
                 'evidence_mapping_steps')
        for index, step in enumerate(steps):
            _require(type(step) is dict and set(step) == {
                'source_state_id', 'choice', 'transition_id',
                'target_state_id', 'directive',
            }
                     and step['source_state_id'] == states[index]
                     and step['target_state_id'] == states[index + 1]
                     and step['transition_id'] == transitions[index]
                     and type(step['choice']) is dict
                     and type(step['directive']) is dict,
                     'evidence_mapping_step_continuity')
    return states, transitions


def _replay_reconciliation_choices(state, choices):
    """Replay one declared finite-model segment and return canonical steps."""

    _require(type(choices) is list and bool(choices),
             'reconciliation_choices')
    current = state
    states = [explorer.state_identity(current)]
    steps = []
    for choice in choices:
        _require(type(choice) is dict,
                 'reconciliation_choice_shape')
        events = [
            event for event in model.outgoing_stimuli(current).to_plain()
            if _same(explorer.abstract_event(event), choice)
        ]
        _require(len(events) == 1, 'reconciliation_choice')
        event = events[0]
        reduction = model.reduce(current, event).to_plain()
        successor = rv.freeze(reduction['successor'])
        target_id = explorer.state_identity(successor)
        directive = model.legal_directive(successor).to_plain()
        _require(_same(reduction['directive'], directive),
                 'reconciliation_directive')
        step = {
            'source_state_id': states[-1],
            'choice': explorer.abstract_event(event),
            'transition_id': explorer.edge_identity(
                states[-1], event, target_id),
            'target_state_id': target_id,
            'directive': directive,
        }
        steps.append(step)
        states.append(target_id)
        current = successor
    return current, states, steps


def _finite_readiness_interleavings():
    """Return both exact readiness orders that converge at generation three."""

    paths = (
        ('spec_first', [
            {'target': 'shared'}, {'target': 'spec'},
            {'target': 'standards'},
        ]),
        ('standards_first', [
            {'target': 'shared'}, {'target': 'standards'},
            {'target': 'spec'},
        ]),
    )
    rows = []
    targets = []
    for label, choices in paths:
        final, state_ids, steps = _replay_reconciliation_choices(
            model.initial_state(explorer.GRAPH_CASE), choices)
        facts = final.to_plain()
        _require(facts.get('generation') == 3
                 and facts.get('phase') == 'host_readiness',
                 'reconciliation_readiness_target')
        material = {
            'label': label,
            'choices': choices,
            'state_ids': state_ids,
            'transition_ids': [
                step['transition_id'] for step in steps],
            'steps': steps,
            'target_state_id': state_ids[-1],
        }
        rows.append(dict(
            material, path_sha256=values.canonical_digest(material)))
        targets.append(state_ids[-1])
    _require(len(set(targets)) == 1,
             'reconciliation_readiness_convergence')
    return rows


def _validate_reconciliation_segment(boundary, states, steps):
    """Require one mapping boundary to equal its independently replayed edge."""

    bridge_fields = {
        'kind', 'source_state_id', 'target_state_id',
        'model_bridge_state_ids', 'model_bridge_transition_ids',
        'model_bridge_steps',
    }
    direct_fields = {
        'kind', 'choice', 'source_state_id', 'transition_id',
        'target_state_id',
    }
    _require(type(boundary) is dict and bool(steps),
             'reconciliation_boundary_shape')
    if set(boundary) == bridge_fields:
        _require(
            _same(boundary['model_bridge_state_ids'], states)
            and _same(boundary['model_bridge_transition_ids'], [
                step['transition_id'] for step in steps])
            and _same(boundary['model_bridge_steps'], steps),
            'reconciliation_bridge',
        )
    else:
        _require(set(boundary) == direct_fields and len(steps) == 1,
                 'reconciliation_boundary_shape')
        step = steps[0]
        _require(_same(boundary['choice'], step['choice']),
                 'reconciliation_choice')
        _require(boundary['transition_id'] == step['transition_id'],
                 'reconciliation_transition_id')
    _require(boundary['source_state_id'] == states[0],
             'reconciliation_source_state')
    _require(boundary['target_state_id'] == states[-1],
             'reconciliation_target_state')


def _production_path_parents():
    """Project the immutable parent policy in its explicit topological order."""

    parents = _PRODUCTION_PATH_PARENTS.to_plain()
    order = _PRODUCTION_PATH_ORDER.to_plain()
    _require(type(parents) is dict and type(order) is list
             and len(order) == len(set(order)) == len(parents)
             and set(order) == set(parents),
             'reconciliation_fixed_parent_policy')
    projected = {}
    for name in order:
        parent = parents[name]
        _require(parent is None or parent in projected,
                 'reconciliation_fixed_parent_order')
        projected[name] = parent
    return projected


def _normalized_reconciliation_aliases(
        input_aliases, mapping_names, input_sha256s):
    _require(type(input_aliases) in (list, tuple),
             'reconciliation_aliases')
    normalized = []
    seen_mappings = set()
    seen_inputs = set()
    for row in input_aliases:
        _require(type(row) is dict and set(row) == {
            'mapping_name', 'inputs'}, 'reconciliation_alias_shape')
        mapping_name = row['mapping_name']
        inputs = row['inputs']
        _require(type(mapping_name) is str
                 and mapping_name in mapping_names
                 and mapping_name not in seen_mappings,
                 'reconciliation_alias_mapping')
        _require(type(inputs) is list and len(inputs) >= 2
                 and all(type(item) is str and item for item in inputs)
                 and len(set(inputs)) == len(inputs)
                 and not seen_inputs.intersection(inputs),
                 'reconciliation_alias_inputs')
        _require(type(input_sha256s) is dict,
                 'reconciliation_alias_input_tree')
        resolved_inputs = []
        for path in inputs:
            value = input_sha256s
            for part in path.split('.'):
                _require(type(value) is dict and part in value,
                         'reconciliation_alias_input_path')
                value = value[part]
            _require(type(value) is str
                     and re.fullmatch(r'[0-9a-f]{64}', value) is not None,
                     'reconciliation_alias_input_digest')
            resolved_inputs.append({
                'path': path,
                'sha256': value,
            })
        seen_mappings.add(mapping_name)
        seen_inputs.update(inputs)
        normalized.append({
            'mapping_name': mapping_name,
            'inputs': resolved_inputs,
        })
    return normalized


def _normalized_declared_segment_replays(
        declarations, path_by_name, parents, canonical_mapping_order):
    """Bind an explicit same-parent segment prefix and its first divergence."""

    _require(type(declarations) in (list, tuple),
             'reconciliation_segment_replays')
    order = {
        name: index for index, name in enumerate(canonical_mapping_order)
    }
    normalized = []
    replay_bindings = {}
    owner_keys = set()
    for declaration in declarations:
        _require(type(declaration) is dict and set(declaration) == {
            'owner_mapping', 'replay_mapping', 'parent_mapping',
            'segment_offset', 'transition_count',
        }, 'reconciliation_segment_replay_shape')
        owner_name = declaration['owner_mapping']
        replay_name = declaration['replay_mapping']
        parent_name = declaration['parent_mapping']
        offset = declaration['segment_offset']
        count = declaration['transition_count']
        _require(
            all(type(name) is str and name in path_by_name
                for name in (owner_name, replay_name, parent_name))
            and len({owner_name, replay_name, parent_name}) == 3
            and parents.get(owner_name) == parent_name
            and parents.get(replay_name) == parent_name
            and order[parent_name] < order[owner_name] < order[replay_name]
            and type(offset) is int and offset == 0
            and type(count) is int and count > 0,
            'reconciliation_segment_replay_identity',
        )
        owner_path = path_by_name[owner_name]
        replay_path = path_by_name[replay_name]
        owner_segment = owner_path['mapping_segment']
        replay_segment = replay_path['mapping_segment']
        owner_start = owner_segment['step_offset'] + offset
        replay_start = replay_segment['step_offset'] + offset
        owner_end = owner_start + count
        replay_end = replay_start + count
        _require(
            offset + count < owner_segment['step_count']
            and offset + count < replay_segment['step_count']
            and owner_start == replay_start,
            'reconciliation_segment_replay_range',
        )
        owner_steps = owner_path['steps'][owner_start:owner_end]
        replay_steps = replay_path['steps'][replay_start:replay_end]
        owner_states = owner_path['state_ids'][owner_start:owner_end + 1]
        replay_states = replay_path['state_ids'][
            replay_start:replay_end + 1]
        owner_next = owner_path['steps'][owner_end]
        replay_next = replay_path['steps'][replay_end]
        _require(
            len(owner_steps) == count
            and _same(owner_steps, replay_steps)
            and _same(owner_states, replay_states)
            and owner_next['source_state_id']
                == replay_next['source_state_id'] == owner_states[-1]
            and owner_next['transition_id'] != replay_next['transition_id'],
            'reconciliation_segment_replay_divergence',
        )
        material = {
            **declaration,
            'owner_path_sha256': owner_path['path_sha256'],
            'replay_path_sha256': replay_path['path_sha256'],
            'owner_step_offset': owner_start,
            'replay_step_offset': replay_start,
            'state_ids': owner_states,
            'shared_steps': owner_steps,
            'immediate_divergence': {
                'owner_step': owner_next,
                'replay_step': replay_next,
            },
        }
        declaration_sha256 = values.canonical_digest(material)
        normalized.append(dict(
            material, declaration_sha256=declaration_sha256))
        for index, step in enumerate(owner_steps):
            owner_key = (owner_name, owner_start + index)
            replay_key = (replay_name, replay_start + index)
            _require(replay_key not in replay_bindings,
                     'reconciliation_segment_replay_overlap')
            owner_keys.add(owner_key)
            replay_bindings[replay_key] = {
                'owner_mapping': owner_name,
                'owner_step_index': owner_start + index,
                'transition_id': step['transition_id'],
                'declaration_sha256': declaration_sha256,
            }
    _require(not owner_keys.intersection(replay_bindings),
             'reconciliation_segment_replay_owner')
    return normalized, replay_bindings


def _reconcile_mapping_paths(
        mappings, parents, *, input_aliases, input_sha256s=None,
        evidence_binding=None, declared_segment_replays=(),
        canonical_mapping_order=None):
    """Close the observed path tree against the unchanged finite model.

    Every mapping is replayed from its declared parent target. Repeated edges
    are retained as explicit same-position prefix occurrences rather than
    silently deduplicated. This closes only the production/model derivation;
    outer campaign, execution, release and qualification facts stay false.
    """

    _require(type(mappings) is list and bool(mappings),
             'reconciliation_mappings')
    _require(type(parents) is dict and bool(parents),
             'reconciliation_parents')
    names = []
    for row in mappings:
        _require(type(row) is dict and set(row) == {
            'name', 'comparison', 'comparison_sha256'},
            'reconciliation_mapping_shape')
        _require(type(row['name']) is str and row['name'],
                 'reconciliation_mapping_name')
        _require(type(row['comparison']) is dict
                 and row['comparison_sha256']
                 == values.canonical_digest(row['comparison']),
                 'reconciliation_mapping_digest')
        names.append(row['name'])
    _require(len(names) == len(set(names)),
             'reconciliation_mapping_names')
    _require(names == list(parents),
             'reconciliation_parent_order')
    _require(set(parents) == set(names)
             and sum(parent is None for parent in parents.values()) == 1
             and all(parent is None or parent in parents
                     for parent in parents.values()),
             'reconciliation_parent_shape')
    if canonical_mapping_order is None:
        canonical_order = list(names)
    else:
        _require(type(canonical_mapping_order) in (list, tuple)
                 and all(type(name) is str
                         for name in canonical_mapping_order)
                 and len(canonical_mapping_order)
                    == len(set(canonical_mapping_order)) == len(names)
                 and set(canonical_mapping_order) == set(names),
                 'reconciliation_canonical_mapping_order')
        canonical_order = list(canonical_mapping_order)
    canonical_rank = {
        name: index for index, name in enumerate(canonical_order)
    }
    _require(all(
        parent is None or canonical_rank[parent] < canonical_rank[name]
        for name, parent in parents.items()
    ), 'reconciliation_canonical_parent_order')
    aliases = _normalized_reconciliation_aliases(
        input_aliases, set(names), input_sha256s)
    if evidence_binding is None:
        normalized_binding = {
            'evidence_sha256': None,
            'source_inventory_sha256': None,
            'input_sha256s_sha256': None,
        }
    else:
        _require(type(evidence_binding) is dict
                 and set(evidence_binding) == {
                     'evidence_sha256', 'source_inventory_sha256',
                     'input_sha256s_sha256'}
                 and all(type(value) is str
                         and re.fullmatch(r'[0-9a-f]{64}', value) is not None
                         for value in evidence_binding.values()),
                 'reconciliation_evidence_binding')
        normalized_binding = dict(evidence_binding)

    initial = model.initial_state(explorer.GRAPH_CASE)
    initial_id = explorer.state_identity(initial)
    readiness_interleavings = _finite_readiness_interleavings()
    path_rows = []
    path_by_name = {}
    state_by_name = {}
    edge_records = {}
    edge_occurrences = {}
    state_occurrences = {}

    for row in mappings:
        name = row['name']
        parent = parents[name]
        if parent is None:
            state = initial
            inherited_states = [initial_id]
            inherited_steps = []
        else:
            _require(parent in path_by_name,
                     'reconciliation_parent_unavailable')
            state = state_by_name[parent]
            inherited_states = list(path_by_name[parent]['state_ids'])
            inherited_steps = deepcopy(path_by_name[parent]['steps'])

        report = row['comparison']
        graph = report.get('graph_mapping')
        _require(type(graph) is dict
                 and graph.get('graph_case') == explorer.GRAPH_CASE
                 and graph.get('graph_owner') == explorer.OWNER
                 and type(graph.get('gap')) is dict,
                 'reconciliation_graph_scope')
        boundary = graph.get('production_boundary')
        _require(type(boundary) is dict,
                 'reconciliation_boundary_shape')
        bridge_steps = (boundary.get('model_bridge_steps')
                        if type(boundary) is dict else None)
        if parent is None and type(report.get('model_choices')) is list:
            state, root_states, root_steps = (
                _replay_reconciliation_choices(
                    initial, report['model_choices']))
            source_indexes = [
                index for index, state_id in enumerate(root_states)
                if state_id == boundary.get('source_state_id')
            ]
            _require(len(source_indexes) == 1,
                     'reconciliation_source_state')
            segment_offset = source_indexes[0]
            segment_states = root_states[segment_offset:]
            segment_steps = root_steps[segment_offset:]
            _validate_reconciliation_segment(
                boundary, segment_states, segment_steps)
            full_states = root_states
            full_steps = root_steps
        else:
            if bridge_steps is not None:
                _require(type(bridge_steps) is list and bool(bridge_steps)
                         and all(type(step) is dict
                                 for step in bridge_steps),
                         'reconciliation_boundary_shape')
                choices = [step.get('choice') for step in bridge_steps]
            else:
                choices = [boundary.get('choice')]
            state, segment_states, segment_steps = (
                _replay_reconciliation_choices(state, choices))
            _validate_reconciliation_segment(
                boundary, segment_states, segment_steps)
            segment_offset = len(inherited_steps)
            full_states = inherited_states + segment_states[1:]
            full_steps = inherited_steps + segment_steps

        _require(_same(report.get('model_state'), state.to_plain()),
                 'reconciliation_model_state')
        expected_frontier = [
            explorer.abstract_event(event) for event in
            model.outgoing_stimuli(state).to_plain()
        ]
        _require(_same(graph['gap'].get('next_uncovered_choices'),
                       expected_frontier),
                 'reconciliation_frontier')
        transition_ids = [step['transition_id'] for step in full_steps]
        _require(len(transition_ids) == len(set(transition_ids)),
                 'reconciliation_duplicate_edge')
        _require(len(full_states) == len(set(full_states)),
                 'reconciliation_duplicate_state')
        path_material = {
            'mapping_name': name,
            'parent_mapping': parent,
            'state_ids': full_states,
            'transition_ids': transition_ids,
            'steps': full_steps,
            'mapping_segment': {
                'step_offset': segment_offset,
                'step_count': len(segment_steps),
            },
            'frontier': {
                'status': graph['gap'].get('status'),
                'next_uncovered_choices': expected_frontier,
                'directive': model.legal_directive(state).to_plain(),
            },
        }
        path_sha256 = values.canonical_digest(path_material)
        path_row = dict(path_material, path_sha256=path_sha256)
        path_rows.append(path_row)
        path_by_name[name] = path_row
        state_by_name[name] = state

        for index, state_id in enumerate(full_states):
            state_occurrences.setdefault(state_id, []).append({
                'mapping_name': name,
                'path_sha256': path_sha256,
                'state_index': index,
            })
        for index, step in enumerate(full_steps):
            transition_id = step['transition_id']
            record = {
                'source_state_id': step['source_state_id'],
                'choice': step['choice'],
                'target_state_id': step['target_state_id'],
                'directive': step['directive'],
            }
            previous = edge_records.get(transition_id)
            _require(previous is None or _same(previous, record),
                     'reconciliation_edge_conflict')
            edge_records[transition_id] = record
            in_mapping_segment = (
                segment_offset <= index
                < segment_offset + len(segment_steps))
            edge_occurrences.setdefault(transition_id, []).append({
                'mapping_name': name,
                'path_sha256': path_sha256,
                'step_index': index,
                'origin': (
                    'mapping_segment' if in_mapping_segment else
                    'model_prefix' if parent is None else
                    'inherited'),
            })

    normalized_segment_replays, replay_bindings = (
        _normalized_declared_segment_replays(
            declared_segment_replays, path_by_name, parents,
            canonical_order)
    )
    used_replay_bindings = set()
    edge_index = []
    for transition_id, record in edge_records.items():
        occurrences = edge_occurrences[transition_id]
        reused = len(occurrences) > 1
        origins = [
            occurrence for occurrence in occurrences
            if occurrence['origin'] != 'inherited'
        ]
        _require(not reused or len({
            occurrence['step_index'] for occurrence in occurrences
        }) == 1, 'reconciliation_unexplained_duplicate_edge')
        declared_replays = []
        declared_owner_keys = set()
        for occurrence in origins:
            key = (occurrence['mapping_name'], occurrence['step_index'])
            binding = replay_bindings.get(key)
            if binding is None:
                continue
            owner_occurrences = [
                candidate for candidate in occurrences
                if candidate['mapping_name'] == binding['owner_mapping']
                and candidate['step_index'] == binding['owner_step_index']
            ]
            _require(
                occurrence['origin'] == 'mapping_segment'
                and binding['transition_id'] == transition_id
                and len(owner_occurrences) == 1
                and owner_occurrences[0]['origin'] == 'mapping_segment',
                'reconciliation_segment_replay_binding',
            )
            occurrence['origin'] = 'declared_replayed_prefix'
            declared_replays.append({
                'mapping_name': occurrence['mapping_name'],
                'declaration_sha256': binding['declaration_sha256'],
            })
            declared_owner_keys.add((
                binding['owner_mapping'], binding['owner_step_index']))
            used_replay_bindings.add(key)
        _require(len(declared_owner_keys) <= 1,
                 'reconciliation_segment_replay_owner')
        origins = [
            occurrence for occurrence in occurrences
            if occurrence['origin'] not in {
                'inherited', 'declared_replayed_prefix'}
        ]
        converged_replay = False
        if len(origins) > 1:
            _require(all(
                occurrence['origin'] == 'mapping_segment'
                for occurrence in origins
            ), 'reconciliation_unexplained_duplicate_edge')
            histories = []
            for occurrence in origins:
                path = path_by_name[occurrence['mapping_name']]
                index = occurrence['step_index']
                _require(path['state_ids'][index]
                         == record['source_state_id'],
                         'reconciliation_unexplained_duplicate_edge')
                histories.append(tuple(path['transition_ids'][:index]))
            _require(len(histories) == len(set(histories)),
                     'reconciliation_unexplained_duplicate_edge')
            if declared_owner_keys:
                declared_owner_key = next(iter(declared_owner_keys))
                owners = [
                    occurrence for occurrence in origins
                    if (occurrence['mapping_name'],
                        occurrence['step_index']) == declared_owner_key
                ]
                _require(len(owners) == 1,
                         'reconciliation_segment_replay_owner')
                owner = owners[0]
            else:
                owner = min(origins, key=lambda occurrence: (
                    occurrence['mapping_name'], occurrence['step_index'],
                    occurrence['path_sha256']))
            for occurrence in origins:
                if occurrence is not owner:
                    occurrence['origin'] = 'converged_replay'
            origins = [owner]
            converged_replay = True
        _require(len(origins) == 1,
                 'reconciliation_unexplained_duplicate_edge')
        edge_index.append({
            'transition_id': transition_id,
            **record,
            'occurrences': occurrences,
            'owner_mapping': origins[0]['mapping_name'],
            'owner_origin': origins[0]['origin'],
            'reused_across_paths': reused,
            'shared_prefix': any(
                occurrence['origin'] == 'inherited'
                for occurrence in occurrences),
            'declared_segment_replay': bool(declared_replays),
            'declared_replays': declared_replays,
            'declared_owner_mapping': (
                next(iter(declared_owner_keys))[0]
                if declared_owner_keys else None),
            'converged_replay': converged_replay,
        })
    _require(used_replay_bindings == set(replay_bindings),
             'reconciliation_segment_replay_unused')
    state_index = [{
        'state_id': state_id,
        'occurrences': occurrences,
    } for state_id, occurrences in state_occurrences.items()]
    production_readiness_interleavings = [
        interleaving['label'] for interleaving in readiness_interleavings
        if any(
            path['transition_ids'][:len(
                interleaving['transition_ids'])]
            == interleaving['transition_ids']
            for path in path_rows
        )
    ]
    _require(bool(production_readiness_interleavings),
             'reconciliation_production_readiness')
    production_state_ids = set(state_occurrences)
    production_transition_ids = set(edge_records)
    readiness_state_ids = {
        state_id for row in readiness_interleavings
        for state_id in row['state_ids']
    }
    readiness_transition_ids = {
        transition_id for row in readiness_interleavings
        for transition_id in row['transition_ids']
    }
    counts = {
        'mappings': len(mappings),
        'paths': len(path_rows),
        'production_states': len(state_index),
        'production_transitions': len(edge_index),
        'readiness_interleavings': len(readiness_interleavings),
        'readiness_states': len(readiness_state_ids),
        'readiness_transitions': len(readiness_transition_ids),
        'reconciled_states': len(
            production_state_ids | readiness_state_ids),
        'reconciled_transitions': len(
            production_transition_ids | readiness_transition_ids),
        'shared_prefix_transitions': sum(
            row['shared_prefix'] for row in edge_index),
        'declared_segment_replay_transitions': sum(
            row['declared_segment_replay'] for row in edge_index),
        'converged_replay_transitions': sum(
            row['converged_replay'] for row in edge_index),
        'reused_transitions': sum(
            row['reused_across_paths'] for row in edge_index),
    }
    core = {
        'schema': RECONCILIATION_SCHEMA,
        'status': 'CLOSED',
        'obligation': {
            'id': 'derivation:reachable_states_and_interleavings',
            'status': 'CLOSED',
            'scope': 'production_paths_and_readiness_interleavings',
        },
        'graph_case': explorer.GRAPH_CASE,
        'graph_owner': explorer.OWNER,
        'initial_state_id': initial_id,
        'canonical_mapping_order': canonical_order,
        'mapping_paths': path_rows,
        'finite_readiness_interleavings': readiness_interleavings,
        'production_readiness_interleavings':
            production_readiness_interleavings,
        'edge_index': edge_index,
        'state_index': state_index,
        'mapping_inputs': [{
            'mapping_name': row['name'],
            'comparison_sha256': row['comparison_sha256'],
        } for row in mappings],
        'declared_segment_replays': normalized_segment_replays,
        'input_aliases': aliases,
        'source_evidence': normalized_binding,
        'counts': counts,
        'unexplained': {
            'states': [],
            'transitions': [],
            'paths': [],
        },
        'gaps': [],
        'production_path_reconciliation_complete': True,
        'model_graph_complete': False,
        'production_graph_complete': False,
        'retained_owner_authentication': False,
        'chronology_attested': False,
        'capture_authenticated': False,
        'host_execution_custody': False,
        'controller_continuation_authorized': False,
        'execution_attested': False,
        'complete_campaign': False,
        'release_authorized': False,
        'qualification_authorized': False,
    }
    return rv.freeze(dict(
        core, reconciliation_sha256=values.canonical_digest(core)))


def validate_path_reconciliation(
        reconciliation, mappings, parents, *, input_aliases,
        input_sha256s=None, declared_segment_replays=(),
        canonical_mapping_order=None):
    """Rebuild generic path evidence from caller-declared topology policy."""

    _require(
        type(reconciliation) is rv.FrozenValue
        and reconciliation == _reconcile_mapping_paths(
            mappings, parents, input_aliases=input_aliases,
            input_sha256s=input_sha256s,
            declared_segment_replays=declared_segment_replays,
            canonical_mapping_order=canonical_mapping_order),
        'reconciliation_readback',
    )


def _reconciliation_evidence_plain(evidence):
    """Validate the still-incomplete v11 prefix used by reconciliation."""

    _require(type(evidence) is rv.FrozenValue,
             'reconciliation_evidence_immutable')
    plain = evidence.to_plain()
    _require(type(plain) is dict
             and plain.get('schema') == PREFIX_EVIDENCE_SCHEMA,
             'reconciliation_evidence_schema')
    _require(
        set(plain) == {
            'schema', 'status', 'source_hashes',
            'source_inventory_sha256', 'input_sha256s', 'mappings',
            'reconstructed_reference', 'gaps',
            'production_graph_complete',
            'retained_owner_authentication', 'chronology_attested',
            'capture_authenticated', 'host_execution_custody',
            'controller_continuation_authorized', 'execution_attested',
            'complete_campaign', 'release_authorized',
            'qualification_authorized',
        }
        and plain.get('status')
        == 'UNATTESTED_PREFIX_RECONSTRUCTIONS_INCOMPLETE'
        and plain.get('gaps') == [{
            'obligation':
                'derivation:reachable_states_and_interleavings',
            'status': 'PENDING',
        }]
        and all(plain.get(field) is False for field in (
            'production_graph_complete',
            'retained_owner_authentication', 'chronology_attested',
            'capture_authenticated', 'host_execution_custody',
            'controller_continuation_authorized', 'execution_attested',
            'complete_campaign', 'release_authorized',
            'qualification_authorized',
        )),
        'reconciliation_evidence_scope',
    )
    return plain


def _reconcile_validated_evidence(evidence):
    """Reconcile one outer v11 value after exact source/input validation."""
    plain = _reconciliation_evidence_plain(evidence)
    return _reconcile_mapping_paths(
        plain.get('mappings'), _production_path_parents(),
        input_aliases=_PRODUCTION_INPUT_ALIASES.to_plain(),
        input_sha256s=plain.get('input_sha256s'),
        declared_segment_replays=(
            _PRODUCTION_DECLARED_SEGMENT_REPLAYS.to_plain()),
        canonical_mapping_order=_PRODUCTION_PATH_ORDER.to_plain(),
        evidence_binding={
            'evidence_sha256': evidence.digest(),
            'source_inventory_sha256':
                plain.get('source_inventory_sha256'),
            'input_sha256s_sha256': values.canonical_digest(
                plain.get('input_sha256s')),
        })


def reconcile_evidence(evidence, sources, observations):
    """Return the nested reconciliation after rebuilding the public v12."""

    validate_evidence(evidence, sources, observations)
    return rv.freeze(evidence.to_plain()['path_reconciliation'])


def validate_evidence_reconciliation(
        reconciliation, evidence, sources, observations):
    """Independently rebuild v12 and compare its nested reconciliation."""

    validate_evidence(evidence, sources, observations)
    expected = rv.freeze(evidence.to_plain()['path_reconciliation'])
    _require(type(reconciliation) is rv.FrozenValue
             and reconciliation == expected,
             'reconciliation_evidence_readback')


def _build_prefix_evidence(sources, observations):
    """Bind thirty-eight native boundaries without retained authority."""

    source_hashes, inventory_sha256 = _source_binding(sources)
    _require(type(observations) is dict and set(observations) == {
        'schema', 'failure_branch', 'success_branch', 'checkpoint_arrivals',
        'final_continuations', 'spec_results', 'standards_results',
        'review_outcomes', 'terminal_cleanup', 'terminal_settlement',
    } and observations['schema'] == OBSERVATIONS_SCHEMA,
             'evidence_observations_shape')
    failure_input = observations['failure_branch']
    success_input = observations['success_branch']
    checkpoint_arrivals_input = observations['checkpoint_arrivals']
    final_continuations_input = observations['final_continuations']
    spec_results_input = observations['spec_results']
    standards_results_input = observations['standards_results']
    review_outcomes_input = observations['review_outcomes']
    terminal_cleanup_input = observations['terminal_cleanup']
    terminal_settlement_input = observations['terminal_settlement']
    _require(type(failure_input) is dict and set(failure_input) == {
        'first_spawn', 'failed_second_spawn',
        'completed_compensation_close',
    }, 'evidence_failure_branch')
    _require(type(success_input) is dict and set(success_input) == {
        'first_spawn', 'completed_second_spawn',
        'partial_spec_acknowledgement',
        'successful_standards_acknowledgement',
        'completed_spec_continuation', 'completed_standards_continuation',
    }, 'evidence_success_branch')
    _require(type(checkpoint_arrivals_input) is dict
             and set(checkpoint_arrivals_input)
             == {'spec_first', 'standards_first'},
             'evidence_checkpoint_arrivals')
    _require(type(final_continuations_input) is dict
             and set(final_continuations_input)
             == {'spec_first', 'standards_first'},
             'evidence_final_continuations')
    _require(type(spec_results_input) is dict
             and set(spec_results_input)
             == {'spec_first', 'standards_first'},
             'evidence_spec_results')
    _require(type(standards_results_input) is dict
             and set(standards_results_input)
             == {'spec_first', 'standards_first'},
             'evidence_standards_results')
    _require(type(review_outcomes_input) is dict
             and set(review_outcomes_input)
             == {'spec_first', 'standards_first'}
             and all(type(review_outcomes_input[label]) is dict
                     and set(review_outcomes_input[label]) == {
                         'accepted', 'rejected', 'evidence_required'}
                     for label in ('spec_first', 'standards_first')),
             'evidence_review_outcomes')
    _require(type(terminal_cleanup_input) is dict
             and set(terminal_cleanup_input) == {
                 'completed', 'known_failures', 'unknown'}
             and type(terminal_cleanup_input['completed']) is dict
             and set(terminal_cleanup_input['completed']) == {
                 'spec_first', 'standards_first'}
             and all(type(
                         terminal_cleanup_input['completed'][label]) is dict
                     and set(terminal_cleanup_input['completed'][label]) == {
                         'accepted', 'rejected'}
                     for label in ('spec_first', 'standards_first'))
             and type(terminal_cleanup_input['known_failures']) is dict
             and set(terminal_cleanup_input['known_failures']) == {
                 'failed', 'cancelled', 'timed_out'},
             'evidence_terminal_cleanup')
    _require(type(terminal_settlement_input) is dict
             and set(terminal_settlement_input) == {
                 'accepted', 'rejected'}
             and all(type(terminal_settlement_input[outcome])
                     is TerminalSettlementLiveComparison
                     for outcome in ('accepted', 'rejected')),
             'evidence_terminal_settlement')
    acknowledgement_input = success_input['partial_spec_acknowledgement']
    _require(type(acknowledgement_input) is dict
             and set(acknowledgement_input) == {
                 'raw_rollout_bytes', 'observer_read', 'advance_report',
             }
             and type(acknowledgement_input['raw_rollout_bytes']) is bytes,
             'evidence_spec_acknowledgement')
    standards_acknowledgement_input = success_input[
        'successful_standards_acknowledgement'
    ]
    _require(type(standards_acknowledgement_input) is dict
             and set(standards_acknowledgement_input) == {
                 'raw_rollout_bytes', 'observer_reads', 'advance_report',
                 'action_source',
             }
             and type(standards_acknowledgement_input[
                 'raw_rollout_bytes']) is bytes,
             'evidence_standards_acknowledgement')
    spec_continuation_input = success_input['completed_spec_continuation']
    _require(type(spec_continuation_input) is dict
             and set(spec_continuation_input) == {
                 'action', 'raw_response', 'pre_hook_report',
                 'post_hook_report', 'advance_report',
             }, 'evidence_spec_continuation')
    standards_continuation_input = success_input[
        'completed_standards_continuation'
    ]
    _require(type(standards_continuation_input) is dict
             and set(standards_continuation_input) == {
                 'action', 'raw_response', 'pre_hook_report',
                 'post_hook_report', 'advance_report',
             }, 'evidence_standards_continuation')
    failure = rv.freeze(failure_input).to_plain()
    success = rv.freeze({
        'first_spawn': success_input['first_spawn'],
        'completed_second_spawn': success_input['completed_second_spawn'],
    }).to_plain()
    acknowledgement = {
        'raw_rollout_bytes': acknowledgement_input['raw_rollout_bytes'],
        'observer_read': rv.freeze(
            acknowledgement_input['observer_read']).to_plain(),
        'advance_report': rv.freeze(
            acknowledgement_input['advance_report']).to_plain(),
    }
    standards_acknowledgement = {
        'raw_rollout_bytes': standards_acknowledgement_input[
            'raw_rollout_bytes'],
        'observer_reads': rv.freeze(
            standards_acknowledgement_input['observer_reads']).to_plain(),
        'advance_report': rv.freeze(
            standards_acknowledgement_input['advance_report']).to_plain(),
        'action_source': rv.freeze(
            standards_acknowledgement_input['action_source']).to_plain(),
    }
    spec_continuation = rv.freeze(spec_continuation_input).to_plain()
    standards_continuation = rv.freeze(
        standards_continuation_input).to_plain()

    first_failure = compare_first_spawn(
        **failure['first_spawn']).to_plain()
    first_success = compare_first_spawn(
        **success['first_spawn']).to_plain()
    _require(_same(first_failure['graph_mapping'],
                   first_success['graph_mapping']),
             'evidence_first_mapping_divergence')
    completed = compare_completed_second_spawn(
        success['first_spawn'], success['completed_second_spawn']).to_plain()
    partial_acknowledgement = compare_first_successful_spec_acknowledgement(
        success['first_spawn'], success['completed_second_spawn'],
        acknowledgement,
    ).to_plain()
    successful_standards_acknowledgement = (
        compare_first_successful_standards_acknowledgement(
            success['first_spawn'], success['completed_second_spawn'],
            acknowledgement, standards_acknowledgement,
        ).to_plain()
    )
    completed_spec_continuation = (
        compare_completed_spec_checkpoint_continuation(
            success['first_spawn'], success['completed_second_spawn'],
            acknowledgement, standards_acknowledgement, spec_continuation,
        ).to_plain()
    )
    completed_standards_continuation = (
        compare_completed_standards_checkpoint_continuation(
            success['first_spawn'], success['completed_second_spawn'],
            acknowledgement, standards_acknowledgement, spec_continuation,
            standards_continuation,
        ).to_plain()
    )
    serial_orders = {
        label: _validated_serial_checkpoint_order(
            completed_standards_continuation,
            checkpoint_arrivals_input[label],
            lanes,
        )
        for label, lanes in (
            ('spec_first', ('spec', 'standards')),
            ('standards_first', ('standards', 'spec')),
        )
    }
    final_orders = {
        label: _validated_final_continuation_order(
            completed_standards_continuation,
            checkpoint_arrivals_input[label],
            final_continuations_input[label],
            lanes,
        )
        for label, lanes in (
            ('spec_first', ('spec', 'standards')),
            ('standards_first', ('standards', 'spec')),
        )
    }
    spec_orders = {
        label: _validated_spec_result_order(
            completed_standards_continuation,
            checkpoint_arrivals_input[label],
            final_continuations_input[label],
            spec_results_input[label],
            lanes,
        )
        for label, lanes in (
            ('spec_first', ('spec', 'standards')),
            ('standards_first', ('standards', 'spec')),
        )
    }
    standards_orders = {
        label: _validated_standards_result_order(
            completed_standards_continuation,
            checkpoint_arrivals_input[label],
            final_continuations_input[label],
            spec_results_input[label],
            standards_results_input[label],
            lanes,
        )
        for label, lanes in (
            ('spec_first', ('spec', 'standards')),
            ('standards_first', ('standards', 'spec')),
        )
    }
    review_orders = {
        label: {
            outcome: _validated_semantic_review_outcome_order(
                completed_standards_continuation,
                review_outcomes_input[label][outcome], lanes)
            for outcome in ('accepted', 'rejected', 'evidence_required')
        }
        for label, lanes in (
            ('spec_first', ('spec', 'standards')),
            ('standards_first', ('standards', 'spec')),
        )
    }
    terminal_orders = {
        'completed': {
            label: {
                outcome: _validated_terminal_cleanup_order(
                    completed_standards_continuation,
                    terminal_cleanup_input['completed'][label][outcome],
                    lanes)
                for outcome in ('accepted', 'rejected')
            }
            for label, lanes in (
                ('spec_first', ('spec', 'standards')),
                ('standards_first', ('standards', 'spec')),
            )
        },
        'known_failures': {
            outcome: _validated_terminal_cleanup_order(
                completed_standards_continuation,
                terminal_cleanup_input['known_failures'][outcome],
                ('spec', 'standards'))
            for outcome in ('failed', 'cancelled', 'timed_out')
        },
        'unknown': _validated_terminal_cleanup_order(
            completed_standards_continuation,
            terminal_cleanup_input['unknown'],
            ('spec', 'standards')),
    }
    terminal_settlement_orders = {
        'accepted': _validated_terminal_settlement_order(
            completed_standards_continuation,
            terminal_settlement_input['accepted'],
            ('spec', 'standards')),
        'rejected': _validated_terminal_settlement_order(
            completed_standards_continuation,
            terminal_settlement_input['rejected'],
            ('standards', 'spec')),
    }
    ordered_live_mappings = []
    for label, lanes in (
            ('spec_first', ('spec', 'standards')),
            ('standards_first', ('standards', 'spec'))):
        serial_report = serial_orders[label]
        final_report = final_orders[label]
        spec_report = spec_orders[label]
        standards_report = standards_orders[label]
        review_reports = review_orders[label]
        _require(serial_report['arrival_order'] == list(lanes)
                 and len(serial_report['comparisons']) == 3
                 and final_report['arrival_order'] == list(lanes)
                 and len(final_report['comparisons']) == 2
                 and spec_report['arrival_order'] == list(lanes)
                 and len(spec_report['comparisons']) == 1
                 and standards_report['arrival_order'] == list(lanes)
                 and len(standards_report['comparisons']) == 2
                 and all(serial_report[field] is False
                         and final_report[field] is False
                         and spec_report[field] is False
                         and standards_report[field] is False
                         for field in _SERIAL_FALSE_FIELDS),
                 'evidence_live_order_scope')
        _require(all(
            report['arrival_order'] == list(lanes)
            and report['production_outcome'] == outcome
            and all(report[field] is False
                    for field in _SERIAL_FALSE_FIELDS)
            for outcome, report in review_reports.items()),
            'evidence_review_order_scope')
        serial_names = (
            label + '_checkpoint_' + lanes[0],
            label + '_checkpoint_' + lanes[1],
            label + '_progress_admission',
        )
        final_names = (
            label + '_final_continue_spec',
            label + '_final_continue_standards',
        )
        ordered_live_mappings.extend(zip(
            serial_names, serial_report['comparisons']))
        ordered_live_mappings.extend(zip(
            final_names, final_report['comparisons']))
        ordered_live_mappings.append((
            label + '_spec_result', spec_report['comparisons'][0]))
        ordered_live_mappings.extend((
            (label + '_standards_result',
             standards_report['comparisons'][0]),
            (label + '_result_aggregation',
             standards_report['comparisons'][1]),
        ))
        ordered_live_mappings.extend(
            (label + '_semantic_review_' + outcome,
             review_reports[outcome])
            for outcome in ('accepted', 'rejected', 'evidence_required')
        )
    completed_terminal_reports = terminal_orders['completed']
    _require(all(
        report['arrival_order'] == list(lanes)
        and report['review_outcome'] == outcome
        and report['production_cleanup_outcomes']
            == ['completed', 'completed']
        and report['model_cleanup_outcomes'] == ['accepted', 'accepted']
        and all(report[field] is False for field in _SERIAL_FALSE_FIELDS)
        for label, lanes in (
            ('spec_first', ('spec', 'standards')),
            ('standards_first', ('standards', 'spec')),
        )
        for outcome, report in completed_terminal_reports[label].items()
    ), 'evidence_terminal_cleanup_completed_scope')
    known_failure_reports = terminal_orders['known_failures']
    _require(all(
        report['arrival_order'] == ['spec', 'standards']
        and report['review_outcome'] == 'accepted'
        and report['production_cleanup_outcomes'] == [outcome]
        and report['model_cleanup_outcomes'] == ['failed']
        and all(report[field] is False for field in _SERIAL_FALSE_FIELDS)
        for outcome, report in known_failure_reports.items()
    ) and all(_same(report['graph_mapping'],
                    known_failure_reports['failed']['graph_mapping'])
              and _same(report['model_state'],
                        known_failure_reports['failed']['model_state'])
              for report in known_failure_reports.values()),
             'evidence_terminal_cleanup_known_failure_scope')
    unknown_terminal_report = terminal_orders['unknown']
    _require(unknown_terminal_report['arrival_order']
                 == ['spec', 'standards']
             and unknown_terminal_report['review_outcome'] == 'accepted'
             and unknown_terminal_report['production_cleanup_outcomes']
                 == ['unknown']
             and unknown_terminal_report['model_cleanup_outcomes']
                 == ['unknown']
             and all(unknown_terminal_report[field] is False
                     for field in _SERIAL_FALSE_FIELDS),
             'evidence_terminal_cleanup_unknown_scope')
    ordered_live_mappings.extend(
        (label + '_terminal_cleanup_' + outcome + '_complete',
         completed_terminal_reports[label][outcome])
        for label in ('spec_first', 'standards_first')
        for outcome in ('accepted', 'rejected')
    )
    ordered_live_mappings.extend((
        ('terminal_cleanup_known_failure',
         known_failure_reports['failed']),
        ('terminal_cleanup_unknown', unknown_terminal_report),
    ))
    ordered_live_mappings.extend(
        ('terminal_settlement_' + outcome,
         terminal_settlement_orders[outcome])
        for outcome in ('accepted', 'rejected')
    )
    failed = compare_failed_second_spawn(
        failure['first_spawn'], failure['failed_second_spawn']).to_plain()
    closed = compare_completed_compensation_close(
        failure['first_spawn'], failure['failed_second_spawn'],
        failure['completed_compensation_close']).to_plain()
    reports = (
        ('first_spawn', first_failure),
        ('completed_second_spawn', completed),
        ('partial_spec_acknowledgement', partial_acknowledgement),
        ('successful_standards_acknowledgement',
         successful_standards_acknowledgement),
        ('completed_spec_continuation', completed_spec_continuation),
        ('completed_standards_continuation',
         completed_standards_continuation),
        *ordered_live_mappings,
        ('failed_second_spawn', failed),
        ('completed_compensation_close', closed),
    )
    scope_reports = (
        ('failure_first_spawn', first_failure),
        ('success_first_spawn', first_success),
        *reports[1:],
    )
    for _name, report in scope_reports:
        graph = report['graph_mapping']
        _require(graph['graph_case'] == explorer.GRAPH_CASE
                 and graph['graph_owner'] == explorer.OWNER
                 and graph['gap']['production_graph_complete'] is False
                 and graph['gap'].get(
                     'same_controller_continuation_authorized', False
                 ) is False
                 and report.get('retained_owner_authentication', False)
                 is False
                 and report.get('chronology_attested', False) is False
                 and report['capture_authenticated'] is False
                 and report['host_execution_custody'] is False
                 and report['controller_continuation_authorized'] is False
                 and report['execution_attested'] is False
                 and report['complete_campaign'] is False
                 and report['release_authorized'] is False
                 and report['qualification_authorized'] is False,
                 'evidence_mapping_scope')
    first_target = first_failure['graph_mapping'][
        'production_boundary']['target_state_id']
    _require(all(report['graph_mapping']['production_boundary'][
        'source_state_id'] == first_target for report in (completed, failed)),
        'evidence_second_boundary_continuity')
    _require(closed['graph_mapping']['production_boundary']['source_state_id']
             == failed['graph_mapping']['production_boundary'][
                 'target_state_id'],
             'evidence_close_boundary_continuity')
    _require(partial_acknowledgement['graph_mapping'][
        'production_boundary']['source_state_id']
        == completed['graph_mapping']['production_boundary']['target_state_id'],
        'evidence_ack_boundary_continuity')
    _require(successful_standards_acknowledgement['graph_mapping'][
        'production_boundary']['source_state_id']
        == partial_acknowledgement['graph_mapping'][
            'production_boundary']['target_state_id'],
        'evidence_standards_ack_boundary_continuity')
    _require(completed_spec_continuation['graph_mapping'][
        'production_boundary']['source_state_id']
        == successful_standards_acknowledgement['graph_mapping'][
            'production_boundary']['target_state_id'],
        'evidence_spec_continuation_boundary_continuity')
    _require(completed_standards_continuation['graph_mapping'][
        'production_boundary']['source_state_id']
        == completed_spec_continuation['graph_mapping'][
            'production_boundary']['target_state_id'],
        'evidence_standards_continuation_boundary_continuity')
    checkpoint_wait_target = completed_standards_continuation[
        'graph_mapping']['production_boundary']['target_state_id']
    for label in ('spec_first', 'standards_first'):
        comparisons = serial_orders[label]['comparisons']
        final_comparisons = final_orders[label]['comparisons']
        spec_comparisons = spec_orders[label]['comparisons']
        standards_comparisons = standards_orders[label]['comparisons']
        review_comparisons = review_orders[label]
        _require(comparisons[0]['graph_mapping']['production_boundary'][
            'source_state_id'] == checkpoint_wait_target
            and all(
                current['graph_mapping']['production_boundary'][
                    'source_state_id']
                == previous['graph_mapping']['production_boundary'][
                    'target_state_id']
                for previous, current in zip(comparisons, comparisons[1:])
            )
            and final_comparisons[0]['graph_mapping'][
                'production_boundary']['source_state_id']
            == comparisons[-1]['graph_mapping'][
                'production_boundary']['target_state_id']
            and final_comparisons[1]['graph_mapping'][
                'production_boundary']['source_state_id']
            == final_comparisons[0]['graph_mapping'][
                'production_boundary']['target_state_id']
            and spec_comparisons[0]['graph_mapping'][
                'production_boundary']['source_state_id']
            == final_comparisons[-1]['graph_mapping'][
                'production_boundary']['target_state_id']
            and standards_comparisons[0]['graph_mapping'][
                'production_boundary']['source_state_id']
            == spec_comparisons[-1]['graph_mapping'][
                'production_boundary']['target_state_id']
            and standards_comparisons[1]['graph_mapping'][
                'production_boundary']['source_state_id']
            == standards_comparisons[0]['graph_mapping'][
                'production_boundary']['target_state_id']
            and all(report['graph_mapping']['production_boundary'][
                        'source_state_id']
                    == standards_comparisons[1]['graph_mapping'][
                        'production_boundary']['target_state_id']
                    for report in review_comparisons.values()),
                 'evidence_live_boundary_continuity')
        _require(all(
            completed_terminal_reports[label][outcome]['graph_mapping'][
                'production_boundary']['source_state_id']
            == review_comparisons[outcome]['graph_mapping'][
                'production_boundary']['target_state_id']
            for outcome in ('accepted', 'rejected')
        ), 'evidence_terminal_cleanup_boundary_continuity')
    accepted_review_target = review_orders['spec_first']['accepted'][
        'graph_mapping']['production_boundary']['target_state_id']
    _require(all(report['graph_mapping']['production_boundary'][
                     'source_state_id'] == accepted_review_target
                 for report in (
                     *known_failure_reports.values(),
                     unknown_terminal_report,
                 )),
             'evidence_terminal_cleanup_stop_continuity')
    _require(
        terminal_settlement_orders['accepted']['graph_mapping'][
            'production_boundary']['source_state_id']
        == completed_terminal_reports['spec_first']['accepted'][
            'graph_mapping']['production_boundary']['target_state_id']
        and terminal_settlement_orders['rejected']['graph_mapping'][
            'production_boundary']['source_state_id']
        == completed_terminal_reports['standards_first']['rejected'][
            'graph_mapping']['production_boundary']['target_state_id'],
        'evidence_terminal_settlement_continuity')

    states, transitions = [], []
    frontiers = {}
    mappings = []
    for name, report in reports:
        report_states, report_transitions = _mapping_ids(report)
        states.extend(report_states)
        transitions.extend(report_transitions)
        frontiers[name] = report['graph_mapping']['gap']
        mappings.append({
            'name': name,
            'comparison': report,
            'comparison_sha256': values.canonical_digest(report),
        })
    input_sha256s = {
        'failure_branch': {
            name: values.canonical_digest(value)
            for name, value in sorted(failure.items())
        },
        'success_branch': {
            'completed_second_spawn': values.canonical_digest(
                success['completed_second_spawn']),
            'first_spawn': values.canonical_digest(success['first_spawn']),
            'partial_spec_acknowledgement': values.canonical_digest(
                _acknowledgement_input_projection(
                    acknowledgement['raw_rollout_bytes'],
                    acknowledgement['observer_read'],
                    acknowledgement['advance_report'],
                )
            ),
            'successful_standards_acknowledgement': values.canonical_digest(
                _complete_acknowledgement_input_projection(
                    standards_acknowledgement['raw_rollout_bytes'],
                    standards_acknowledgement['observer_reads'],
                    standards_acknowledgement['advance_report'],
                    standards_acknowledgement['action_source'],
                )
            ),
            'completed_spec_continuation': values.canonical_digest(
                spec_continuation),
            'completed_standards_continuation': values.canonical_digest(
                standards_continuation),
        },
        'checkpoint_arrivals': {
            label: serial_orders[label]['input_sha256']
            for label in ('spec_first', 'standards_first')
        },
        'final_continuations': {
            label: final_orders[label]['input_sha256']
            for label in ('spec_first', 'standards_first')
        },
        'spec_results': {
            label: spec_orders[label]['input_sha256']
            for label in ('spec_first', 'standards_first')
        },
        'standards_results': {
            label: standards_orders[label]['input_sha256']
            for label in ('spec_first', 'standards_first')
        },
        'review_outcomes': {
            label: {
                outcome: review_orders[label][outcome]['input_sha256']
                for outcome in (
                    'accepted', 'rejected', 'evidence_required')
            }
            for label in ('spec_first', 'standards_first')
        },
        'terminal_cleanup': {
            'completed': {
                label: {
                    outcome: completed_terminal_reports[label][outcome][
                        'input_sha256']
                    for outcome in ('accepted', 'rejected')
                }
                for label in ('spec_first', 'standards_first')
            },
            'known_failures': {
                outcome: known_failure_reports[outcome]['input_sha256']
                for outcome in ('failed', 'cancelled', 'timed_out')
            },
            'unknown': unknown_terminal_report['input_sha256'],
        },
        'terminal_settlement': {
            outcome: terminal_settlement_orders[outcome]['input_sha256']
            for outcome in ('accepted', 'rejected')
        },
    }
    _reconcile_mapping_paths(
        mappings, _production_path_parents(),
        input_aliases=_PRODUCTION_INPUT_ALIASES.to_plain(),
        input_sha256s=input_sha256s,
        declared_segment_replays=(
            _PRODUCTION_DECLARED_SEGMENT_REPLAYS.to_plain()),
        canonical_mapping_order=_PRODUCTION_PATH_ORDER.to_plain())
    return rv.freeze({
        'schema': PREFIX_EVIDENCE_SCHEMA,
        'status': 'UNATTESTED_PREFIX_RECONSTRUCTIONS_INCOMPLETE',
        'source_hashes': source_hashes,
        'source_inventory_sha256': inventory_sha256,
        'input_sha256s': input_sha256s,
        'mappings': mappings,
        'reconstructed_reference': {
            'graph_case': explorer.GRAPH_CASE,
            'graph_owner': explorer.OWNER,
            'state_ids': list(dict.fromkeys(states)),
            'transition_ids': list(dict.fromkeys(transitions)),
            'frontiers': frontiers,
        },
        'gaps': [{
            'obligation':
                'derivation:reachable_states_and_interleavings',
            'status': 'PENDING',
        }],
        'production_graph_complete': False,
        'retained_owner_authentication': False,
        'chronology_attested': False,
        'capture_authenticated': False,
        'host_execution_custody': False,
        'controller_continuation_authorized': False,
        'execution_attested': False,
        'complete_campaign': False,
        'release_authorized': False,
        'qualification_authorized': False,
    })


def build_evidence(sources, observations):
    """Bind the immutable v11 prefix and its closed path reconciliation."""

    prefix = _build_prefix_evidence(sources, observations)
    reconciliation = _reconcile_validated_evidence(prefix)
    return rv.freeze({
        'schema': EVIDENCE_SCHEMA,
        'status': 'UNATTESTED_PREFIX_RECONSTRUCTIONS_INCOMPLETE',
        'prefix_evidence': prefix.to_plain(),
        'prefix_evidence_sha256': prefix.digest(),
        'path_reconciliation': reconciliation.to_plain(),
        'path_reconciliation_sha256': reconciliation.digest(),
        'gaps': [{
            'obligation':
                'derivation:reachable_states_and_interleavings',
            'status': 'CLOSED',
        }],
        'production_path_reconciliation_complete': True,
        'model_graph_complete': False,
        'production_graph_complete': False,
        'retained_owner_authentication': False,
        'chronology_attested': False,
        'capture_authenticated': False,
        'host_execution_custody': False,
        'controller_continuation_authorized': False,
        'execution_attested': False,
        'complete_campaign': False,
        'release_authorized': False,
        'qualification_authorized': False,
    })


def validate_evidence(evidence, sources, observations):
    """Rebuild every comparison from original sources and observations."""

    _require(type(evidence) is rv.FrozenValue
             and evidence == build_evidence(sources, observations),
             'evidence_readback')
