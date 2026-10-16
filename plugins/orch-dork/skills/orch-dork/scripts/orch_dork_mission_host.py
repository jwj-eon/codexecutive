"""Trusted-host material binding for the composed Issue225 mission path.

Start binding resolves the existing WorkerPort catalog against canonical
mission history. It is an observation, NEVER permission to create a worker or
proof of route deployment, physical cwd/containment, stop, verification or
landing. The collection/staging join holds durable canonical authorization,
uses the fixed host stager to add exact Git objects, and seals the candidate in
mission history. Historical recovery reads use the original session and staging
journal without requesting a replacement. Worker effects still require the
selected route's actual support and the exact retained receiver operation.

Catalog, protocol, collection reader and stager are trusted host implementations,
not candidate inputs. None of these joins verifies or lands a candidate.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import hashlib
import inspect
import json

from orch_dork_mission_authority import (MissionAuthority, MissionRefusal,
    validate_worker_cleanup, effect_cleanup_contract, is_run_owner, completion_staging_fields,
    validate_completion_cleanup, completion_target_id, FREEZE_SCHEMA_V2)
from orch_dork_evidence_core import legacy_ascii_bytes
import orch_dork_mission_candidate as candidate_staging
import orch_dork_mission_publication as publication
import orch_dork_mission_verification as verification
from orch_dork_worktree_runner import validate_planned_worktree_id, WorktreeRunnerError


class MissionHostRefusal(ValueError):
    """A composed host boundary cannot bind the selected canonical mission."""


@dataclass(frozen=True)
class WorkerCleanupReader:
    """Fixed original WorkerPort reader with trusted catalog and custody enrollment."""
    catalog: object
    state_root: Path

    def read(self, request, *, workspace, baseline, workspace_sha256):
        from orch_dork_worker_port_host.collection import read_terminal_cleanup
        return read_terminal_cleanup(self.catalog, self.state_root, request,
            workspace=workspace, baseline=baseline, workspace_sha256=workspace_sha256)


@dataclass(frozen=True)
class MissionCleanupReaders:
    """Trusted host enrollments; never worker/candidate supplied callbacks."""
    worker_reader: object = None
    stager: object = None
    verifier: object = None
    publisher: object = None


def _fixed_receiver(receiver, record_type, methods, *, label=None):
    if (type(receiver) is not record_type or any(
            inspect.getattr_static(receiver, name) is not inspect.getattr_static(record_type, name)
            for name in methods)):
        raise MissionHostRefusal('fixed trusted host '+(label or record_type.__name__)+' enrollment is required')


def _require_durable_authorization(tower):
    if not tower.store.durable or not callable(getattr(tower.store, 'authorization_guard', None)):
        raise MissionHostRefusal('durable canonical authorization is unavailable')


def _require_root(tower, frozen, requesting_task_id):
    if not is_run_owner(tower, frozen, requesting_task_id):
        raise MissionHostRefusal('requester is not the run-owning root')


def _read_trusted(reader, *args, **kwargs):
    """Translate only a trusted read's refusal; an effect body keeps its error."""
    try:
        return reader(*args, **kwargs)
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        raise MissionHostRefusal('trusted host readback is unavailable: '+str(error)) from error


def _require_worker_call_budgets(call, frozen):
    """Bind the registered finite call to one writer; no monetary usage proof."""
    budgets = call.get('budgets') if isinstance(call, dict) else None
    if (not isinstance(budgets, dict) or
            any(type(budgets.get(field)) is not int or not 0 < budgets[field] <= limit
                for field, limit in (('token_count', frozen['limits']['tokens']),
                                     ('wall_time_ms', frozen['limits']['elapsed_ms']))) or
            any(type(budgets.get(field)) is not int or budgets[field] != count
                for field, count in (('child_count', 0), ('concurrency', 1),
                                     ('generation_count', 1)))):
        raise MissionHostRefusal('registered worker call budgets differ from the mission freeze')


def _canonical_json(value, *, limit=None):
    return legacy_ascii_bytes(value, limit=limit,
        refusal=MissionHostRefusal('host record exceeds the retained staging bound'))


def _publish_root_artifact(tower, frozen, raw, *, media_type, schema, lineage,
                           custody_receipt_sha256=None):
    digest = hashlib.sha256(raw).hexdigest()
    return tower.artifacts.publish(raw, media_type=media_type, provenance={
        'producer_run_id': frozen['run_id'], 'producer_node_id': 'root',
        'task_spec_sha256': digest, 'content_schema': schema,
        'privacy_class': 'local_only',
        'custody_receipt_sha256': (digest if custody_receipt_sha256 is None
                                  else custody_receipt_sha256),
        'source_lineage': lineage, 'consumer_node_ids': ['mission'],
        'retention_state': 'retained_evidence'})


def bind_worker_start(tower, repository, mission_id, *, catalog, protocol,
                      requesting_task_id):
    """Read and resolve exact start identities without dispatch or store writes."""
    state = MissionAuthority(tower, repository).check_creation(mission_id)
    mission = state['missions'][mission_id]
    frozen = mission['freeze']
    _require_root(tower, frozen, requesting_task_id)
    starts = [intent for intent in mission['receiver_intents'].values()
              if intent['request']['operation'] == 'start']
    if len(starts) != 1:
        raise MissionHostRefusal('one retained worker start is required')
    request = starts[0]['request']
    report = protocol.validate_request(request)
    if report['status'] != 'PASS' or report['canonical'] != request:
        raise MissionHostRefusal('retained worker request is invalid')
    refs = request['payload']['refs']
    resolved = _read_trusted(catalog.validate_start_refs, refs, owner=request['owner'])
    _require_worker_call_budgets(resolved.get('worker_call'), frozen)
    workspace = resolved['lane_workspace']
    if refs['lane_workspace']['sha256'] != frozen['workspace_manifest_sha256']:
        raise MissionHostRefusal('workspace registration digest differs from the freeze')
    planned_id = workspace.get('planned_worktree_id')
    try:
        validate_planned_worktree_id(planned_id)
    except WorktreeRunnerError as error:
        raise MissionHostRefusal('workspace registration has no supported planned identity') from error
    run_root = Path(workspace['run_root'])
    planned = run_root / planned_id
    if (not run_root.is_absolute() or not run_root.is_dir() or
            run_root.resolve(strict=True) != run_root or
            str(planned) != frozen['workspace'] or planned.exists() or planned.is_symlink()):
        raise MissionHostRefusal('planned workspace binding is unavailable or colliding')
    reservation = resolved['capacity_reservation']
    runtime, route = resolved['runtime'], resolved['route']
    model = resolved['model_manifest']
    if (refs['model_manifest']['sha256'] != frozen['route']['manifest_sha256'] or
            model['logical_model_id'] != frozen['route']['model'] or
            any(value['model'] != frozen['route']['model'] or
                value['effort'] != frozen['route']['effort'] for value in (runtime, route)) or
            workspace['base_revision'] != frozen['baseline_commit'] or
            resolved['base_revision']['revision'] != frozen['baseline_commit'] or
            reservation['run_id'] != frozen['run_id'] or
            reservation['node_id'] != workspace['lane_id'] or
            frozen['capacity_lane_id'] != reservation['run_id']+':'+reservation['node_id'] or
            any(type(runtime[field]) is not int or runtime[field] > frozen['limits']['output_bytes']
                for field in ('stdout_limit_bytes', 'stderr_limit_bytes'))):
        raise MissionHostRefusal('registered material does not bind the mission freeze')
    return {'schema': 'orch-dork/mission-start-binding/v1', 'status': 'BOUND',
            'mission_id': mission_id, 'generation': state['generation'],
            'event_hash': state['event_hash'], 'request': deepcopy(request),
            'request_ref': deepcopy(starts[0]['request_ref']),
            'workspace': str(planned), 'material_sha256': {
                name: value['sha256'] for name, value in refs.items()},
            'qualification': False, 'creation_authorized': False}


def retain_worker_response(tower, repository, mission_id, raw, *, protocol):
    """Import exact trusted receiver bytes into canonical Root custody.

    This is an observation importer, not dispatch or cessation/containment
    acceptance. The caller obtains bytes from the retained WorkerPort receiver;
    full protocol validation does not turn a fixture into physical evidence.
    Changed current revision does not prevent historical original-key readback.
    Concurrent history changes cause the existing canonical CAS to refuse.
    """
    state = tower.read_mission_authority(repository)
    mission = state['missions'].get(mission_id)
    if mission is None:
        raise MissionHostRefusal('receiver mission claim is unavailable')
    if type(raw) is not bytes or len(raw) > mission['freeze']['limits']['receiver_response_bytes']:
        raise MissionHostRefusal('receiver response bytes exceed the frozen bound')
    try:
        response = json.loads(raw)
        report = protocol.validate_response(response)
        if report['status'] != 'PASS' or protocol.canonical_bytes(response) != raw:
            raise MissionHostRefusal('receiver response is invalid or noncanonical')
        key = response['request']['idempotency_key']
    except (ValueError, TypeError, KeyError) as error:
        raise MissionHostRefusal('receiver response is invalid or noncanonical') from error
    intent = mission['receiver_intents'].get(key)
    if intent is None or intent['request'] != response['request']:
        raise MissionHostRefusal('receiver response does not bind a retained request')
    if 'response_ref' in intent:
        if response != intent['response']:
            raise MissionHostRefusal('different receiver response is already retained')
        return state
    digest = hashlib.sha256(raw).hexdigest()
    frozen = mission['freeze']
    ref = _publish_root_artifact(tower, frozen, raw, media_type='application/json',
        schema=protocol.RESPONSE_SCHEMA,
        lineage=[mission['frozen_mission_ref'], intent['request_ref']])
    return tower.transition_mission(repository, {
        'kind': 'receiver_observation', 'operation_id': 'observe-'+digest[:32],
        'expected_generation': state['generation'], 'expected_seq': state['seq'],
        'expected_prev_hash': state['event_hash'], 'payload': {
            'mission_id': mission_id, 'idempotency_key': key, 'response_ref': ref}})


def retain_collected_diff(tower, repository, mission_id, idempotency_key, *, reader):
    """Bind independently revalidated receiver bytes into exact Root custody.

    reader is the trusted host's bound WorkerPort read_collected_candidate;
    its catalog and state root are fixed by that host. Fixture readers test
    this custody join only. Importing bytes never verifies/lands a candidate,
    creates a worker, settles uncertainty or releases mission/capacity claims.
    """
    state = tower.read_mission_authority(repository)
    mission = state['missions'].get(mission_id)
    if mission is None:
        raise MissionHostRefusal('collected candidate mission is unavailable')
    intent = mission['receiver_intents'].get(idempotency_key)
    if (intent is None or intent['request']['operation'] != 'collect' or
            'response' not in intent or intent['response']['status'] != 'PASS' or
            intent['response']['session_state'] != 'CANDIDATE_READY'):
        raise MissionHostRefusal('retained ready collection is unavailable')
    frozen, request = mission['freeze'], intent['request']
    report = _read_trusted(reader, deepcopy(request), workspace=frozen['workspace'],
                    baseline=frozen['baseline_commit'],
                    workspace_sha256=frozen['workspace_manifest_sha256'])
    if (not isinstance(report, dict) or report.get('status') != 'COLLECTED' or
            report.get('schema') != 'orch-dork/collected-candidate-readback/v1' or
            report.get('qualification') is not False or
            report.get('request_sha256') != request['request_sha256'] or
            report.get('session_handle') != request['session_handle'] or
            report.get('workspace') != frozen['workspace'] or
            report.get('baseline_commit') != frozen['baseline_commit'] or
            report.get('workspace_registration_sha256') != frozen['workspace_manifest_sha256'] or
            report.get('collection') != intent['response']['collection']):
        raise MissionHostRefusal('receiver candidate does not bind the mission')
    diff = report.get('diff')
    artifact = intent['response']['collection'].get('candidate_artifact')
    if (type(diff) is not bytes or len(diff) > frozen['limits']['output_bytes'] or
            not isinstance(artifact, dict) or set(artifact) != {
                'schema','uri','sha256','size_bytes','media_type'}):
        raise MissionHostRefusal('collected diff bytes are unavailable')
    digest = hashlib.sha256(diff).hexdigest()
    if (artifact['schema'] != 'orch-dork/artifact-ref/v1' or
            artifact['uri'] != 'artifact://sha256/'+digest or artifact['sha256'] != digest or
            type(artifact['size_bytes']) is not int or artifact['size_bytes'] != len(diff) or
            artifact['media_type'] != 'text/x-diff'):
        raise MissionHostRefusal('collected diff does not bind its actual artifact')
    header = {key:value for key,value in report.items() if key != 'diff'}
    receipt = _canonical_json(header)
    ref = _publish_root_artifact(tower, frozen, diff, media_type='text/x-diff',
        schema='orch-dork/mission-candidate-diff/v1', lineage=[intent['response_ref']],
        custody_receipt_sha256=hashlib.sha256(receipt).hexdigest())
    return {'schema':'orch-dork/mission-collected-diff/v1','candidate_artifact_ref':ref,
            'collection_response_ref':deepcopy(intent['response_ref']),
            'workspace_manifest_sha256':report['workspace_manifest_sha256'],
            'receiver_event_hash':report['event_hash'], 'qualification':False}


def _staging_request(mission, collection):
    frozen = mission['freeze']
    # Anchor to the original immutable freeze and FIRST collection intent.
    # Diff/policy/baseline/repository are bound by the request below; changing
    # them cannot allocate an alternative operation after an uncertain start.
    identity = _canonical_json({
        'mission_id': frozen['mission_id'],
        'freeze_sha256': mission['frozen_mission_ref']['sha256'],
        'collection_request_sha256': collection['request']['request_sha256']},
        limit=candidate_staging.LIMIT)
    return candidate_staging.StagingRequest(
        operation_id='stage-' + hashlib.sha256(identity).hexdigest(),
        repository=frozen['repository']['path'], baseline=frozen['baseline_commit'],
        diff_sha256=collection['response']['collection']['candidate_artifact']['sha256'],
        policy_sha256=frozen['acceptance_policy_sha256'],
        scope=tuple(frozen['write_scope']))


def _original_staging(stager, request, diff):
    """Reprove the stager's original journal and command bytes without Git."""
    try:
        return stager.read_staged_evidence(request, diff)
    except candidate_staging.StagingBusy as error:
        raise MissionHostRefusal(error.reason) from error
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise MissionHostRefusal('original staging evidence is unavailable or changed') from error


def _candidate_envelope(frozen, collected, staged):
    return {'schema': 'orch-dork/mission-candidate-seal/v1',
            **{name: deepcopy(frozen[name]) for name in (
                'mission_id', 'run_id', 'ticket_id', 'ownership_generation',
                'baseline_commit', 'workspace', 'workspace_manifest_sha256',
                'acceptance_policy_sha256', 'write_scope', 'repository', 'target_ref')},
            'ticket_revision': frozen['revision_sha256'],
            'commit': staged.commit, 'tree': staged.tree,
            'collection_response_ref': collected['collection_response_ref'],
            'candidate_artifact_ref': collected['candidate_artifact_ref']}


def _revalidate_sealed_candidate(tower, mission, collection, request, stager):
    """Read only the seal's original Root refs and the stager's retained proof."""
    envelope = mission['candidate']
    sealed_refs = {name: envelope[name] for name in
                   ('collection_response_ref', 'candidate_artifact_ref')}
    if sealed_refs['collection_response_ref'] != collection['response_ref']:
        raise MissionHostRefusal('sealed candidate has a different original collection')
    retained_diff = _read_trusted(tower.artifacts.read, sealed_refs['candidate_artifact_ref'])
    retained_result, journal_bytes = _original_staging(stager, request, retained_diff)
    if envelope != _candidate_envelope(mission['freeze'], sealed_refs, retained_result):
        raise MissionHostRefusal('sealed candidate differs from original staging')
    lineage = _read_trusted(tower.artifacts.record, mission['candidate_ref'])['source_lineage']
    journals = [ref for ref in lineage if _read_trusted(tower.artifacts.record, ref)['content_schema']
                == 'orch-dork/candidate-staging/v1']
    if len(journals) != 1 or _read_trusted(tower.artifacts.read, journals[0]) != journal_bytes:
        raise MissionHostRefusal('original staging journal custody is unavailable or changed')


def stage_collected_candidate(tower, repository, mission_id, idempotency_key, *,
                              reader, stager, requesting_task_id):
    """Stage Root-custodied collection bytes and append one canonical seal.

    reader and the exact CandidateStager instance are fixed trusted-host
    enrollments, like the catalog/readback seam; neither is worker input.
    No executable or caller-produced result is accepted. The durable store
    guard excludes canonical writers from current Root/revision/full capacity
    validation through staging and seal CAS. The stager remains the owner of
    its bounded Git capture and original journal. This context does not pass
    authorization descriptors to staging children: staging adds only objects,
    never a target/ref effect, and parent loss cannot create a canonical seal.

    Return canonical state. A sealed exact retry reads only Root artifacts and
    the original staging journal, with no reader/stage call or store write.
    Refusal, incomplete evidence and UNKNOWN raise without replacing a staging
    operation/candidate or releasing any mission/capacity claim. Verification,
    worker/route creation and landing remain separate host boundaries.
    """
    _require_durable_authorization(tower)
    _fixed_receiver(stager, candidate_staging.CandidateStager, ('stage', 'read_staged_evidence'), label='stager')
    with tower.store.authorization_guard():
        state = MissionAuthority(tower, repository).check_creation(mission_id)
        mission = state['missions'][mission_id]
        frozen = mission['freeze']
        _require_root(tower, frozen, requesting_task_id)
        if stager.workspace_root != Path(frozen['workspace']):
            raise MissionHostRefusal('stager workspace does not bind the mission freeze')
        collections = [intent for intent in mission['receiver_intents'].values()
                       if intent['request']['operation'] == 'collect']
        if (not collections or collections[0]['request']['idempotency_key'] != idempotency_key or
                collections[0].get('response', {}).get('status') != 'PASS' or
                collections[0]['response']['session_state'] != 'CANDIDATE_READY'):
            raise MissionHostRefusal('original retained ready collection is unavailable')
        collection = collections[0]
        request = _staging_request(mission, collection)
        if 'candidate_ref' in mission:
            _revalidate_sealed_candidate(tower, mission, collection, request, stager)
            return state
        collected = retain_collected_diff(tower, repository, mission_id,
                                         idempotency_key, reader=reader)
        diff = tower.artifacts.read(collected['candidate_artifact_ref'])
        staged = stager.stage(request, diff)
        if type(staged) is not candidate_staging.StagingResult or staged.status != 'STAGED':
            raise MissionHostRefusal('candidate staging remains ' + str(getattr(staged, 'status', 'UNKNOWN'))
                                     + ': ' + str(getattr(staged, 'reason', 'unproved result')))
        original, raw = _original_staging(stager, request, diff)
        if staged != original:
            raise MissionHostRefusal('stage result differs from its original retained journal')
        lineage = [mission['frozen_mission_ref'], collected['collection_response_ref'],
                   collected['candidate_artifact_ref']]
        journal_ref = _publish_root_artifact(tower, frozen, raw,
            media_type='application/json', schema='orch-dork/candidate-staging/v1', lineage=lineage)
        envelope = _candidate_envelope(frozen, collected, original)
        ref = _publish_root_artifact(tower, frozen,
            _canonical_json(envelope, limit=candidate_staging.LIMIT),
            media_type='application/json', schema=envelope['schema'], lineage=[*lineage, journal_ref])
        return tower.transition_mission(repository, {
            'kind': 'candidate_seal', 'operation_id': 'seal-' + request.operation_id,
            'expected_generation': state['generation'], 'expected_seq': state['seq'],
            'expected_prev_hash': state['event_hash'],
            'payload': {'mission_id': mission_id, 'candidate_ref': ref}})


def _completion_staging_request(mission, target, target_ref):
    if mission.get('completion_target') != target or mission.get('completion_target_ref') != target_ref:
        raise MissionHostRefusal('final staging differs from its retained target observation')
    fields = completion_staging_fields(mission)
    return candidate_staging.StagingRequest(**{**fields, 'scope': tuple(fields['scope'])})


def _completion_envelope(mission, target_ref, request, staged):
    return {**deepcopy(mission['candidate']),
        'schema': 'orch-dork/mission-final-candidate-seal/v1',
        'baseline_commit': request.baseline, 'commit': staged.commit, 'tree': staged.tree,
        'original_candidate_ref': mission['candidate_ref'],
        'target_observation_ref': target_ref, 'completion_id': mission['completion']['id']}


def stage_completion_candidate(tower, repository, mission_id, *, stager, publisher,
                               requesting_task_id):
    """Seal the original diff on the observed target under one durable slot.

    The canonical claim survives parent loss and unknown reads/staging. Exact
    recovery rechecks original journals without collecting again or replacing
    the target observation or final candidate. This neither verifies nor lands.
    """
    _require_durable_authorization(tower)
    _fixed_receiver(stager, candidate_staging.CandidateStager, ('stage', 'read_staged_evidence'), label='stager')
    _fixed_receiver(publisher, publication.PublicationReceiver,
                    ('observe_or_read_target', 'observe_target', 'read_target_observation'),
                    label='target reader')
    with tower.store.authorization_guard():
        authority = MissionAuthority(tower, repository)
        state = authority.read()
        mission = state['missions'].get(mission_id)
        if mission is None or mission['freeze']['schema'] != FREEZE_SCHEMA_V2:
            raise MissionHostRefusal('final completion requires fixed batch mission mode')
        state = _read_trusted(authority.check_completion, mission_id)
        mission = state['missions'][mission_id]
        frozen = mission['freeze']
        _require_root(tower, frozen, requesting_task_id)
        if (stager.workspace_root != Path(frozen['workspace']) or
                str(publisher.repository) != frozen['repository']['path'] or
                publisher.target_ref != frozen['target_ref']):
            raise MissionHostRefusal('final receivers do not bind the frozen mission')
        collections = [intent for intent in mission['receiver_intents'].values()
                       if intent['request']['operation'] == 'collect']
        if not collections or 'candidate_ref' not in mission:
            raise MissionHostRefusal('final completion has no original collected candidate')
        original_request = _staging_request(mission, collections[0])
        _revalidate_sealed_candidate(tower, mission, collections[0], original_request, stager)
        target_id = completion_target_id(mission)
        target_args = {'baseline': frozen['baseline_commit'],
                       'interface_contracts': frozen['interface_contracts']}
        target = _read_trusted(publisher.observe_or_read_target, target_id, **target_args)
        if target['status'] != 'PASS':
            raise MissionHostRefusal('completion target remains '+target['status']+': '+target['reason'])
        if 'completion_target_ref' in mission:
            target_ref = mission['completion_target_ref']
            if tower.artifacts.read(target_ref) != _canonical_json(target, limit=65536):
                raise MissionHostRefusal('final target observation custody changed')
        else:
            target_ref = _publish_root_artifact(tower, frozen, _canonical_json(target, limit=65536),
                media_type='application/json', schema=target['schema'],
                lineage=[mission['frozen_mission_ref'], mission['candidate_ref']])
            state = tower.transition_mission(repository, {
                'kind': 'completion_target', 'operation_id': 'retain-' + target_id,
                'expected_generation': state['generation'], 'expected_seq': state['seq'],
                'expected_prev_hash': state['event_hash'],
                'payload': {'mission_id': mission_id, 'target_observation_ref': target_ref}})
            mission = state['missions'][mission_id]
        request = _completion_staging_request(mission, target, target_ref)
        diff_ref = mission['candidate']['candidate_artifact_ref']
        diff = tower.artifacts.read(diff_ref)
        if 'final_candidate_ref' in mission:
            staged, raw = _original_staging(stager, request, diff)
            if mission['final_candidate'] != _completion_envelope(mission, target_ref, request, staged):
                raise MissionHostRefusal('final candidate differs from its original staged result')
            journals = [ref for ref in tower.artifacts.record(mission['final_candidate_ref'])['source_lineage']
                        if tower.artifacts.record(ref)['content_schema'] == 'orch-dork/candidate-staging/v1']
            if len(journals) != 1 or tower.artifacts.read(journals[0]) != raw:
                raise MissionHostRefusal('original final staging custody changed')
            return state
        staged = stager.stage(request, diff)
        if type(staged) is not candidate_staging.StagingResult or staged.status != 'STAGED':
            raise MissionHostRefusal('final staging remains '+str(getattr(staged, 'status', 'UNKNOWN'))
                                     +': '+str(getattr(staged, 'reason', 'unproved result')))
        original, raw = _original_staging(stager, request, diff)
        if staged != original:
            raise MissionHostRefusal('final result differs from its original staging journal')
        lineage = [mission['frozen_mission_ref'], mission['candidate_ref'], target_ref,
                   diff_ref, mission['candidate']['collection_response_ref']]
        journal_ref = _publish_root_artifact(tower, frozen, raw, media_type='application/json',
            schema='orch-dork/candidate-staging/v1', lineage=lineage)
        envelope = _completion_envelope(mission, target_ref, request, original)
        ref = _publish_root_artifact(tower, frozen, _canonical_json(envelope, limit=65536),
            media_type='application/json', schema=envelope['schema'], lineage=[*lineage, journal_ref])
        return tower.transition_mission(repository, {
            'kind': 'completion_seal', 'operation_id': 'seal-' + request.operation_id,
            'expected_generation': state['generation'], 'expected_seq': state['seq'],
            'expected_prev_hash': state['event_hash'],
            'payload': {'mission_id': mission_id, 'candidate_ref': ref}})


@contextmanager
def hold_worker_start(tower, repository, mission_id, *, catalog, protocol,
                      requesting_task_id):
    """Hold canonical exclusion while the trusted host binds one start.

    The store owns the lock; the caller receives its already-held descriptors
    only for the enclosing trusted effect's inheritance. Material binding is
    still an observation: this context supplies no contained-route support,
    worker creation or replacement permission. The effect host must verify
    route support and use the one retained request before any launch. Closing
    the context never releases mission claims or canonical lane capacity.
    """
    _require_durable_authorization(tower)
    with tower.store.authorization_guard() as fds:
        bound=bind_worker_start(tower,repository,mission_id,catalog=catalog,
                                protocol=protocol,requesting_task_id=requesting_task_id)
        yield bound,fds


@contextmanager
def hold_effect_closure(tower, repository, mission_id, *, readers, requesting_task_id):
    """Hold canonical exclusion across original readbacks and closure binding.

    Every reader is read-only. No process, verification, publication, signature
    or release is started here. The caller may retain one settlement intent
    under this guard, then use its exact signed release through canonical Core.
    Root-custodied proof is additional evidence; original verdicts stay intact.
    """
    _require_durable_authorization(tower)
    if type(readers) is not MissionCleanupReaders:
        raise MissionHostRefusal('closed trusted host cleanup enrollment is required')
    with tower.store.authorization_guard():
        state = MissionAuthority(tower, repository).read()
        mission = state['missions'].get(mission_id)
        if mission is None or mission['claim_state'] != 'HELD' or 'settlement_intent' in mission:
            raise MissionHostRefusal('effect closure requires one unsettled held mission')
        frozen = mission['freeze']
        _require_root(tower, frozen, requesting_task_id)
        value = {'schema': 'orch-dork/mission-effect-closure/v1', 'mission_id': mission_id,
                 'ownership_generation': frozen['ownership_generation'],
                 'authority_generation': state['generation'], 'authority_event_hash': state['event_hash'],
                 'worker_request_ref': None, 'worker_cleanup_ref': None,
                 'verification_intent_ref': mission.get('verification_intent_ref'),
                 'verification_cleanup_ref': None,
                 'publication_intent_ref': mission.get('publication_intent_ref'),
                 'publication_cleanup_ref': None}
        lineage = [mission['frozen_mission_ref']]
        if frozen['schema'] == FREEZE_SCHEMA_V2 and 'completion' in mission:
            value.update(schema='orch-dork/mission-effect-closure/v2',
                completion_target_ref=mission.get('completion_target_ref'),
                completion_target_cleanup_ref=None, final_candidate_ref=mission.get('final_candidate_ref'),
                final_staging_cleanup_ref=None)
            _fixed_receiver(readers.publisher, publication.PublicationReceiver, ('read_target_cleanup',))
            proof = _read_trusted(readers.publisher.read_target_cleanup, completion_target_id(mission),
                baseline=frozen['baseline_commit'], interface_contracts=frozen['interface_contracts'])
            try:
                validate_completion_cleanup(proof, mission, 'target')
            except MissionRefusal as error:
                raise MissionHostRefusal(str(error)) from error
            parents = [mission['frozen_mission_ref'], *[mission[name] for name in
                ('candidate_ref', 'completion_target_ref') if name in mission]]
            ref = _publish_root_artifact(tower, frozen, _canonical_json(proof, limit=65536),
                media_type='application/json', schema=proof['schema'], lineage=parents)
            value['completion_target_cleanup_ref'] = ref
            lineage += [*parents, ref]
            if 'completion_target_ref' in mission:
                _fixed_receiver(readers.stager, candidate_staging.CandidateStager, ('read_cleanup',))
                request = _completion_staging_request(mission, mission['completion_target'], mission['completion_target_ref'])
                diff = _read_trusted(tower.artifacts.read, mission['candidate']['candidate_artifact_ref'])
                proof = _read_trusted(readers.stager.read_cleanup, request, diff)
                try:
                    validate_completion_cleanup(proof, mission, 'staging')
                except MissionRefusal as error:
                    raise MissionHostRefusal(str(error)) from error
                parents = [mission['candidate_ref'], mission['completion_target_ref']]
                if 'final_candidate_ref' in mission:
                    parents.append(mission['final_candidate_ref'])
                ref = _publish_root_artifact(tower, frozen, _canonical_json(proof, limit=65536),
                    media_type='application/json', schema=proof['schema'], lineage=parents)
                value['final_staging_cleanup_ref'] = ref
                lineage += [*parents, ref]
        starts = [intent for intent in mission['receiver_intents'].values()
                  if intent['request']['operation'] == 'start']
        if starts:
            terminal = [intent for intent in mission['receiver_intents'].values()
                        if intent['request']['operation'] in ('status', 'cancel', 'collect')]
            if not terminal:
                raise MissionHostRefusal('original worker terminal reader is unavailable')
            _fixed_receiver(readers.worker_reader, WorkerCleanupReader, ('read',))
            intent = terminal[-1]
            proof = _read_trusted(readers.worker_reader.read, deepcopy(intent['request']), workspace=frozen['workspace'],
                baseline=frozen['baseline_commit'], workspace_sha256=frozen['workspace_manifest_sha256'])
            try:
                validate_worker_cleanup(proof, frozen, intent['request'])
            except MissionRefusal as error:
                raise MissionHostRefusal(str(error)) from error
            ref = _publish_root_artifact(tower, frozen, _canonical_json(proof, limit=65536),
                media_type='application/json', schema=proof['schema'], lineage=[intent['request_ref']])
            value.update(worker_request_ref=intent['request_ref'], worker_cleanup_ref=ref)
            lineage += [intent['request_ref'], ref]
        if 'candidate_ref' in mission:
            _fixed_receiver(readers.stager, candidate_staging.CandidateStager, ('read_staged_evidence',))
            collections = [intent for intent in mission['receiver_intents'].values()
                           if intent['request']['operation'] == 'collect']
            if not collections:
                raise MissionHostRefusal('original staging collection is unavailable')
            request = _staging_request(mission, collections[0])
            _revalidate_sealed_candidate(tower, mission, collections[0], request, readers.stager)
            lineage.append(mission['candidate_ref'])
        for effect, receiver, record_type in (
                ('verification', readers.verifier, verification.ProtectedVerifier),
                ('publication', readers.publisher, publication.PublicationReceiver)):
            if effect+'_intent' not in mission:
                continue
            _fixed_receiver(receiver, record_type, ('read_cleanup',))
            contract = effect_cleanup_contract(effect)
            try:
                request = contract.request(mission[effect+'_intent'])
                proof = _read_trusted(receiver.read_cleanup, request)
                original_status = (mission.get(effect+'_observation') or {}).get('status')
                contract.validate(proof, request, original_status=original_status)
            except MissionRefusal as error:
                raise MissionHostRefusal(str(error)) from error
            parents = [mission[effect+'_intent_ref']]
            if effect+'_observation_ref' in mission:
                parents.append(mission[effect+'_observation_ref'])
            ref = _publish_root_artifact(tower, frozen, _canonical_json(proof, limit=65536),
                media_type='application/json', schema=contract.schema, lineage=parents)
            value[effect+'_cleanup_ref'] = ref
            lineage += [*parents, ref]
        ref = _publish_root_artifact(tower, frozen, _canonical_json(value, limit=65536),
            media_type='application/json', schema=value['schema'], lineage=lineage)
        yield {'state': state, 'mission': mission, 'effect_closure_ref': ref}
