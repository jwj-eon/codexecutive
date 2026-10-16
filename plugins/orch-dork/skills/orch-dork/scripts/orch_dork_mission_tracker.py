"""Exact tracker proposals bound to both canonical settlement and a Verified run.

The Root host holds the durable store guard through every recheck and the
existing intake proposal/confirmation. A retained Root artifact binds the
proposal to one named mission and its immutable freeze and settlement. The
original intake remains the only writer and requires explicit confirmation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Mapping

import orch_dork_evidence_core as evidence
import orch_dork_governed_run_watcher as watcher
import orch_dork_mission_authority as authority
import orch_dork_mission_publication as publication
from orch_dork_run_store import StoreError
import orch_dork_work_intake as intake

BINDING_SCHEMA = 'orch-dork/mission-tracker-binding/v1'
PROPOSAL_SCHEMA = 'orch-dork/mission-tracker-proposal/v1'
CONFIRM_SCHEMA = 'orch-dork/mission-tracker-confirm/v1'
RECONCILE_SCHEMA = 'orch-dork/mission-tracker-reconcile/v1'
_BINDING_FIELDS = {'schema', 'mission_id', 'run_id', 'ticket_id', 'target_path',
    'requesting_task_id', 'repository', 'project_root', 'frozen_mission_ref',
    'settlement_observation_ref', 'intake_proposal_sha256'}
_SHA = re.compile(r'[0-9a-f]{64}\Z')


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _report(schema, **values):
    return watcher.sealed({'schema': schema, 'provider_free': True, **values}, 'tracker_sha256')


def _refused(schema, error):
    return _report(schema, status='REFUSED', reason='mission_tracker:binding_refused',
                   message=str(error), mutation_performed=False)


def _common_directory(repository):
    """Observe the actual Git common directory; linked worktrees share this owner."""
    path = Path(repository).resolve(strict=True)
    system_path = publication._system_path()
    _require(system_path, 'trusted Git search path is unavailable')
    executable = shutil.which('git', path=system_path)
    _require(executable, 'trusted Git executable is unavailable')
    result = subprocess.run([executable, 'rev-parse', '--path-format=absolute', '--git-common-dir'],
                            cwd=path, env=publication._git_environment(),
                            capture_output=True, timeout=5, check=True)
    _require(len(result.stdout) <= 4096 and len(result.stderr) <= 4096,
             'repository identity output is oversized')
    common = Path(result.stdout.decode().strip()).resolve(strict=True)
    _require(common.is_dir(), 'repository common directory is unavailable')
    return common


def _enforce_source_drift(state, mission):
    """Refuse when ordered source observations have invalidated the mission.

    With no ordered source observations (``state.get("source") is None``) the
    pool check inside ``read_verified_settlement`` still governs today's
    behavior, so this gate is a no-op. With ordered observations the gate
    refuses a propose/confirm if:

    * the ticket has been tombstoned (the tombstone record outlives any
      later return to the pool);
    * the current pool revision no longer matches the mission's frozen
      revision; or
    * the current pool entry is no longer ready, for example because a
      dependency reopened. The authority records that as
      ``readiness_lost``; the gate surfaces it as
      ``"mission ticket lost readiness in the current source observation"``
      so the refusal reason is distinct from a revision change.
    """
    if state.get("source") is None:
        return
    frozen = mission["freeze"]
    ticket_id = frozen["ticket_id"]
    frozen_revision = frozen["revision_sha256"]
    _require(ticket_id not in (state.get("tombstones") or {}),
             'mission ticket is tombstoned by source observation')
    pool = (state.get("pool") or {}).get("tickets") or {}
    current = pool.get(ticket_id)
    _require(current is not None and current["revision_sha256"] == frozen_revision,
             'mission ticket no longer matches the current source revision')
    _require(current is not None and current.get("ready", True),
             'mission ticket lost readiness in the current source observation')


def _bound_context(tower, repository, *, mission_id, run_id, ticket_id,
                   target_path, requesting_task_id, records):
    record, value = intake.read_verified_run(records, run_id, requesting_task_id)
    common = _common_directory(repository)
    _require(_common_directory(record['project_root']) == common,
             'tracker repository differs from the Verified run')
    _require(value['target']['path'] == target_path and ticket_id in value['selected_tickets'],
             'tracker target or ticket differs from the Verified intake')
    state, mission = authority.MissionAuthority(tower, common).read_verified_settlement(
        mission_id, run_id=run_id, ticket_id=ticket_id, root_task_id=requesting_task_id)
    _enforce_source_drift(state, mission)
    return record, value, state, mission


def _binding(record, state, mission, target_path, proposal_sha):
    frozen = mission['freeze']
    return {'schema': BINDING_SCHEMA, 'mission_id': frozen['mission_id'],
        'run_id': frozen['run_id'], 'ticket_id': frozen['ticket_id'],
        'target_path': target_path, 'requesting_task_id': record['requesting_thread_id'],
        'repository': state['repository'], 'project_root': record['project_root'],
        'frozen_mission_ref': mission['frozen_mission_ref'],
        'settlement_observation_ref': mission['settlement_observation_ref'],
        'intake_proposal_sha256': proposal_sha}


def _guard(tower):
    _require(tower is not None and tower.store.durable and
             callable(getattr(tower.store, 'authorization_guard', None)),
             'tracker requires the durable authorization guard')
    return tower.store.authorization_guard()


_ERRORS = (ValueError, OSError, KeyError, TypeError, AttributeError,
           subprocess.SubprocessError, watcher.WatcherError, StoreError)


def _read_and_validate_binding(tower, arguments, *, requesting_thread_id, op):
    """Read the retained binding artifact and validate its shape against the task.

    Centralises the byte-size bound, the schema and field check, and the
    task binding so propose_tracker, confirm_tracker, and reconcile_tracker
    all enforce the same shape. Returns the binding dict.
    """
    _require(isinstance(arguments, Mapping) and set(arguments) ==
             {'confirm_proposal_sha256', 'proposal_ref'},
             op + ' must name the exact retained proposal digest')
    digest, ref = arguments['confirm_proposal_sha256'], arguments['proposal_ref']
    _require(isinstance(digest, str) and _SHA.fullmatch(digest) and
             isinstance(ref, Mapping) and ref.get('sha256') == digest,
             op + ' must name the exact retained proposal digest')
    raw = tower.artifacts.read(ref)
    _require(len(raw) <= 65536, 'tracker binding is oversized')
    binding = json.loads(raw)
    _require(isinstance(binding, dict) and set(binding) == _BINDING_FIELDS and
             binding['schema'] == BINDING_SCHEMA and
             binding['requesting_task_id'] == requesting_thread_id,
             'tracker proposal does not bind this task')
    return digest, binding


def _classify_consumed_marker(marker, observed_sha, pre_image, updated):
    """Translate the intake's consumed-marker schema into a reconcile status.

    The writer in orch_dork_work_intake writes two shapes:

    * APPLIED uses ``marker["status"] == "APPLIED"``, with the
      sealed report that intake.confirm returned.
    * CLAIMED uses ``marker["state"] == "CLAIMED"``, the unsealed
      reservation written before the file replace.

    Any other shape (missing APPLIED/CLAIMED keys, an unknown status
    string, an empty marker) is treated as DRIFTED so reconcile never
    reports a status the authority did not actually publish.
    """
    if marker is None:
        return 'NOT_APPLIED'
    if marker.get('status') == 'APPLIED':
        return 'APPLIED' if observed_sha == updated else 'DRIFTED'
    if marker.get('state') == 'CLAIMED':
        if observed_sha == updated:
            return 'APPLIED_OBSERVED'
        if observed_sha == pre_image:
            return 'NOT_APPLIED'
        return 'DRIFTED'
    return 'DRIFTED'


def propose_tracker(arguments, *, requesting_thread_id, records, repository, tower):
    """Retain a mission-bound exact proposal; do not change the tracker."""
    try:
        _require(isinstance(arguments, Mapping) and set(arguments) ==
                 {'run_id', 'mission_id', 'target_path', 'ticket_id', 'edits'},
                 'tracker proposal fields')
        _require(all(isinstance(arguments[key], str) and arguments[key]
                     for key in ('run_id', 'mission_id', 'target_path', 'ticket_id')),
                 'tracker proposal identity')
        _require(isinstance(arguments['edits'], list) and arguments['edits'] and
                 all(isinstance(edit, Mapping) and edit.get('ticket_id') == arguments['ticket_id']
                     for edit in arguments['edits']), 'tracker edits must name the exact mission ticket')
        with _guard(tower):
            record, value, state, mission = _bound_context(tower, repository,
                **{key: arguments[key] for key in ('mission_id', 'run_id', 'ticket_id', 'target_path')},
                requesting_task_id=requesting_thread_id, records=records)
            proposal = intake.propose({'run_id': arguments['run_id'], 'edits': arguments['edits']},
                                      requesting_thread_id=requesting_thread_id, records=records)
            _require(proposal['status'] == 'APPROVAL_REQUIRED', proposal.get('message', 'intake refused'))
            binding = _binding(record, state, mission, arguments['target_path'], proposal['proposal_sha256'])
            raw = evidence.canonical_bytes(binding)
            digest = hashlib.sha256(raw).hexdigest()
            ref = tower.artifacts.publish(raw, media_type='application/json', provenance={
                'producer_run_id': arguments['run_id'], 'producer_node_id': 'root',
                'task_spec_sha256': digest, 'content_schema': BINDING_SCHEMA,
                'privacy_class': 'local_only', 'custody_receipt_sha256': digest,
                'source_lineage': [mission['frozen_mission_ref'], mission['settlement_observation_ref']],
                'consumer_node_ids': ['mission'], 'retention_state': 'retained_evidence'})
            return _report(PROPOSAL_SCHEMA, status='APPROVAL_REQUIRED', proposal_ref=ref,
                proposal_sha256=ref['sha256'], mission_id=arguments['mission_id'],
                run_id=arguments['run_id'], ticket_id=arguments['ticket_id'],
                file=arguments['target_path'], edits=arguments['edits'], diff=proposal['diff'],
                question='Apply these exact tracker edits? Confirm this proposal digest after agreement.',
                mutation_performed=False)
    except _ERRORS as error:
        return _refused(PROPOSAL_SCHEMA, error)


def confirm_tracker(arguments, *, requesting_thread_id, records, repository, tower):
    """Recheck the retained binding and delegate explicit confirmation once."""
    confirmation_started = False
    applied = None
    try:
        _require(isinstance(arguments, Mapping) and set(arguments) ==
                 {'confirm_proposal_sha256', 'proposal_ref'}, 'tracker confirmation fields')
        digest, ref = arguments['confirm_proposal_sha256'], arguments['proposal_ref']
        _require(isinstance(digest, str) and _SHA.fullmatch(digest) and
                 isinstance(ref, Mapping) and ref.get('sha256') == digest,
                 'confirmation must name the exact retained proposal digest')
        with _guard(tower):
            digest, binding = _read_and_validate_binding(tower, arguments,
                requesting_thread_id=requesting_thread_id,
                op='tracker confirmation')
            record, value, state, mission = _bound_context(tower, repository,
                **{key: binding[key] for key in ('mission_id', 'run_id', 'ticket_id', 'target_path')},
                requesting_task_id=requesting_thread_id, records=records)
            _require(binding == _binding(record, state, mission, binding['target_path'],
                                        binding['intake_proposal_sha256']), 'canonical tracker binding changed')
            provenance = tower.artifacts.record(ref)
            _require(provenance['producer_run_id'] == binding['run_id'] and
                     provenance['producer_node_id'] == 'root' and
                     provenance['content_schema'] == BINDING_SCHEMA and
                     len(provenance['source_lineage']) == 2 and
                     all(parent in provenance['source_lineage'] for parent in
                         (binding['frozen_mission_ref'], binding['settlement_observation_ref'])),
                     'tracker proposal has no original Root custody')
            proposal = intake.read_status_proposal(records, binding['intake_proposal_sha256'], requesting_thread_id)
            _require(proposal['run_id'] == binding['run_id'] and
                     proposal['project_root'] == binding['project_root'] and
                     proposal['target'] == value['target'] and
                     all(edit['ticket_id'] == binding['ticket_id'] for edit in proposal['edits']),
                     'intake proposal differs from the mission-bound edit')
            confirmation_started = True
            applied = intake.confirm({'confirm_proposal_sha256': binding['intake_proposal_sha256']},
                                     requesting_thread_id=requesting_thread_id, records=records)
            if applied['status'] != 'APPLIED':
                return _report(CONFIRM_SCHEMA, status='REFUSED', reason='mission_tracker:confirmation_refused',
                    message=applied.get('message', 'intake refused'),
                    mutation_performed=bool(applied.get('mutation_performed')))
            return _report(CONFIRM_SCHEMA, status='APPLIED', proposal_sha256=digest,
                mission_id=binding['mission_id'], run_id=binding['run_id'], file=applied['file'],
                updated_sha256=applied['updated_sha256'], mutation_performed=True)
    except _ERRORS as error:
        if confirmation_started:
            # Once the writer was entered, an exception cannot establish that
            # nothing changed. Preserve a returned receipt's effect bit; an
            # interrupted writer with no receipt leaves the effect unknown.
            mutation = applied.get('mutation_performed') if isinstance(applied, Mapping) else None
            return _report(CONFIRM_SCHEMA, status='UNKNOWN',
                reason='mission_tracker:confirmation_unconfirmed', message=str(error),
                mutation_performed=mutation if type(mutation) is bool else None)
        return _refused(CONFIRM_SCHEMA, error)


def reconcile_tracker(arguments, *, requesting_thread_id, records, repository, tower):
    """Reconcile the actual tracker projection state; do not authorize another edit.

    Re-reads the retained binding and the bound intake proposal, reads the
    consumed marker through the read-only intake accessor, and observes the
    current target file digest under the same durable guard. The sealed
    report distinguishes APPLIED (marker APPLIED and file at the proposal's
    updated digest), APPLIED_OBSERVED (marker CLAIMED with the file at the
    updated digest, meaning a crash lost the APPLIED marker after the
    replace), NOT_APPLIED (no marker, or CLAIMED with the file at the
    pre-image), or DRIFTED (any other state). Reconciliation never writes
    the file, never writes or consumes a marker, and never authorizes a
    fresh confirmation: a consumed proposal that observed NOT_APPLIED must
    acquire a new proposal before another edit.
    """
    try:
        with _guard(tower):
            digest, binding = _read_and_validate_binding(tower, arguments,
                requesting_thread_id=requesting_thread_id,
                op='reconciliation')
            # Enforce the same repository identity check as propose/confirm
            # so reconcile never produces a sealed report for a foreign
            # repository; the reading path is otherwise read-only.
            common = _common_directory(repository)
            _require(_common_directory(binding['project_root']) == common,
                     'tracker repository differs from the Verified run')
            proposal = intake.read_status_proposal(records, binding['intake_proposal_sha256'],
                                                   requesting_thread_id)
            _require(proposal['run_id'] == binding['run_id'] and
                     proposal['project_root'] == binding['project_root'] and
                     proposal['target']['path'] == binding['target_path'] and
                     all(edit['ticket_id'] == binding['ticket_id'] for edit in proposal['edits']),
                     'intake proposal differs from the mission-bound edit')
            marker = intake.read_consumed_marker(records, binding['intake_proposal_sha256'],
                                                 requesting_thread_id)
            observed_sha = intake.read_target_digest(binding['project_root'], binding['target_path'])
            pre_image = proposal['target']['sha256']
            updated = proposal['updated_sha256']
            status = _classify_consumed_marker(marker, observed_sha, pre_image, updated)
            return _report(RECONCILE_SCHEMA, status=status, proposal_sha256=digest,
                mission_id=binding['mission_id'], run_id=binding['run_id'],
                file=binding['target_path'], observed_sha256=observed_sha,
                pre_image_sha256=pre_image, updated_sha256=updated,
                mutation_performed=False)
    except _ERRORS as error:
        return _refused(RECONCILE_SCHEMA, error)
