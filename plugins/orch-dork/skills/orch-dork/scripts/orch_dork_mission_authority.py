"""Canonical mission history for a host-resolved repository (Issue 225).

This source slice records ordered pool observations and conservative whole-
repository claims in the existing RunEngine. A claim binds an existing capacity
reservation; it does not establish deployed route support, containment or
workspace/check enforcement. Those must be observed before creation effects.
Its repository argument is the trusted host's resolved common Git directory;
this module does not discover Git identity or admit a worker, publication or
tracker edit. Those boundaries require the composed mission host. State is a
reduction of canonical facts, never a second mutable owner database.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import stat

import orch_dork_run_engine as run_engine
import orch_dork_artifact_ledger as artifact_ledger
import orch_dork_mission_publication as publication
import orch_dork_mission_verification as verification
import orch_dork_mission_scope as _mission_scope
from orch_dork_evidence_core import is_canonical_absolute_path, canonical_text, digest


SCHEMA = "orch-dork/mission-authority/v1"
FREEZE_SCHEMA = "orch-dork/mission-freeze/v1"
FREEZE_SCHEMA_V2 = "orch-dork/mission-freeze/v2"
ANCHOR_SCHEMA = "orch-dork/mission-authority-anchor/v1"
_GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
_MAX_REQUEST_BYTES = 16_384
_MAX_HOST_OBSERVATION_BYTES = 65_536
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_TICKET = re.compile(r"[1-9][0-9]{0,6}\Z")
_TRANSITION_FIELDS = frozenset({
    "kind", "operation_id", "expected_generation", "expected_seq",
    "expected_prev_hash", "payload",
})
MISSION_CAPACITY_ROUTE = 'portable_qwen'


class MissionRefusal(ValueError):
    """The canonical mission transition cannot be accepted."""


def _canonical(value):
    return canonical_text(value)


def _sha(value):
    return digest(value)


def is_run_owner(tower, frozen, requesting_task_id):
    """The frozen task and Root model identify one run-owning Root."""
    return (requesting_task_id == frozen['requester']['root_task_id'] and
            tower.root_model == frozen['requester']['root_model'])


def expected_publication_binding(mission, *, authorization_generation):
    """One material request binding for intent and held effect permission."""
    frozen = mission['freeze']
    candidate = _effective_candidate(mission)
    return {
        'mission_id': frozen['mission_id'], 'repository': frozen['repository']['path'],
        'ticket_id': frozen['ticket_id'], 'ticket_revision': frozen['revision_sha256'],
        'ownership_generation': frozen['ownership_generation'], 'target_ref': frozen['target_ref'],
        'expected_old': candidate['baseline_commit'], 'new_commit': candidate['commit'],
        'new_tree': candidate['tree'],
        'verification_evidence_sha256': mission['verification_observation_ref']['sha256'],
        'authorization_generation': authorization_generation,
    }


def _effective_candidate(mission):
    """The preserved original in legacy mode; only the final seal in v2."""
    field = 'final_candidate' if mission['freeze']['schema'] == FREEZE_SCHEMA_V2 else 'candidate'
    if field not in mission:
        raise MissionRefusal('completion has no final sealed candidate')
    return mission[field]


def _effective_candidate_ref(mission):
    _effective_candidate(mission)
    return mission['final_candidate_ref' if mission['freeze']['schema'] == FREEZE_SCHEMA_V2 else 'candidate_ref']


def completion_staging_fields(mission):
    """The one final-stage material binding, shared by host and closure reader."""
    identity = {'frozen_mission_ref': mission['frozen_mission_ref'],
        'original_candidate_ref': mission['candidate_ref'],
        'completion_id': mission['completion']['id'],
        'target_observation_ref': mission['completion_target_ref']}
    frozen = mission['freeze']
    return {'operation_id': 'final-stage-' + _sha(identity),
        'repository': frozen['repository']['path'], 'baseline': mission['completion_target']['commit'],
        'diff_sha256': mission['candidate']['candidate_artifact_ref']['sha256'],
        'policy_sha256': frozen['acceptance_policy_sha256'], 'scope': frozen['write_scope']}


def completion_target_id(mission):
    return 'target-' + _sha({'frozen_mission_ref': mission['frozen_mission_ref'],
        'original_candidate_ref': mission['candidate_ref'], 'completion_id': mission['completion']['id']})


def _require_completion(state, mission):
    if (mission['freeze']['schema'] != FREEZE_SCHEMA_V2 or mission['claim_state'] != 'HELD'
            or 'settlement_intent' in mission or mission.get('completion', {}).get('state') != 'HELD'):
        raise MissionRefusal('completion requires its original held slot')
    holders = [row for row in state['missions'].values()
               if row.get('completion', {}).get('state') == 'HELD']
    if len(holders) != 1 or holders[0] != mission:
        raise MissionRefusal('completion slot ownership is ambiguous')
    if not _matches_current_ready_revision(state, mission['freeze']):
        raise MissionRefusal('completion no longer matches the current ready revision')


def _apply_completion_claim(_tower, state, payload):
    mission = _claimed_mission(state, payload)
    if (mission['freeze']['schema'] != FREEZE_SCHEMA_V2 or mission['claim_state'] != 'HELD'
            or 'settlement_intent' in mission or 'candidate_ref' not in mission):
        raise MissionRefusal('completion claim requires one unfinished fixed batch candidate')
    if not _matches_current_ready_revision(state, mission['freeze']):
        raise MissionRefusal('completion claim no longer matches the current ready revision')
    if ('completion' in mission or any(row.get('completion', {}).get('state') == 'HELD'
                                      for row in state['missions'].values())):
        raise MissionRefusal('completion slot is occupied or already retained')
    if any(row.get('completion', {}).get('id') == payload['completion_id']
           for row in state['missions'].values()):
        raise MissionRefusal('completion identity was already retained')
    mission.update(completion={'id': payload['completion_id'], 'state': 'HELD',
                              'authorization_generation': state['generation'] + 1},
                   status='COMPLETION_HELD')


def _read_completion_target(tower, mission, target_ref):
    frozen = mission['freeze']
    target = _read_mission_json(tower, target_ref, limit=_MAX_HOST_OBSERVATION_BYTES)
    target_schema = 'orch-dork/mission-target-observation/v1'
    _require_shape(target, ('schema', 'operation_id', 'repository', 'repository_identity', 'target_ref',
        'commit', 'tree', 'baseline', 'interface_contracts', 'contract_observations', 'status', 'reason',
        'commands', 'publication_authorized', 'evidence_path'), 'completion target observation')
    if (target['schema'] != target_schema or target['status'] != 'PASS'
            or target['operation_id'] != completion_target_id(mission)
            or target['reason'] != 'target:observed'
            or any(type(target[name]) is not str or not _GIT_OID.fullmatch(target[name])
                   for name in ('commit', 'tree'))
            or target['repository'] != frozen['repository']['path']
            or target['repository_identity'] != [frozen['repository']['device'], frozen['repository']['inode']]
            or target['target_ref'] != frozen['target_ref'] or target['baseline'] != frozen['baseline_commit']
            or target['interface_contracts'] != frozen['interface_contracts']
            or target['publication_authorized'] is not False
            or type(target['commands']) is not list
            or len(target['commands']) != 6 + 3 * len(frozen['interface_contracts'])
            or any(type(row) is not dict or type(row.get('exit_code')) is not int
                   or row['exit_code'] != 0 or row.get('reason') != 'exited'
                   or type(row.get('cleanup')) is not dict
                   or row['cleanup'].get('complete') is not True for row in target['commands'])):
        raise MissionRefusal('final candidate has no exact observed target')
    contracts = target['contract_observations']
    if type(contracts) is not list or len(contracts) != len(frozen['interface_contracts']):
        raise MissionRefusal('completion target has incomplete dependency observations')
    for expected, observed in zip(frozen['interface_contracts'], contracts):
        _require_shape(observed, ('path', 'sha256', 'git_mode', 'blob'), 'target dependency observation')
        if (any(observed[name] != expected[name] for name in ('path', 'sha256'))
                or observed['git_mode'] not in ('100644', '100755')
                or type(observed['blob']) is not str or not _GIT_OID.fullmatch(observed['blob'])):
            raise MissionRefusal('completion target changed its relied-on dependency facts')
    _require_root_custody(tower, target_ref, frozen, target_schema)
    return target


def _apply_completion_target(tower, state, payload):
    mission = _claimed_mission(state, payload)
    _require_completion(state, mission)
    if 'completion_target_ref' in mission:
        raise MissionRefusal('completion target is already retained')
    ref = payload['target_observation_ref']
    target = _read_completion_target(tower, mission, ref)
    if mission['candidate_ref'] not in tower.artifacts.record(ref)['source_lineage']:
        raise MissionRefusal('completion target lineage is unavailable')
    mission.update(completion_target=target, completion_target_ref=ref)


def _apply_completion_seal(tower, state, payload):
    mission = _claimed_mission(state, payload)
    _require_completion(state, mission)
    if 'final_candidate_ref' in mission or mission['freeze']['limits']['retained_candidates'] < 2:
        raise MissionRefusal('final candidate is already retained or its budget is unavailable')
    frozen, original = mission['freeze'], mission['candidate']
    ref = payload['candidate_ref']
    value = _read_mission_json(tower, ref)
    schema = 'orch-dork/mission-final-candidate-seal/v1'
    _require_shape(value, (*original, 'original_candidate_ref', 'target_observation_ref', 'completion_id'),
                   'final candidate seal')
    stable = set(original) - {'schema', 'baseline_commit', 'commit', 'tree'}
    if (value['schema'] != schema or any(value[name] != original[name] for name in stable)
            or value['original_candidate_ref'] != mission['candidate_ref']
            or value['completion_id'] != mission['completion']['id']
            or any(type(value[name]) is not str or not _GIT_OID.fullmatch(value[name])
                   for name in ('baseline_commit', 'commit', 'tree'))):
        raise MissionRefusal('final candidate does not bind its original mission')
    target_ref = value['target_observation_ref']
    target = _read_completion_target(tower, mission, target_ref)
    if (target_ref != mission.get('completion_target_ref') or
            target['commit'] != value['baseline_commit']):
        raise MissionRefusal('final candidate differs from its retained completion target')
    _require_root_custody(tower, ref, frozen, schema)
    parents = (mission['candidate_ref'], target_ref, original['collection_response_ref'],
               original['candidate_artifact_ref'])
    if (any(parent not in tower.artifacts.record(ref)['source_lineage'] for parent in parents)
            or mission['candidate_ref'] not in tower.artifacts.record(target_ref)['source_lineage']):
        raise MissionRefusal('final candidate lineage is unavailable')
    journals = [parent for parent in tower.artifacts.record(ref)['source_lineage']
                if tower.artifacts.record(parent)['content_schema'] == 'orch-dork/candidate-staging/v1']
    if len(journals) != 1:
        raise MissionRefusal('final candidate has no original staging journal')
    _require_root_custody(tower, journals[0], frozen, 'orch-dork/candidate-staging/v1')
    mission.update(final_candidate=value, final_candidate_ref=ref, status='FINAL_CANDIDATE_SEALED')


def _require_shape(value, fields, name):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise MissionRefusal(name + " has an invalid shape")


def _validate_pool_payload(pool):
    if not isinstance(pool["observation_id"], str) or not _ID.fullmatch(
            pool["observation_id"]):
        raise MissionRefusal("invalid observation identity")
    if not isinstance(pool["ledger_sha256"], str) or not _SHA.fullmatch(
            pool["ledger_sha256"]):
        raise MissionRefusal("invalid ledger digest")
    tickets = pool["tickets"]
    if not isinstance(tickets, dict) or len(tickets) > 512:
        raise MissionRefusal("invalid bounded ticket pool")
    for ticket_id, ticket in tickets.items():
        if not isinstance(ticket_id, str) or not _TICKET.fullmatch(ticket_id):
            raise MissionRefusal("invalid ticket identity")
        _require_shape(ticket, ("revision_sha256", "ready"), "ticket")
        if not isinstance(ticket["revision_sha256"], str) or not _SHA.fullmatch(
                ticket["revision_sha256"]):
            raise MissionRefusal("invalid ticket revision")
        if type(ticket["ready"]) is not bool:
            raise MissionRefusal("unknown ticket readiness")


def _validate_transition(value):
    _require_shape(value, _TRANSITION_FIELDS, 'mission transition')
    kind = value['kind']
    if type(kind) is not str or kind not in _TRANSITION_RULES:
        raise MissionRefusal('unsupported mission transition')
    rule = _TRANSITION_RULES[kind]
    if not isinstance(value['operation_id'], str) or not _ID.fullmatch(value['operation_id']):
        raise MissionRefusal('invalid operation identity')
    for field in ('expected_generation', 'expected_seq'):
        if type(value[field]) is not int or value[field] < 0:
            raise MissionRefusal('invalid ' + field)
    if not isinstance(value['expected_prev_hash'], str) or not _SHA.fullmatch(value['expected_prev_hash']):
        raise MissionRefusal('invalid expected previous hash')
    _require_shape(value['payload'], rule.payload_fields, kind.replace('_', ' '))
    for field, pattern in rule.identities:
        identity = value['payload'][field]
        if not isinstance(identity, str) or not pattern.fullmatch(identity):
            raise MissionRefusal('invalid ' + kind.replace('_', ' ') + ' identity')
    if rule.payload_validator is not None:
        rule.payload_validator(value['payload'])
    return deepcopy(value)


def _apply_pool(state, pool):
    identity = pool["observation_id"]
    if state.get("source") is not None:
        raise MissionRefusal("ordered source observations supersede unordered pool snapshots")
    if identity in state["observations"]:
        raise MissionRefusal("pool observation was already consumed")
    state["observations"][identity] = _sha(pool)
    state["pool"] = pool


_SOURCE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+-]{0,127}\Z")
_OBSERVED_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
_MAX_SOURCE_GAPS = 64


def _validate_source_payload(source):
    """One complete, ordered ledger snapshot with semantic and metadata digests.

    revision_sha256 covers a ticket's behavior, acceptance, dependencies and
    prose; metadata_sha256 covers only owner-approved scheduling metadata such
    as priority. The host observer supplies the split and a source sequence
    that only grows along the ledger's history.
    """
    if not isinstance(source["observation_id"], str) or not _ID.fullmatch(source["observation_id"]):
        raise MissionRefusal("invalid observation identity")
    if not isinstance(source["ledger_sha256"], str) or not _SHA.fullmatch(source["ledger_sha256"]):
        raise MissionRefusal("invalid ledger digest")
    if not isinstance(source["source_version"], str) or not _SOURCE_VERSION.fullmatch(source["source_version"]):
        raise MissionRefusal("invalid source version")
    if type(source["sequence"]) is not int or source["sequence"] < 1:
        raise MissionRefusal("invalid source sequence")
    if not isinstance(source["observed_at"], str) or not _OBSERVED_AT.fullmatch(source["observed_at"]):
        raise MissionRefusal("invalid source observation time")
    tickets = source["tickets"]
    if not isinstance(tickets, dict) or len(tickets) > 512:
        raise MissionRefusal("invalid bounded ticket pool")
    for ticket_id, ticket in tickets.items():
        if not isinstance(ticket_id, str) or not _TICKET.fullmatch(ticket_id):
            raise MissionRefusal("invalid ticket identity")
        _require_shape(ticket, ("revision_sha256", "metadata_sha256", "ready"), "ticket")
        for field in ("revision_sha256", "metadata_sha256"):
            if not isinstance(ticket[field], str) or not _SHA.fullmatch(ticket[field]):
                raise MissionRefusal("invalid ticket " + field.removesuffix("_sha256"))
        if type(ticket["ready"]) is not bool:
            raise MissionRefusal("unknown ticket readiness")


def _source_snapshot(state):
    source = state["source"]
    return {key: source[key] for key in ("observation_id", "version", "sequence", "observed_at")}


def _apply_source(state, source):
    """Accept one newer complete snapshot; never move requirements backward.

    A delayed, repeated or reordered observation is not newer and refuses.
    A skipped sequence is accepted as the complete current snapshot and its
    gap stays visible. A ticket missing from the snapshot is tombstoned and
    never resurrected: if its identity returns it is held not ready. A held
    mission whose ticket changed semantically, lost readiness (for example a
    dependency reopened) or was deleted is marked so for good; only a
    separately admitted mission can carry changed intent.
    """
    identity = source["observation_id"]
    if identity in state["observations"]:
        raise MissionRefusal("pool observation was already consumed")
    previous = state.get("source")
    if previous is not None and source["sequence"] <= previous["sequence"]:
        raise MissionRefusal("source observation is not newer than the current source")
    tombstones = state.setdefault("tombstones", {})
    known = state["pool"]["tickets"] if state["pool"] is not None else {}
    for ticket_id, ticket in known.items():
        if ticket_id not in source["tickets"] and ticket_id not in tombstones:
            tombstones[ticket_id] = {"revision_sha256": ticket["revision_sha256"],
                                     "observation_id": identity}
    gaps = list(previous["gaps"]) if previous is not None else []
    if previous is not None and source["sequence"] != previous["sequence"] + 1:
        gaps = (gaps + [[previous["sequence"], source["sequence"]]])[-_MAX_SOURCE_GAPS:]
    state["observations"][identity] = _sha(source)
    state["pool"] = {"observation_id": identity, "ledger_sha256": source["ledger_sha256"],
                     "tickets": {ticket_id: {"revision_sha256": ticket["revision_sha256"],
                                             "ready": ticket["ready"] and ticket_id not in tombstones}
                                 for ticket_id, ticket in source["tickets"].items()}}
    state["ticket_metadata"] = {ticket_id: ticket["metadata_sha256"]
                                for ticket_id, ticket in source["tickets"].items()}
    state["source"] = {"observation_id": identity, "version": source["source_version"],
                       "sequence": source["sequence"], "observed_at": source["observed_at"],
                       "gaps": gaps}
    for mission in state["missions"].values():
        if mission.get("claim_state") == "RELEASED" or "requirements" in mission:
            continue
        frozen = mission["freeze"]
        current = state["pool"]["tickets"].get(frozen["ticket_id"])
        if frozen["ticket_id"] in tombstones:
            changed, reason = "TOMBSTONED", "ticket_deleted"
        elif current is None or current["revision_sha256"] != frozen["revision_sha256"]:
            changed, reason = "STALE", "requirement_revision_changed"
        elif not current["ready"]:
            changed, reason = "STALE", "readiness_lost"
        else:
            continue
        mission["requirements"] = {"state": changed, "reason": reason, "observation_id": identity,
                                   "source_version": source["source_version"],
                                   "sequence": source["sequence"]}


def _record_source(state, mission, key):
    """Make the exact source version visible where a decision was taken."""
    if state.get("source") is not None:
        mission[key] = _source_snapshot(state)


def pending_effects(mission):
    """Effect intents whose outcome this authority has not yet observed."""
    pending = ["receiver:" + key for key, intent in sorted(mission.get("receiver_intents", {}).items())
               if "response_ref" not in intent]
    for effect in ("verification", "publication"):
        if effect + "_intent" in mission and effect + "_observation_ref" not in mission:
            pending.append(effect)
    if "worker_release_intent" in mission and "worker_release_observation_ref" not in mission:
        pending.append("worker_release")
    if "settlement_intent" in mission and mission.get("claim_state") == "HELD":
        pending.append("settlement")
    return pending


def _read_mission_artifact(tower, ref):
    """Use the ledger's reference validation; translate unreadable retained bytes."""
    try:
        return tower.artifacts.read(ref)
    except (OSError, KeyError, ValueError, TypeError, AttributeError) as error:
        raise MissionRefusal('mission artifact is not readable bounded data') from error


def _read_mission_json(tower, ref, *, limit=_MAX_REQUEST_BYTES):
    try:
        body = _read_mission_artifact(tower, ref)
        if len(body) > limit or ref.get("media_type") != "application/json":
            raise MissionRefusal("mission artifact is not bounded JSON")
        value = json.loads(body)
        if not isinstance(value, dict):
            raise MissionRefusal("mission artifact must be a JSON object")
        return value
    except MissionRefusal:
        raise
    except (OSError, ValueError, TypeError, AttributeError) as error:
        raise MissionRefusal('mission artifact is not readable bounded JSON') from error


def _validate_planned_workspace(workspace_path):
    """Permit an absent canonical planned workspace; the parent must be a canonical directory.

    The selected WorkerPort supervisor creates its workspace after start, so
    admitting the mission must accept the registered planned path being
    absent and demand only that the parent exists as a canonical directory.
    This grants no creation permission and does not assert physical
    containment; the planned-workspace M3 worker owns the trusted catalog,
    supervisor and worktree IDs and is responsible for materializing the
    workspace. The Root host demands the exact registered planned path be
    absent immediately before service.start and the materialized manifest
    and cwd match afterward. Existing canonical directory fixtures remain
    accepted as a legacy check path; that path is not a creation grant.
    """
    workspace = Path(workspace_path)
    if not workspace.is_absolute():
        raise MissionRefusal("mission workspace identity is unavailable")
    if workspace.exists() or workspace.is_symlink():
        try:
            info = workspace.lstat()
        except OSError as error:
            raise MissionRefusal("mission workspace identity is unavailable") from error
        if stat.S_ISLNK(info.st_mode):
            raise MissionRefusal("mission workspace is a symlink")
        if stat.S_ISDIR(info.st_mode):
            try:
                canonical = workspace.resolve(strict=True)
            except OSError as error:
                raise MissionRefusal("mission workspace identity is unavailable") from error
            if canonical != workspace:
                raise MissionRefusal("mission workspace is not canonical")
            return
        raise MissionRefusal("mission workspace is a file")
    parent = workspace.parent
    if parent == workspace:
        raise MissionRefusal("mission workspace has no parent directory")
    if not parent.exists() or parent.is_symlink():
        raise MissionRefusal("mission workspace parent is unavailable")
    try:
        parent_info = parent.lstat()
    except OSError as error:
        raise MissionRefusal("mission workspace parent is unavailable") from error
    if not stat.S_ISDIR(parent_info.st_mode):
        raise MissionRefusal("mission workspace parent is not a directory")
    try:
        canonical_parent = parent.resolve(strict=True)
    except OSError as error:
        raise MissionRefusal("mission workspace parent is not canonical") from error
    if canonical_parent != parent:
        raise MissionRefusal("mission workspace parent is not canonical")


def _require_root_custody(tower, ref, frozen, schema):
    provenance = tower.artifacts.record(ref)
    if (provenance["content_schema"] != schema or
            provenance["producer_run_id"] != frozen["run_id"] or
            provenance["producer_node_id"] != "root" or
            provenance["task_spec_sha256"] != ref["sha256"] or
            provenance["privacy_class"] != "local_only" or
            "mission" not in provenance["consumer_node_ids"]):
        raise MissionRefusal("mission artifact custody does not bind the root")


def _read_freeze(tower, ref):
    frozen = _read_mission_json(tower, ref)
    # Dispatch by schema first; v1 and v2 use disjoint closed shape sets.
    schema = frozen.get("schema") if isinstance(frozen, dict) else None
    if schema == FREEZE_SCHEMA_V2:
        _require_shape(frozen, (
            "schema", "mission_id", "repository", "ticket_id", "revision_sha256",
            "observation_id", "run_id", "plan_sha256", "ownership_generation",
            "capacity_lane_id", "write_scope", "shared_resources", "target_ref",
            "baseline_commit", "workspace", "workspace_manifest_sha256",
            "acceptance_policy_sha256", "route", "requester", "limits",
            "batch", "interface_contracts",
        ), "mission freeze")
        return _read_freeze_v2(tower, frozen, ref)
    if schema != FREEZE_SCHEMA:
        raise MissionRefusal("unsupported mission freeze")
    _require_shape(frozen, (
        "schema", "mission_id", "repository", "ticket_id", "revision_sha256",
        "observation_id", "run_id", "plan_sha256", "ownership_generation",
        "capacity_lane_id", "write_scope", "shared_resources", "target_ref",
        "baseline_commit", "workspace", "workspace_manifest_sha256",
        "acceptance_policy_sha256", "route", "requester", "limits",
    ), "mission freeze")
    for field in ("mission_id", "observation_id", "run_id"):
        if not isinstance(frozen[field], str) or not _ID.fullmatch(frozen[field]):
            raise MissionRefusal("invalid frozen " + field)
    if not isinstance(frozen["ticket_id"], str) or not _TICKET.fullmatch(
            frozen["ticket_id"]):
        raise MissionRefusal("invalid frozen ticket")
    for field in ("revision_sha256", "plan_sha256", "workspace_manifest_sha256",
                  "acceptance_policy_sha256"):
        if not isinstance(frozen[field], str) or not _SHA.fullmatch(frozen[field]):
            raise MissionRefusal("invalid frozen " + field)
    if type(frozen["ownership_generation"]) is not int or \
            frozen["ownership_generation"] < 1:
        raise MissionRefusal("invalid ownership generation")
    if not isinstance(frozen["capacity_lane_id"], str) or not \
            1 <= len(frozen["capacity_lane_id"]) <= 255:
        raise MissionRefusal("invalid capacity lane identity")
    # The first mission conservatively owns the complete repository. Narrow
    # disjoint path claims and concurrent completion belong to Issue 226.
    if frozen["write_scope"] != ["."]:
        raise MissionRefusal("first mission requires complete repository scope")
    resources = frozen["shared_resources"]
    if not isinstance(frozen["target_ref"], str) or not re.fullmatch(
            r"refs/heads/[A-Za-z0-9_./-]{1,128}", frozen["target_ref"]):
        raise MissionRefusal("invalid designated target")
    required = {"ticket:" + frozen["ticket_id"], "target:" + frozen["target_ref"]}
    if (not isinstance(resources, list) or len(resources) > 64 or
            any(not isinstance(item, str) or not item or len(item) > 255
                for item in resources) or len(set(resources)) != len(resources)
            or not required <= set(resources)):
        raise MissionRefusal("complete shared resource scope is required")
    if not isinstance(frozen["baseline_commit"], str) or not _GIT_OID.fullmatch(frozen["baseline_commit"]):
        raise MissionRefusal("invalid workspace baseline")
    if not is_canonical_absolute_path(frozen["workspace"]):
        raise MissionRefusal("invalid frozen workspace")
    # The frozen workspace is the registered planned path; the planned-
    # workspace M3 worker (separate) owns the trusted catalog, supervisor
    # and worktree IDs and binds the registered workspace object through
    # the existing workspace_manifest_sha256. The live-filesystem
    # existence/current-identity check is performed at the admit write
    # boundary only, never in history reduction: canonical state is a
    # reduction of durable facts, not a snapshot of host filesystem.
    _require_shape(frozen["route"], ("model", "effort", "manifest_sha256"), "route")
    if (any(not isinstance(frozen["route"][field], str) or
            not 1 <= len(frozen["route"][field]) <= 255
            for field in ("model", "effort")) or
            not isinstance(frozen["route"]["manifest_sha256"], str) or
            not _SHA.fullmatch(frozen["route"]["manifest_sha256"])):
        raise MissionRefusal("unsupported selected mission route")
    _require_shape(frozen["requester"], ("root_task_id", "root_model", "root_effort"),
                   "requester")
    if (not isinstance(frozen["requester"]["root_task_id"], str) or
            not _ID.fullmatch(frozen["requester"]["root_task_id"]) or
            frozen["requester"]["root_effort"] != "xhigh" or
            not isinstance(frozen["requester"]["root_model"], str)):
        raise MissionRefusal("invalid run-owning requester")
    limits = frozen["limits"]
    _require_shape(limits, (
        "worker_lanes", "unfinished_missions", "retained_candidates",
        "output_bytes", "elapsed_ms", "tokens", "cost_microunits",
        "verification_ms", "intake_iterations", "receiver_operations",
        "receiver_response_bytes",
    ), "limits")
    if any(type(value) is not int or value <= 0 for value in limits.values()):
        raise MissionRefusal("finite positive mission limits are required")
    if (any(limits[key] != 1 for key in ("worker_lanes", "unfinished_missions"))
            or limits["output_bytes"] > 65_536 or limits["receiver_operations"] > 128
            or limits["receiver_response_bytes"] > 1_048_576):
        raise MissionRefusal("mission exceeds first-slice capacity")
    _require_root_custody(tower, ref, frozen, FREEZE_SCHEMA)
    return frozen


def _validate_canonical_relative_path(value, label):
    """Translate the shared strict path predicate into the mission vocabulary."""
    try:
        _mission_scope.path_in_scope(value, (".",))
    except _mission_scope.ScopeRefusal as error:
        raise MissionRefusal("invalid " + label) from error


def _read_freeze_v2(tower, frozen, ref):
    """Validate an Issue 226 v2 batch-claim mission freeze (sibling of v1).

    The v2 freeze is the original v1 set of fields plus the closed
    ``batch`` and ``interface_contracts`` extensions. Distinct run
    contexts require distinct run IDs, plans, workspaces and capacity
    lanes; shared ``target:`` resources are reserved out of the v2
    admission. The limits enforce two claimed unfinished missions,
    one writer lane and at most two retained candidates. The validation
    here is the typed shape and content contract; the actual batch
    consistency, mode mixing and collision checks happen at the admit
    write boundary in :func:`_apply_admission_v2`.
    """
    for field in ("mission_id", "observation_id", "run_id"):
        if not isinstance(frozen[field], str) or not _ID.fullmatch(frozen[field]):
            raise MissionRefusal("invalid frozen " + field)
    if not isinstance(frozen["ticket_id"], str) or not _TICKET.fullmatch(
            frozen["ticket_id"]):
        raise MissionRefusal("invalid frozen ticket")
    for field in ("revision_sha256", "plan_sha256", "workspace_manifest_sha256",
                  "acceptance_policy_sha256"):
        if not isinstance(frozen[field], str) or not _SHA.fullmatch(frozen[field]):
            raise MissionRefusal("invalid frozen " + field)
    if type(frozen["ownership_generation"]) is not int or \
            frozen["ownership_generation"] < 1:
        raise MissionRefusal("invalid ownership generation")
    if not isinstance(frozen["capacity_lane_id"], str) or not \
            1 <= len(frozen["capacity_lane_id"]) <= 255:
        raise MissionRefusal("invalid capacity lane identity")
    try:
        normalized_scope = _mission_scope.normalize_scope(frozen["write_scope"])
    except _mission_scope.ScopeRefusal as error:
        raise MissionRefusal("invalid v2 write scope: " + str(error)) from error
    if normalized_scope == (".",):
        raise MissionRefusal("v2 write_scope must not be the legacy whole repository")
    if frozen["write_scope"] != list(normalized_scope):
        raise MissionRefusal("v2 write_scope must be canonically sorted")
    resources = frozen["shared_resources"]
    if (not isinstance(resources, list) or len(resources) > 64 or
            any(not isinstance(item, str) or not item or len(item) > 255
                for item in resources) or len(set(resources)) != len(resources)):
        raise MissionRefusal("invalid v2 shared resources")
    required = {"ticket:" + frozen["ticket_id"]}
    if not required <= set(resources):
        raise MissionRefusal("v2 shared resources must include ticket:<ticket_id>")
    if any(item.startswith("target:") for item in resources):
        raise MissionRefusal("v2 shared resources must not hold a target:<ref> reference")
    if not isinstance(frozen["target_ref"], str) or not re.fullmatch(
            r"refs/heads/[A-Za-z0-9_./-]{1,128}", frozen["target_ref"]):
        raise MissionRefusal("invalid designated target")
    if not isinstance(frozen["baseline_commit"], str) or not _GIT_OID.fullmatch(frozen["baseline_commit"]):
        raise MissionRefusal("invalid workspace baseline")
    if not is_canonical_absolute_path(frozen["workspace"]):
        raise MissionRefusal("invalid frozen workspace")
    _require_shape(frozen["route"], ("model", "effort", "manifest_sha256"), "route")
    if (any(not isinstance(frozen["route"][field], str) or
            not 1 <= len(frozen["route"][field]) <= 255
            for field in ("model", "effort")) or
            not isinstance(frozen["route"]["manifest_sha256"], str) or
            not _SHA.fullmatch(frozen["route"]["manifest_sha256"])):
        raise MissionRefusal("unsupported selected mission route")
    _require_shape(frozen["requester"], ("root_task_id", "root_model", "root_effort"),
                   "requester")
    if (not isinstance(frozen["requester"]["root_task_id"], str) or
            not _ID.fullmatch(frozen["requester"]["root_task_id"]) or
            frozen["requester"]["root_effort"] != "xhigh" or
            not isinstance(frozen["requester"]["root_model"], str)):
        raise MissionRefusal("invalid run-owning requester")
    limits = frozen["limits"]
    _require_shape(limits, (
        "worker_lanes", "unfinished_missions", "retained_candidates",
        "output_bytes", "elapsed_ms", "tokens", "cost_microunits",
        "verification_ms", "intake_iterations", "receiver_operations",
        "receiver_response_bytes",
    ), "limits")
    if any(type(value) is not int or value <= 0 for value in limits.values()):
        raise MissionRefusal("finite positive mission limits are required")
    if (limits["worker_lanes"] != 1 or
            limits["unfinished_missions"] != 2 or
            limits["retained_candidates"] > 2 or
            limits["output_bytes"] > 65_536 or limits["receiver_operations"] > 128
            or limits["receiver_response_bytes"] > 1_048_576):
        raise MissionRefusal("v2 mission exceeds fixed two-mission capacity")
    batch = frozen["batch"]
    _require_shape(batch, ("id", "mission_ids", "unfinished_limit",
                           "completion_limit"), "v2 batch")
    if (not isinstance(batch["id"], str) or not _ID.fullmatch(batch["id"])):
        raise MissionRefusal("invalid v2 batch id")
    if (not isinstance(batch["mission_ids"], list) or
            len(batch["mission_ids"]) not in (1, 2) or
            any(not isinstance(item, str) or not _ID.fullmatch(item)
                for item in batch["mission_ids"]) or
            len(set(batch["mission_ids"])) != len(batch["mission_ids"])):
        raise MissionRefusal("invalid v2 batch mission ids")
    mission_ids_sorted = sorted(batch["mission_ids"])
    if batch["mission_ids"] != mission_ids_sorted:
        raise MissionRefusal("v2 batch mission ids must be sorted")
    if frozen["mission_id"] not in batch["mission_ids"]:
        raise MissionRefusal("v2 batch mission ids must contain this mission")
    if (type(batch["unfinished_limit"]) is not int or
            batch["unfinished_limit"] != 2 or
            type(batch["completion_limit"]) is not int or
            batch["completion_limit"] != 1):
        raise MissionRefusal("v2 batch limits must be unfinished_limit=2 completion_limit=1")
    contracts = frozen["interface_contracts"]
    if not isinstance(contracts, list) or len(contracts) > 64:
        raise MissionRefusal("invalid v2 interface contracts")
    seen_paths = []
    for contract in contracts:
        _require_shape(contract, ("path", "sha256"), "v2 interface contract")
        _validate_canonical_relative_path(contract["path"], "v2 interface contract path")
        if (not isinstance(contract["sha256"], str) or
                not _SHA.fullmatch(contract["sha256"])):
            raise MissionRefusal("invalid v2 interface contract sha256")
        seen_paths.append(contract["path"])
    if sorted(seen_paths) != seen_paths:
        raise MissionRefusal("v2 interface contracts must be sorted by path")
    if len(set(seen_paths)) != len(seen_paths):
        raise MissionRefusal("v2 interface contracts must be unique by path")
    # The v2 interface contracts are relied-on read-only target file
    # facts: this mission declares which target files it depends on
    # without writing. A freeze whose own write_scope covers any of
    # its own contract paths is declaring a write intent on a file it
    # also promises not to write; lexical disjointness is not
    # semantic independence.
    own_scope = tuple(frozen["write_scope"])
    for contract_path in seen_paths:
        if _mission_scope.path_in_scope(contract_path, own_scope):
            raise MissionRefusal("v2 write_scope covers its own interface contract path")
    _require_root_custody(tower, ref, frozen, FREEZE_SCHEMA_V2)
    return frozen



def _matches_current_ready_revision(state, frozen):
    """One exact ticket/revision/readiness invariant for every creation path.

    A mission an ordered source marked changed or deleted never matches
    again, even if its revision returns.
    """
    pool = state["pool"]
    mission = state["missions"].get(frozen["mission_id"])
    if mission is not None and "requirements" in mission:
        return False
    return pool is not None and pool["tickets"].get(frozen["ticket_id"]) == {
        "revision_sha256": frozen["revision_sha256"], "ready": True}


def _apply_admission(state, frozen, ref, capacity_sha256):
    """Admit one mission freeze; v2 freezes the same dispatch after fixed batch checks."""
    pool = state["pool"]
    if (pool is None or frozen["repository"] != state["repository"] or
            frozen["observation_id"] != pool["observation_id"] or
            not _matches_current_ready_revision(state, frozen)):
        raise MissionRefusal("mission no longer matches the current ready revision")
    # The ownership generation is the canonical fact generation at claim
    # acquisition. It stays frozen for that owner while later facts advance
    # the stream's separate CAS generation; it is never a renewable lease.
    if frozen["ownership_generation"] != state["generation"] + 1:
        raise MissionRefusal("mission ownership generation is stale")
    if frozen["mission_id"] in state["missions"]:
        raise MissionRefusal("mission identity was already retained")
    if frozen["schema"] == FREEZE_SCHEMA_V2:
        _apply_admission_v2(state, frozen, ref, capacity_sha256)
        return
    # The first legacy mission conservatively owns the complete repository.
    # Mixed v1/v2 freezes refuse; an unfinished v1 mission occupies the
    # single completion slot until settlement.
    if any(mission.get("claim_state") != "RELEASED" for mission in state["missions"].values()):
        raise MissionRefusal("unfinished mission completion slot is occupied")
    state["missions"][frozen["mission_id"]] = {
        "status": "ADMITTED", "claim_state": "HELD", "freeze": frozen, "frozen_mission_ref": ref,
        "capacity_sha256": capacity_sha256, "receiver_intents": {},
        "receiver_cursor": 0, "receiver_state": None,
    }
    _record_source(state, state["missions"][frozen["mission_id"]], "admitted_source")


def _apply_admission_v2(state, frozen, ref, capacity_sha256):
    """Admit one v2 batch-claim mission freeze under the fixed two-mission slice.

    The validation enforces the bounded first Issue 226 vertical slice:

    * Mixed v1/v2 refuses: any held v1 mission blocks v2 admission and
      any held v2 mission blocks v1 admission through the standard
      ``unfinished mission completion slot is occupied`` path.
    * The third mission refuses: the v2 batch ``unfinished_limit`` is 2.
    * Different batch freezes refuse while any claims are held: a held
      v2 mission's batch id becomes the canonical batch for the
      repository until settlement.
    * Duplicate tickets / overlapping write scopes / overlapping shared
      resources / duplicate run IDs / duplicate capacity lanes /
      duplicate workspaces refuse before any partial claim is recorded.
      Canonical repository identity uses the existing common Git
      device/inode proof; path spelling aliases do not bypass admission.
    """
    held = [mission for mission in state["missions"].values()
            if mission.get("claim_state") != "RELEASED"]
    # Issue 227 rolling refill: a singleton batch is one refill member. It
    # needs ordered source observations, cannot take a slot reserved for an
    # incomplete fixed batch, and waits until every held mission's effects
    # are reconciled, so a restart cannot add effects over unknown outcomes.
    rolling = len(frozen["batch"]["mission_ids"]) == 1
    if rolling:
        if state.get("source") is None:
            raise MissionRefusal("v2 rolling batch requires ordered source observations")
        if any(mission["freeze"].get("batch", {}).get("id") == frozen["batch"]["id"]
               for mission in state["missions"].values()):
            raise MissionRefusal("v2 rolling batch id was already used")
        for existing in held:
            members = existing["freeze"].get("batch", {}).get("mission_ids", [])
            if len(members) > 1 and any(member not in state["missions"] for member in members):
                raise MissionRefusal("v2 rolling batch cannot take an incomplete fixed batch slot")
            if pending_effects(existing):
                raise MissionRefusal("v2 rolling batch requires reconciled effects before admission")
    # Mixed legacy mode refuses: any still-held v1 mission blocks a v2
    # admission here, and held v2 missions block new v1 admissions through
    # the standard ``unfinished mission completion slot is occupied`` gate.
    # Released missions of either schema are history and block neither.
    for existing in held:
        if existing["freeze"]["schema"] != FREEZE_SCHEMA_V2:
            raise MissionRefusal("v2 admission refuses mixed legacy mode")
    new_batch_id = frozen["batch"]["id"]
    new_scope = tuple(frozen["write_scope"])
    new_resources = frozenset(frozen["shared_resources"])
    # Per-resource collision checks run before the unfinished-slot
    # check: duplicate ticket / scope / shared-resource / run / plan /
    # workspace / capacity-lane / interface-contract overlap all
    # refuse before any partial claim is recorded, regardless of
    # whether the slot is full.
    for existing in held:
        if not rolling and existing["freeze"]["batch"]["id"] != new_batch_id:
            raise MissionRefusal("v2 admission refuses a different batch")
        existing_freeze = existing["freeze"]
        if existing_freeze["ticket_id"] == frozen["ticket_id"]:
            raise MissionRefusal("v2 admission refuses a duplicate ticket")
        if existing_freeze["run_id"] == frozen["run_id"]:
            raise MissionRefusal("v2 admission refuses a duplicate run id")
        if existing_freeze["plan_sha256"] == frozen["plan_sha256"]:
            raise MissionRefusal("v2 admission refuses a duplicate plan")
        if existing_freeze["workspace"] == frozen["workspace"]:
            raise MissionRefusal("v2 admission refuses a duplicate workspace")
        if existing_freeze["capacity_lane_id"] == frozen["capacity_lane_id"]:
            raise MissionRefusal("v2 admission refuses a duplicate capacity lane")
        existing_scope = tuple(existing_freeze["write_scope"])
        if _mission_scope.scopes_overlap(existing_scope, new_scope):
            raise MissionRefusal("v2 admission refuses an overlapping scope")
        existing_resources = frozenset(existing_freeze["shared_resources"])
        if existing_resources & new_resources:
            raise MissionRefusal("v2 admission refuses an overlapping shared resource")
        existing_contracts = [item["path"] for item in
                              existing_freeze.get("interface_contracts", [])]
        new_contracts = [item["path"] for item in
                         frozen.get("interface_contracts", [])]
        if any(_mission_scope.path_in_scope(contract_path, new_scope)
               for contract_path in existing_contracts):
            raise MissionRefusal("v2 admission writes inside a peer's interface contract")
        if any(_mission_scope.path_in_scope(contract_path, existing_scope)
               for contract_path in new_contracts):
            raise MissionRefusal("v2 admission's contract is inside a peer's write_scope")
    # After per-resource checks pass, the unfinished-slot check guards
    # against a third mission regardless of whether its collisions
    # would have refused; the slot is the canonical completion bound.
    if len(held) >= 2:
        raise MissionRefusal("v2 unfinished mission slot is occupied")
    if not rolling and any(existing["freeze"]["batch"] != frozen["batch"] for existing in held):
        raise MissionRefusal("v2 admission refuses inconsistent batch membership")
    state["missions"][frozen["mission_id"]] = {
        "status": "ADMITTED", "claim_state": "HELD", "freeze": frozen, "frozen_mission_ref": ref,
        "capacity_sha256": capacity_sha256, "receiver_intents": {},
        "receiver_cursor": 0, "receiver_state": None,
    }
    _record_source(state, state["missions"][frozen["mission_id"]], "admitted_source")


def _read_worker_request(tower, mission, ref):
    """Bind the existing WorkerPort envelope; this records no launch permission.

    The composed host still must validate every registered object and physical
    route against the freeze through WorkerPort's own catalog before delivery.
    An immutable intent is not a successful registration or execution receipt.
    """
    request = _read_mission_json(tower, ref)
    _require_shape(request, ("schema", "operation", "owner", "session_handle", "cursor",
                             "idempotency_key", "payload", "request_sha256"), "worker request")
    if (request["schema"] != "orch-dork/worker-port-host-request/v1" or
            request["operation"] not in ("start", "status", "follow_up", "cancel", "collect") or
            type(request["cursor"]) is not int or request["cursor"] < 0 or
            not isinstance(request["idempotency_key"], str) or not _RECEIVER_KEY.fullmatch(request["idempotency_key"])):
        raise MissionRefusal("unsupported worker request")
    core = {key: value for key, value in request.items() if key != "request_sha256"}
    if request["request_sha256"] != _sha(core):
        raise MissionRefusal("worker request seal changed")
    frozen = mission["freeze"]
    owner = {"schema": "orch-dork/worker-port-owner/v1",
             "owner_id": frozen["requester"]["root_task_id"],
             "generation": str(frozen["ownership_generation"]),
             "authority_sha256": mission["frozen_mission_ref"]["sha256"]}
    owner["owner_sha256"] = _sha(owner)
    if request["owner"] != owner:
        raise MissionRefusal("worker request does not bind the run-owning root")
    operation = request["operation"]
    if operation == "start":
        if request["session_handle"] is not None or request["cursor"] != 0:
            raise MissionRefusal("invalid first worker session")
        _require_shape(request["payload"], ("refs",), "worker start payload")
        _require_shape(request["payload"]["refs"], (
            "authority", "base_revision", "capability_profile", "capacity_reservation",
            "lane_workspace", "model_manifest", "route", "runtime", "task_spec", "worker_call",
        ), "worker start refs")
        refs = request["payload"]["refs"].values()
    else:
        starts = [intent["request"] for intent in mission["receiver_intents"].values()
                  if intent["request"]["operation"] == "start"]
        if (len(starts) != 1 or request["session_handle"] !=
                "wp-" + starts[0]["request_sha256"][:32] or
                request["cursor"] != mission["receiver_cursor"]):
            raise MissionRefusal("worker request does not bind the original session cursor")
        if operation in ("status", "collect"):
            _require_shape(request["payload"], (), "worker readback payload")
            refs = ()
        else:
            name = "continuation_ref" if operation == "follow_up" else "cancellation_ref"
            _require_shape(request["payload"], (name,), "worker control payload")
            refs = (request["payload"][name],)
    for object_ref in refs:
        _require_shape(object_ref, ("schema", "kind", "object_id", "sha256"), "worker object ref")
        if (object_ref["schema"] != "orch-dork/worker-port-object-ref/v1" or
                any(not isinstance(object_ref[field], str) or not _RECEIVER_KEY.fullmatch(object_ref[field])
                    for field in ("kind", "object_id")) or
                not isinstance(object_ref["sha256"], str) or not _SHA.fullmatch(
                    object_ref["sha256"])):
            raise MissionRefusal("invalid worker object identity")
    _require_root_custody(tower, ref, frozen, request["schema"])
    return request


def _apply_receiver_intent(tower, state, payload, request):
    mission = state["missions"].get(payload["mission_id"])
    if mission is None:
        raise MissionRefusal("mission claim is unavailable")
    frozen = mission["freeze"]
    operation = request["operation"]
    intents = mission["receiver_intents"]
    if operation == "start" and (mission["status"] != "ADMITTED" or intents):
        raise MissionRefusal("worker start already has a retained intent")
    if request["idempotency_key"] in intents:
        raise MissionRefusal("receiver key already has a retained intent")
    if len(intents) >= frozen["limits"]["receiver_operations"]:
        raise MissionRefusal("receiver operation budget is exhausted")
    if operation in ("start", "follow_up"):
        if 'worker_release_intent' in mission:
            raise MissionRefusal('worker release closes worker creation')
        if not _matches_current_ready_revision(state, frozen):
            raise MissionRefusal("worker effect no longer matches the current ready revision")
    if operation == "follow_up":
        if ("candidate_ref" in mission or mission["receiver_state"] != "AWAITING_FOLLOW_UP" or
                any(intent["request"]["operation"] == "follow_up" for intent in intents.values())):
            raise MissionRefusal("worker follow-up requires one observed waiting session")
    intents[request["idempotency_key"]] = {
        "request": request, "request_ref": payload["request_ref"], "delivery": "UNKNOWN",
    }
    if operation == "start":
        mission["status"] = "START_PENDING"



def _apply_receiver_observation(tower, state, payload):
    """Retain a root-custodied receiver readback; never release a claim.

    This binds the initial response to the retained exact start. The composed
    host validates WorkerPort's full protocol and independently observes its
    receiver before publishing the artifact. Neither this ledger fact nor a
    session-state string establishes cessation, containment or acceptance.
    Current admission is deliberately not consulted for historical readback.
    """
    mission = state["missions"].get(payload["mission_id"])
    if mission is None:
        raise MissionRefusal("receiver mission claim is unavailable")
    intent = mission["receiver_intents"].get(payload["idempotency_key"])
    if intent is None:
        raise MissionRefusal("receiver observation has no retained intent")
    if "response_ref" in intent:
        raise MissionRefusal("receiver receipt is already retained")
    ref = payload["response_ref"]
    response = _read_mission_json(
        tower, ref, limit=mission["freeze"]["limits"]["receiver_response_bytes"])
    _require_shape(response, (
        "schema", "operation", "request_sha256", "request", "status", "reason",
        "session_handle", "cursor", "session_state", "events", "collection",
        "timing", "response_sha256",
    ), "receiver response")
    request = intent["request"]
    core = {key: value for key, value in response.items() if key != "response_sha256"}
    handle = response["session_handle"]
    expected_handle = ("wp-" + request["request_sha256"][:32]
                       if request["operation"] == "start" else request["session_handle"])
    if (response["schema"] != "orch-dork/worker-port-host-response/v1" or
            response["operation"] != request["operation"] or
            response["request"] != request or
            response["request_sha256"] != request["request_sha256"] or
            response["response_sha256"] != _sha(core) or
            response["status"] not in ("ACCEPTED", "PASS", "REFUSED", "UNAVAILABLE",
                                       "RECOVERY_PENDING") or
            handle not in (None, expected_handle) or
            (response["status"] in ("ACCEPTED", "PASS") and handle is None)):
        raise MissionRefusal("receiver response does not bind the retained intent")
    if (not isinstance(response["reason"], str) or not response["reason"] or
            len(response["reason"].encode()) > 8192 or "\x00" in response["reason"] or
            type(response["cursor"]) is not int or response["cursor"] < request["cursor"] or
            (response["session_state"] is not None and (
                not isinstance(response["session_state"], str) or not _RECEIVER_KEY.fullmatch(response["session_state"]))) or
            not isinstance(response["events"], list) or len(response["events"]) > 16 or
            any(not isinstance(event, dict) for event in response["events"]) or
            (response["collection"] is not None and (
                request["operation"] != "collect" or not isinstance(response["collection"], dict)))):
        raise MissionRefusal("receiver response metadata is invalid")
    _require_shape(response["timing"], ("wall_time_ms",), "receiver timing")
    if (type(response["timing"]["wall_time_ms"]) is not int or
            response["timing"]["wall_time_ms"] < 0):
        raise MissionRefusal("receiver response timing is invalid")
    _require_root_custody(tower, ref, mission["freeze"], response["schema"])
    intent.update(response=response, response_ref=ref,
                  delivery="OBSERVED" if response["status"] in ("ACCEPTED", "PASS")
                  else "UNKNOWN")
    if handle is not None and response["cursor"] >= mission["receiver_cursor"]:
        mission["receiver_cursor"] = response["cursor"]
        mission["receiver_state"] = response["session_state"]
    if "settlement_intent" in mission:
        return
    if "candidate_ref" not in mission:
        mission["status"] = ("WORKER_OBSERVED" if intent["delivery"] == "OBSERVED"
                             else "RECOVERY_PENDING")
    elif intent["delivery"] == "UNKNOWN":
        mission["status"] = "RECOVERY_PENDING"



def _apply_candidate_seal(tower, state, payload):
    """Retain the trusted host's exact staged-candidate binding, not acceptance.

    Root's collector validates the physical WorkerPort collection and builds
    the exact Git candidate before it publishes this manifest. This history
    checks the sealed identities and collected-byte lineage. The protected
    verifier must still read the actual commit/tree; neither a SHA1 declaration
    nor a worker's self-report establishes behavioral acceptance or landing.
    """
    mission = state["missions"].get(payload["mission_id"])
    if mission is None:
        raise MissionRefusal("candidate mission claim is unavailable")
    if "candidate_ref" in mission:
        raise MissionRefusal("candidate is already sealed and retained")
    frozen = mission["freeze"]
    if frozen["schema"] == FREEZE_SCHEMA_V2:
        retained = sum(1 for other in state["missions"].values()
                       if other is not mission and other.get("claim_state") != "RELEASED"
                       and "candidate_ref" in other)
        if retained + 1 > frozen["limits"]["retained_candidates"]:
            raise MissionRefusal("retained candidate limit is reached")
    if not _matches_current_ready_revision(state, frozen):
        raise MissionRefusal("candidate seal no longer matches the current ready revision")
    ref = payload["candidate_ref"]
    candidate = _read_mission_json(tower, ref)
    frozen_fields = (
        "mission_id", "run_id", "ticket_id", "ownership_generation", "baseline_commit",
        "workspace", "workspace_manifest_sha256", "acceptance_policy_sha256",
        "write_scope", "repository", "target_ref",
    )
    _require_shape(candidate, (*frozen_fields, "schema", "ticket_revision", "commit", "tree",
                               "collection_response_ref", "candidate_artifact_ref"), "candidate seal")
    schema = "orch-dork/mission-candidate-seal/v1"
    if (candidate["schema"] != schema or
            any(candidate[name] != frozen[name] for name in frozen_fields) or
            candidate["ticket_revision"] != frozen["revision_sha256"] or
            any(not isinstance(candidate[name], str) or not _GIT_OID.fullmatch(candidate[name]) for name in ("commit", "tree"))):
        raise MissionRefusal("candidate seal does not bind the frozen mission")
    collections = [intent["response"]["collection"]
                   for intent in mission["receiver_intents"].values()
                   if intent["request"]["operation"] == "collect" and
                   intent.get("response_ref") == candidate["collection_response_ref"] and
                   intent["response"]["status"] == "PASS" and
                   intent["response"]["session_state"] == "CANDIDATE_READY"]
    if len(collections) != 1 or not isinstance(collections[0], dict):
        raise MissionRefusal("candidate seal has no retained ready collection")
    artifact = candidate["candidate_artifact_ref"]
    diff = _read_mission_artifact(tower, artifact)
    collected = collections[0].get("candidate_artifact")
    _require_shape(collected, ("schema", "uri", "sha256", "size_bytes", "media_type"),
                   "collected candidate artifact")
    if (artifact.get("media_type") != "text/x-diff" or
            len(diff) > frozen["limits"]["output_bytes"] or
            collected["schema"] != "orch-dork/artifact-ref/v1" or
            collected["uri"] != "artifact://sha256/" + artifact["sha256"] or
            collected["media_type"] != "text/x-diff" or
            collected["sha256"] != artifact["sha256"] or
            type(collected["size_bytes"]) is not int or collected["size_bytes"] != len(diff)):
        raise MissionRefusal("candidate artifact does not bind the collected bytes")
    _require_root_custody(tower, artifact, frozen, "orch-dork/mission-candidate-diff/v1")
    _require_root_custody(tower, ref, frozen, schema)
    if (candidate["collection_response_ref"] not in tower.artifacts.record(artifact)["source_lineage"] or
            any(parent not in tower.artifacts.record(ref)["source_lineage"]
                for parent in (candidate["collection_response_ref"], artifact))):
        raise MissionRefusal("candidate artifact lineage is unavailable")
    mission.update(candidate=candidate, candidate_ref=ref, status="CANDIDATE_SEALED")


def _read_verification_request(tower, ref, frozen):
    """Read and validate a root-custodied VerificationRequest v1.

    The trusted host composes the canonical request before the protected
    verifier runs; the verifier itself does not contribute to this fact. The
    request must carry the exact closed fields declared by the stable
    verifier component and bind the frozen mission, the current ready
    revision and the original ownership generation. Authorization generation
    is checked separately against the canonical state at accepted intent.
    """
    request = _read_mission_json(tower, ref)
    try:
        verification.VerificationRequest.from_recorded_wire(request)
    except verification.VerificationRefusal as error:
        raise MissionRefusal('invalid closed verification request: '+str(error)) from error
    # The request's repository must equal the frozen mission's
    # registered common Git directory. A canonical-but-foreign path
    # would let a foreign root mask the actual frozen repository; the
    # canonical join refuses such requests.
    frozen_repo = frozen.get("repository", {})
    if (not isinstance(frozen_repo, dict) or
            not isinstance(frozen_repo.get("path"), str) or
            request["repository"] != frozen_repo["path"]):
        raise MissionRefusal("verification request repository does not match the frozen mission")
    # The request must bind the frozen mission and the exact retained
    # candidate/decision lineage. The protected verifier will re-read the
    # actual commit/tree; the SHA1 declaration alone is not acceptance.
    if (request["mission_id"] != frozen["mission_id"] or
            request["ticket_id"] != frozen["ticket_id"] or
            request["ticket_revision"] != frozen["revision_sha256"] or
            request["ownership_generation"] != frozen["ownership_generation"] or
            request["policy_sha256"] != frozen["acceptance_policy_sha256"]):
        raise MissionRefusal("verification request does not bind the frozen mission")
    _require_root_custody(tower, ref, frozen, request["schema"])
    return request


def _apply_verification_intent(tower, state, payload):
    """Commit the exact verification plan before the protected verifier runs.

    The intent binds the root-custodied VerificationRequest v1 to the
    retained candidate/freeze, the original ownership generation, the
    current ready revision and the canonical capacity that must remain
    active while the verifier is enrolled. Authorization generation is the
    canonical state generation at the moment the intent is accepted; that
    generation is what the intent will record. No physical effects run in
    the transaction: the intent only reserves the immutable plan. One
    intent is the upper bound per exact candidate; restart, retry or
    UNKNOWN observations never replace it.
    """
    mission = state["missions"].get(payload["mission_id"])
    if mission is None:
        raise MissionRefusal("verification mission claim is unavailable")
    if mission['freeze']['schema'] == FREEZE_SCHEMA_V2:
        _require_completion(state, mission)
    if "verification_intent" in mission:
        raise MissionRefusal("verification intent is already retained")
    if "candidate" not in mission:
        raise MissionRefusal("verification intent requires a sealed candidate")
    candidate = _effective_candidate(mission)
    if (candidate.get("commit") is None or candidate.get("tree") is None):
        raise MissionRefusal("sealed candidate is not verified-bound")
    frozen = mission["freeze"]
    # Current ready revision must still match before the protected verifier
    # runs; the canonical capacity binding is re-validated by the dispatch
    # caller through the same _require_capacity_binding gate that the
    # admission recorded. A later revision or capacity revocation refuses
    # the intent without partial claims and without conferring any current
    # effect. A historical observation is still recordable afterward.
    if not _matches_current_ready_revision(state, frozen):
        raise MissionRefusal("verification intent no longer matches the current ready revision")
    request = _read_verification_request(tower, payload["request_ref"], frozen)
    if (request["commit"] != candidate["commit"] or
            request["tree"] != candidate["tree"]):
        raise MissionRefusal("verification request does not bind the retained candidate")
    expected_authorization = state["generation"] + 1
    if request["authorization_generation"] != expected_authorization:
        raise MissionRefusal("verification request authorization generation is stale")
    mission.update(verification_intent=request,
                   verification_intent_ref=payload["request_ref"],
                   status="VERIFICATION_PENDING")
    _record_source(state, mission, "verification_source")


def _read_verification_evidence(tower, ref, frozen, request):
    """Validate the root-published raw evidence for one protected verification.

    The Root host calls the actual verifier, reads its closed evidence and
    publishes the raw JSON into the Artifact Ledger; the canonical mission
    ledger then re-binds the request/policy digest, the candidate
    commit/tree and the original mission generations. The observation is
    a fact, not an effect: a VERIFIED outcome does not publish, settle or
    release capacity here.
    """
    evidence = _read_mission_json(tower, ref, limit=_MAX_HOST_OBSERVATION_BYTES)
    if evidence.get('schema') == 'orch-dork/protected-verification-observation/v1':
        try:
            verification.validate_nonaccepting_observation(
                evidence, verification.VerificationRequest.from_recorded_wire(request))
        except verification.VerificationRefusal as error:
            raise MissionRefusal(str(error)) from error
        _require_root_custody(tower, ref, frozen, evidence['schema'])
        return {'request': request, 'status': evidence['result']['status'], 'reason': evidence['result']['reason']}
    try:
        verification.validate_retained_evidence(evidence)
    except verification.VerificationRefusal as error:
        raise MissionRefusal(str(error)) from error
    if evidence['request'] != request:
        raise MissionRefusal('verification evidence does not bind the retained request')
    if request['policy_sha256'] != frozen['acceptance_policy_sha256']:
        raise MissionRefusal('verification request policy does not bind the frozen policy')
    _require_root_custody(tower, ref, frozen, evidence["schema"])
    return evidence




def _retain_effect_observation(mission, effect, observation, ref, status):
    """Keep exact effect history; a settlement fixes the accepted outcome."""
    history = mission.setdefault(effect + "_observations", [])
    if len(history) >= mission["freeze"]["limits"]["receiver_operations"]:
        raise MissionRefusal(effect + " observation budget exhausted")
    history.append(dict(observation, evidence_ref=ref))
    if "settlement_intent" in mission:
        return
    if (effect == "publication" and
            mission.get("publication_observation", {}).get("status") == "LANDED"):
        return
    mission.update({effect + "_observation": observation,
                    effect + "_observation_ref": ref, "status": status})


def _apply_verification_observation(tower, state, payload):
    """Record the root-custodied protected-verification evidence.

    The observation is historical: it never confers publication, releases
    the existing claim or releases canonical capacity. When the retained
    intent and the readback match, the mission's status is updated to
    reflect the verifier's verdict, but a failed or unknown outcome keeps
    the original candidate and intent. A second observation that does not
    match the retained request refuses; restart, retry or UNKNOWN never
    replaces the original intent.
    """
    mission = state["missions"].get(payload["mission_id"])
    if mission is None:
        raise MissionRefusal("verification mission claim is unavailable")
    if "verification_intent" not in mission:
        raise MissionRefusal("verification observation has no retained intent")
    if "verification_observation" in mission or mission.get("verification_observations"):
        raise MissionRefusal("verification observation is already retained")
    intent = mission["verification_intent"]
    if payload["idempotency_key"] != intent["operation_id"]:
        raise MissionRefusal("verification observation does not bind the retained intent")
    evidence = _read_verification_evidence(
        tower, payload["evidence_ref"], mission["freeze"], intent)
    if (evidence["request"]["commit"] != _effective_candidate(mission)["commit"] or
            evidence["request"]["tree"] != _effective_candidate(mission)["tree"]):
        raise MissionRefusal("verification evidence does not bind the retained candidate")
    # The evidence must re-bind the original mission generations and the
    # request it was composed for, not a hand-written success.
    if (evidence["request"]["mission_id"] != mission["freeze"]["mission_id"] or
            evidence["request"]["ownership_generation"] !=
            mission["freeze"]["ownership_generation"]):
        raise MissionRefusal("verification evidence does not bind the original mission")
    # Retain only the immutable verdict; the run-typed observation never
    # publishes, settles or releases capacity.
    status = {"VERIFIED": "VERIFIED", "FAILED": "VERIFICATION_FAILED",
              "STOPPED": "VERIFICATION_FAILED", "REFUSED": "VERIFICATION_REFUSED"}
    _retain_effect_observation(mission, "verification",
        {"status": evidence["status"], "reason": evidence["reason"]},
        payload["evidence_ref"], status.get(evidence["status"], "VERIFICATION_UNKNOWN"))



def _publication_request(value):
    """Construct and validate the exact publication wire on every read."""
    try:
        request = publication.PublicationRequest.from_recorded_wire(value)
    except (publication.PublicationRefusal, TypeError, ValueError) as error:
        raise MissionRefusal('invalid closed publication request: '+str(error)) from error
    return request


def _apply_publication_intent(tower, state, payload):
    """Retain one full verified request; no Git effect or claim release."""
    mission = state["missions"].get(payload["mission_id"])
    if mission is None:
        raise MissionRefusal("publication mission claim is unavailable")
    if mission['freeze']['schema'] == FREEZE_SCHEMA_V2:
        _require_completion(state, mission)
    frozen = mission["freeze"]
    if "publication_intent" in mission:
        raise MissionRefusal("publication intent is already retained")
    if not _matches_current_ready_revision(state, frozen):
        raise MissionRefusal("publication does not match the current ready revision")
    if mission.get("verification_observation", {}).get("status") != "VERIFIED":
        raise MissionRefusal("publication requires protected verified evidence")
    ref = payload["request_ref"]
    value = _read_mission_json(tower, ref)
    request = _publication_request(value)
    expected = expected_publication_binding(mission, authorization_generation=state['generation'] + 1)
    if (not is_canonical_absolute_path(request.repository) or
            any(getattr(request, key) != item for key, item in expected.items())):
        raise MissionRefusal("publication request does not bind the current verified mission")
    _require_root_custody(tower, ref, frozen, publication.SCHEMA)
    lineage = tower.artifacts.record(ref)["source_lineage"]
    if any(parent not in lineage for parent in (
            _effective_candidate_ref(mission), mission["verification_observation_ref"])):
        raise MissionRefusal("publication evidence lineage is unavailable")
    mission.update(publication_intent=value, publication_intent_ref=ref,
                   publication_intent_generation=state["generation"] + 1,
                   status="PUBLICATION_PENDING")
    _record_source(state, mission, "publication_source")


def _validate_landed_publication(request, result):
    """Check the closed landing facts imported from the trusted receiver.

    The receiver proves original journal custody and marker bytes. This
    reduction binds that host observation to the retained request; it never
    performs Git effects or treats a declaration as physical acceptance.
    """
    expected = {
        "operation_id": request.operation_id,
        "request_sha256": request.sha256,
        "marker_ref": publication.publication_marker_ref(request),
        "observed_marker_oid": publication.publication_marker_oid(request),
        "landed_commit": request.new_commit,
        "landed_tree": request.new_tree,
        "reason": "marker:exact",
    }
    if any(result.get(key) != value for key, value in expected.items()):
        raise MissionRefusal("publication landing does not bind the retained request")
    target = result.get("current_target_oid")
    if ("current_target_oid" not in result or
            (target is not None and (type(target) is not str or not _GIT_OID.fullmatch(target))) or
            result.get("target_marker_snapshot_atomic") is not False):
        raise MissionRefusal("publication target observation is unavailable")
    effect = result.get("effect")
    if not isinstance(effect, dict):
        raise MissionRefusal("publication effect observation is unavailable")
    cleanup = effect.get("cleanup")
    supervisor = effect.get("supervisor_exit")
    if (type(effect.get("exit_code")) is not int or
            "supervisor_exit" not in effect or
            (supervisor is not None and (type(supervisor) is not int or supervisor != 0)) or
            effect.get("reason") != "exited" or effect.get("capture_complete") is not True or
            not isinstance(cleanup, dict) or cleanup.get("complete") is not True or
            cleanup.get("remaining") != [] or cleanup.get("group_remaining") != []):
        raise MissionRefusal("publication landing has unproved capture or cleanup")


def _apply_publication_observation(tower, state, payload):
    """Retain historical delivery readback without granting current effects."""
    mission = state["missions"].get(payload["mission_id"])
    if mission is None or "publication_intent" not in mission:
        raise MissionRefusal("publication observation has no retained intent")
    intent = mission["publication_intent"]
    if payload["idempotency_key"] != intent["operation_id"]:
        raise MissionRefusal("publication observation does not bind the retained intent")
    request = _publication_request(intent)
    ref = payload["evidence_ref"]
    value = _read_mission_json(tower, ref, limit=_MAX_HOST_OBSERVATION_BYTES)
    schema = "orch-dork/mission-publication-observation/v1"
    _require_shape(value, ("schema", "mission_id", "request_sha256", "result"),
                   "publication observation")
    if (value["schema"] != schema or value["mission_id"] != request.mission_id or
            value["request_sha256"] != request.sha256):
        raise MissionRefusal("publication observation does not bind its request")
    _require_root_custody(tower, ref, mission["freeze"], schema)
    if mission["publication_intent_ref"] not in tower.artifacts.record(ref)["source_lineage"]:
        raise MissionRefusal("publication observation lineage is unavailable")
    result = value["result"]
    if (not isinstance(result, dict) or result.get("status") not in ("LANDED", "REFUSED", "UNKNOWN") or
            type(result.get("reason")) is not str or not result["reason"] or
            result.get("retain_claims") is not True or result.get("qualification") is not False or
            result.get("operation_id") != request.operation_id or
            result.get("request_sha256") != request.sha256):
        raise MissionRefusal("invalid publication receiver observation")
    if result["status"] == "LANDED":
        _validate_landed_publication(request, result)
    observation = {"status": result["status"], "reason": result["reason"], "evidence_ref": ref}
    _retain_effect_observation(mission, "publication", observation, ref,
        "LANDED" if result["status"] == "LANDED" else "PUBLICATION_" + result["status"])


_SETTLEMENT_STATES = {"LANDED": "completed", "VERIFIED": "completed",
                      "FAILED": "failed", "STOPPED": "cancelled"}


def _settlement_outcome(mission, outcome, effect_closure=None, *, completion_failed=False):
    """Preserve acceptance verdicts; independent cessation can end uncertainty."""
    if type(outcome) is not str or outcome not in _SETTLEMENT_STATES:
        raise MissionRefusal("unsettled outcome cannot release a mission")
    verification_status = mission.get("verification_observation", {}).get("status")
    publication_status = mission.get("publication_observation", {}).get("status")
    worker = mission["receiver_state"]
    ceased = effect_closure is not None
    if publication_status == 'LANDED' and outcome != 'LANDED':
        raise MissionRefusal('observed landing requires landed settlement')
    if "publication_intent" in mission:
        if (outcome != "LANDED" or publication_status != "LANDED") and not (
                ceased and outcome in ("FAILED", "STOPPED")):
            raise MissionRefusal("unsettled publication retains the mission claim")
    if outcome == "LANDED" and (publication_status != "LANDED" or verification_status != "VERIFIED"):
        raise MissionRefusal("landing settlement requires protected landing evidence")
    if outcome in ("LANDED", "VERIFIED") and (verification_status != "VERIFIED" or worker != "CANDIDATE_READY"):
        raise MissionRefusal("verified settlement requires the terminal candidate")
    if ("verification_intent" in mission and verification_status not in ("VERIFIED", "FAILED", "STOPPED")
            and not (ceased and outcome in ("FAILED", "STOPPED"))):
        raise MissionRefusal("unsettled verification retains the mission claim")
    if outcome == "FAILED" and worker not in ("FAILED", "REJECTED", "TIMED_OUT") and verification_status != "FAILED":
        if not (ceased and (verification_status == "REFUSED" or publication_status == "REFUSED" or completion_failed)):
            raise MissionRefusal("failed settlement requires a recorded failure")
    if outcome == "STOPPED" and worker != "CANCELLED" and verification_status != "STOPPED" and not ceased:
        if any(intent["request"]["operation"] in ("start", "follow_up")
               for intent in mission["receiver_intents"].values()):
            raise MissionRefusal("stopped settlement requires recorded cessation")


WORKER_CLEANUP_SCHEMA = 'orch-dork/worker-port-terminal-cleanup-readback/v1'


def validate_worker_cleanup(proof, frozen, request):
    """One producer/consumer predicate for the original worker's bound proof."""
    expected = {'schema': WORKER_CLEANUP_SCHEMA, 'status': 'OBSERVED',
        'request_sha256': request['request_sha256'], 'workspace': frozen['workspace'],
        'baseline_commit': frozen['baseline_commit'],
        'workspace_registration_sha256': frozen['workspace_manifest_sha256']}
    if (not isinstance(proof, dict) or proof.get('qualification') is not False or
            any(proof.get(key) != item for key, item in expected.items())):
        raise MissionRefusal('worker cleanup does not bind the original mission')


@dataclass(frozen=True)
class EffectCleanupContract:
    """One retained cleanup wire and request owner, shared by both boundaries."""
    schema: str
    request_type: type
    resolution_field: str
    observed_status: str | None = None

    def request(self, wire):
        try:
            return self.request_type.from_recorded_wire(wire)
        except ValueError as error:
            raise MissionRefusal('cleanup has no closed original request') from error

    def validate(self, proof, request, *, original_status=None):
        if (not isinstance(proof, dict) or proof.get('schema') != self.schema or
                proof.get(self.resolution_field) not in ('NO_EFFECT', 'CESSATED') or
                (self.observed_status is not None and proof.get('status') != self.observed_status) or
                proof.get('request_sha256') != hashlib.sha256(request.canonical_bytes).hexdigest() or
                proof.get('qualification') is not False):
            raise MissionRefusal('cleanup does not bind the original effect')
        if self.resolution_field == 'resolution':
            if (proof['resolution'] == 'CESSATED' and
                    original_status not in ('LANDED', 'REFUSED')):
                raise MissionRefusal('unsettled publication requires original receiver reconciliation')
        elif original_status is not None and proof.get('original_status') != original_status:
            raise MissionRefusal('verification cleanup changed the original verdict')


_EFFECT_CLEANUP_CONTRACTS = {
    'verification': EffectCleanupContract(verification.CLEANUP_SCHEMA,
        verification.VerificationRequest, 'status'),
    'publication': EffectCleanupContract(publication.CLEANUP_SCHEMA,
        publication.PublicationRequest, 'resolution', 'OBSERVED'),
}


def effect_cleanup_contract(effect):
    """Read the closed mission effect contract; confer no cleanup authority."""
    return _EFFECT_CLEANUP_CONTRACTS[effect]


def validate_completion_cleanup(proof, mission, effect):
    """The closed original-read/stage cleanup binding; no release permission."""
    frozen = mission['freeze']
    if not isinstance(proof, dict) or proof.get('status') != 'OBSERVED' or proof.get('qualification') is not False:
        raise MissionRefusal('completion cleanup is unproved')
    if effect == 'target':
        expected = {'schema': 'orch-dork/mission-target-cleanup-readback/v1',
            'operation_id': completion_target_id(mission),
            'repository': frozen['repository']['path'], 'target_ref': frozen['target_ref'],
            'baseline': frozen['baseline_commit'], 'interface_contracts': frozen['interface_contracts']}
        fields = (*expected, 'request_sha256', 'result_sha256', 'status', 'resolution',
                  'original_status', 'reason', 'commands', 'qualification')
        if mission.get('completion_target_ref') is not None:
            if (proof.get('resolution') != 'CESSATED' or proof.get('original_status') != 'PASS'
                    or proof.get('result_sha256') != mission['completion_target_ref']['sha256']):
                raise MissionRefusal('completion cleanup omits its retained target observation')
    else:
        material = completion_staging_fields(mission)
        expected = {'schema': 'orch-dork/candidate-staging-cleanup-readback/v1',
            'operation_id': material['operation_id'], 'request_sha256': _sha(material)}
        fields = (*expected, 'binding_sha256', 'status', 'resolution', 'reason', 'original_status',
                  'result_sha256', 'commands', 'qualification')
        if mission.get('final_candidate_ref') is not None and (
                proof.get('resolution') != 'CESSATED' or proof.get('original_status') != 'STAGED'):
            raise MissionRefusal('completion cleanup omits its retained final candidate')
    _require_shape(proof, fields, 'completion '+effect+' cleanup')
    if (any(proof[name] != item for name, item in expected.items())
            or proof['resolution'] not in ('NO_EFFECT', 'CESSATED')):
        raise MissionRefusal('completion cleanup does not bind the original '+effect)


def _read_effect_closure(tower, mission, ref, *, current=None):
    """Bind Root's immutable physical readbacks to every original effect.

    These records are published by the trusted host under canonical exclusion.
    They are separate from the original outcome and cannot upgrade acceptance.
    Signed capacity cleanup must cover the enclosing exact closure as well.
    """
    frozen = mission['freeze']
    value = _read_mission_json(tower, ref, limit=_MAX_HOST_OBSERVATION_BYTES)
    final_completion = frozen['schema'] == FREEZE_SCHEMA_V2 and 'completion' in mission
    schema = 'orch-dork/mission-effect-closure/v2' if final_completion else 'orch-dork/mission-effect-closure/v1'
    names = ('worker_request_ref', 'worker_cleanup_ref', 'verification_intent_ref',
             'verification_cleanup_ref', 'publication_intent_ref', 'publication_cleanup_ref')
    if final_completion:
        names += ('completion_target_ref', 'completion_target_cleanup_ref',
                  'final_candidate_ref', 'final_staging_cleanup_ref')
    _require_shape(value, ('schema', 'mission_id', 'ownership_generation', 'authority_generation',
                           'authority_event_hash', *names), 'effect closure')
    if (value['schema'] != schema or value['mission_id'] != frozen['mission_id']
            or type(value['ownership_generation']) is not int
            or value['ownership_generation'] != frozen['ownership_generation']):
        raise MissionRefusal('effect closure does not bind its mission')
    if (type(value['authority_generation']) is not int or value['authority_generation'] < 0
            or type(value['authority_event_hash']) is not str
            or not _SHA.fullmatch(value['authority_event_hash'])):
        raise MissionRefusal('effect closure authority cursor is invalid')
    if current is not None and (value['authority_generation'] != current['generation']
            or value['authority_event_hash'] != current['event_hash']):
        raise MissionRefusal('effect closure authority cursor is stale')
    _require_root_custody(tower, ref, frozen, schema)
    lineage = tower.artifacts.record(ref)['source_lineage']
    for name in names:
        if value[name] is not None and value[name] not in lineage:
            raise MissionRefusal('effect closure lineage is unavailable')
    if final_completion:
        for name in ('completion_target_ref', 'final_candidate_ref'):
            if value[name] != mission.get(name):
                raise MissionRefusal('effect closure changed retained completion evidence')
        for effect, field in (('target', 'completion_target_cleanup_ref'), ('staging', 'final_staging_cleanup_ref')):
            cleanup_ref = value[field]
            if effect == 'staging' and mission.get('completion_target_ref') is None:
                if cleanup_ref is not None:
                    raise MissionRefusal('effect closure has foreign final staging cleanup')
                continue
            if cleanup_ref is None:
                raise MissionRefusal('effect closure omits completion '+effect+' cleanup')
            proof = _read_mission_json(tower, cleanup_ref, limit=_MAX_HOST_OBSERVATION_BYTES)
            validate_completion_cleanup(proof, mission, effect)
            _require_root_custody(tower, cleanup_ref, frozen, proof['schema'])
    starts = [intent for intent in mission['receiver_intents'].values()
              if intent['request']['operation'] == 'start']
    if starts:
        retained = [intent for intent in mission['receiver_intents'].values()
                    if intent['request_ref'] == value['worker_request_ref']
                    and intent['request']['operation'] in ('status', 'cancel', 'collect')]
        if len(retained) != 1 or value['worker_cleanup_ref'] is None:
            raise MissionRefusal('effect closure has no original worker readback')
        proof = _read_mission_json(tower, value['worker_cleanup_ref'], limit=_MAX_HOST_OBSERVATION_BYTES)
        validate_worker_cleanup(proof, frozen, retained[0]['request'])
        _require_root_custody(tower, value['worker_cleanup_ref'], frozen, proof['schema'])
        if value['worker_request_ref'] not in tower.artifacts.record(value['worker_cleanup_ref'])['source_lineage']:
            raise MissionRefusal('worker cleanup lineage is unavailable')
    elif value['worker_request_ref'] is not None or value['worker_cleanup_ref'] is not None:
        raise MissionRefusal('unstarted mission has foreign worker cleanup')
    for effect, contract in _EFFECT_CLEANUP_CONTRACTS.items():
        original_ref = mission.get(effect+'_intent_ref')
        cleanup_ref = value[effect+'_cleanup_ref']
        if original_ref is None:
            if value[effect+'_intent_ref'] is not None or cleanup_ref is not None:
                raise MissionRefusal('effect closure has foreign '+effect+' cleanup')
            continue
        if value[effect+'_intent_ref'] != original_ref or cleanup_ref is None:
            raise MissionRefusal('effect closure omits original '+effect+' cleanup')
        request = contract.request(mission[effect+'_intent'])
        proof = _read_mission_json(tower, cleanup_ref, limit=_MAX_HOST_OBSERVATION_BYTES)
        original_status = (mission.get(effect+'_observation') or {}).get('status')
        contract.validate(proof, request, original_status=original_status)
        _require_root_custody(tower, cleanup_ref, frozen, contract.schema)
        if original_ref not in tower.artifacts.record(cleanup_ref)['source_lineage']:
            raise MissionRefusal(effect+' cleanup lineage is unavailable')
    return value


def worker_terminal_state(mission):
    """The canonical receiver-to-capacity terminal state; one mapping for all callers."""
    state = mission['receiver_state']
    if state == 'CANDIDATE_READY':
        return 'completed'
    if state in ('FAILED', 'REJECTED', 'TIMED_OUT'):
        return 'failed'
    # A cancelled, unstarted or ambiguous worker can release only after the
    # independently bound effect closure below proves cessation/no effect.
    return 'cancelled'


def _read_worker_release_request(tower, mission, ref, *, current=None):
    import orch_dork_shared_capacity as capacity
    frozen = mission['freeze']
    if frozen['schema'] != FREEZE_SCHEMA_V2:
        raise MissionRefusal('separate worker release requires a fixed batch mission')
    request = _read_mission_json(tower, ref)
    schema = 'orch-dork/mission-worker-release-request/v1'
    _require_shape(request, ('schema', 'mission_id', 'ownership_generation', 'terminal_state',
                            'terminal_evidence_ref', 'release_receipt_ref'), 'worker release request')
    terminal = worker_terminal_state(mission)
    if (request['schema'] != schema or request['mission_id'] != frozen['mission_id']
            or type(request['ownership_generation']) is not int
            or request['ownership_generation'] != frozen['ownership_generation']
            or request['terminal_state'] != terminal):
        raise MissionRefusal('worker release does not bind its original terminal state')
    _require_root_custody(tower, ref, frozen, schema)
    closure_ref, receipt_ref = request['terminal_evidence_ref'], request['release_receipt_ref']
    closure = _read_mission_json(tower, closure_ref)
    responses = sorted([row['response_ref'] for row in mission['receiver_intents'].values()
                        if 'response_ref' in row], key=lambda item: item['sha256'])
    expected = {'schema': 'orch-dork/mission-worker-closure/v1', 'mission_id': frozen['mission_id'],
        'ownership_generation': frozen['ownership_generation'], 'terminal_state': terminal,
        'frozen_mission_ref': mission['frozen_mission_ref'], 'receiver_response_refs': responses,
        'candidate_ref': mission.get('candidate_ref'), 'effect_closure_ref': closure.get('effect_closure_ref')}
    _require_shape(closure, expected, 'worker terminal closure')
    if closure != expected or expected['effect_closure_ref'] is None:
        raise MissionRefusal('worker release has no exact original closure')
    _read_effect_closure(tower, mission, expected['effect_closure_ref'], current=current)
    _require_root_custody(tower, closure_ref, frozen, expected['schema'])
    parents = [mission['frozen_mission_ref'], *responses, expected['effect_closure_ref']]
    if mission.get('candidate_ref') is not None:
        parents.append(mission['candidate_ref'])
    if any(parent not in tower.artifacts.record(closure_ref)['source_lineage'] for parent in parents):
        raise MissionRefusal('worker closure lineage is unavailable')
    receipt = _read_mission_json(tower, receipt_ref)
    if (not capacity.validate_release_receipt(receipt, lane_id=frozen['capacity_lane_id'],
            run_id=frozen['run_id'], route=MISSION_CAPACITY_ROUTE, terminal_state=terminal)
            or receipt['terminal_evidence_sha256'] != closure_ref['sha256']):
        raise MissionRefusal('worker release receipt does not bind its original closure')
    _require_root_custody(tower, receipt_ref, frozen, capacity.RELEASE_SCHEMA)
    if (closure_ref not in tower.artifacts.record(receipt_ref)['source_lineage']
            or any(parent not in tower.artifacts.record(ref)['source_lineage']
                   for parent in (closure_ref, receipt_ref))):
        raise MissionRefusal('worker release request lineage is unavailable')
    return request, receipt


def _apply_worker_release_intent(tower, state, payload):
    mission = _claimed_mission(state, payload)
    if (mission['claim_state'] != 'HELD' or 'settlement_intent' in mission
            or 'worker_release_intent' in mission or 'verification_intent' in mission
            or 'publication_intent' in mission):
        raise MissionRefusal('worker release requires its original unfinished worker phase')
    request, _receipt = _read_worker_release_request(tower, mission, payload['request_ref'], current=state)
    mission.update(worker_release_intent=request, worker_release_intent_ref=payload['request_ref'])


def _apply_worker_release_observation(tower, state, payload):
    mission = _claimed_mission(state, payload)
    if ('worker_release_intent' not in mission or 'worker_release_observation_ref' in mission
            or mission['claim_state'] != 'HELD' or 'settlement_intent' in mission):
        raise MissionRefusal('worker release observation has no pending held mission')
    ref = payload['evidence_ref']
    value = _read_mission_json(tower, ref)
    expected = {'schema': 'orch-dork/mission-worker-release-observation/v1',
                'mission_id': payload['mission_id'],
                'worker_release_intent_ref': mission['worker_release_intent_ref']}
    _require_shape(value, (*expected, 'capacity_state_sha256'), 'worker release observation')
    if (any(value[key] != item for key, item in expected.items())
            or type(value['capacity_state_sha256']) is not str
            or not _SHA.fullmatch(value['capacity_state_sha256'])):
        raise MissionRefusal('worker release observation does not bind its intent')
    _require_root_custody(tower, ref, mission['freeze'], expected['schema'])
    if mission['worker_release_intent_ref'] not in tower.artifacts.record(ref)['source_lineage']:
        raise MissionRefusal('worker release observation lineage is unavailable')
    mission.update(worker_release_observation_ref=ref, worker_released_capacity_sha256=value['capacity_state_sha256'])


def _require_completion_capacity(authority, mission):
    if 'settlement_intent' in mission:
        raise MissionRefusal('settlement closes all mission creation')
    if 'worker_release_intent' not in mission:
        return _require_creation_capacity(authority, mission)
    if 'worker_release_observation_ref' not in mission:
        raise MissionRefusal('worker release is not independently observed')
    receipt = _read_mission_json(authority.tower, mission['worker_release_intent']['release_receipt_ref'])
    return authority._require_capacity_binding(mission['freeze'], released_receipt=receipt)


def _prepare_completion_claim_capacity(authority, current, payload):
    return _require_completion_capacity(authority, _claimed_mission(current, payload))


def _prepare_worker_release_observation(authority, current, payload):
    return authority._require_retained_release(current, payload, 'worker_release_intent')


def _read_settlement_request(tower, mission, ref, *, current=None):
    import orch_dork_shared_capacity as capacity
    frozen = mission["freeze"]
    request = _read_mission_json(tower, ref)
    separate_worker_release = 'worker_release_intent' in mission
    schema = ('orch-dork/mission-settlement-request/v2' if separate_worker_release
              else 'orch-dork/mission-settlement-request/v1')
    fields = ('schema', 'mission_id', 'ownership_generation', 'outcome',
              'terminal_evidence_ref', 'release_receipt_ref')
    if separate_worker_release:
        fields += ('worker_release_observation_ref',)
    _require_shape(request, fields, 'settlement request')
    if separate_worker_release and (
            mission.get('worker_release_observation_ref') is None
            or request['worker_release_observation_ref'] != mission['worker_release_observation_ref']
            or request['release_receipt_ref'] != mission['worker_release_intent']['release_receipt_ref']):
        raise MissionRefusal('settlement does not bind the original observed worker release')
    if (request["schema"] != schema or request["mission_id"] != frozen["mission_id"] or
            type(request["ownership_generation"]) is not int or
            request["ownership_generation"] != frozen["ownership_generation"]):
        raise MissionRefusal("settlement request does not bind its mission")
    _require_root_custody(tower, ref, frozen, schema)
    closure_ref, receipt_ref = request["terminal_evidence_ref"], request["release_receipt_ref"]
    closure = _read_mission_json(tower, closure_ref, limit=_MAX_HOST_OBSERVATION_BYTES)
    responses = sorted([intent["response_ref"] for intent in mission["receiver_intents"].values()
                        if "response_ref" in intent], key=lambda item: item["sha256"])
    expected = {"schema": closure.get("schema"), "mission_id": frozen["mission_id"],
                "ownership_generation": frozen["ownership_generation"], "outcome": request["outcome"],
                "frozen_mission_ref": mission["frozen_mission_ref"], "receiver_response_refs": responses,
                "verification_observation_ref": mission.get("verification_observation_ref"),
                "publication_observation_ref": mission.get("publication_observation_ref")}
    if (frozen['schema'] == FREEZE_SCHEMA_V2 and 'completion' in mission
            and expected['schema'] != 'orch-dork/mission-closure/v2'):
        # Completion owns target-read/staging effects even when the worker
        # was not released early. The legacy worker receipt cannot prove
        # those effects ceased or release their repository completion slot.
        raise MissionRefusal('completion settlement requires full mission effect closure')
    effect_closure = None
    if expected['schema'] == 'orch-dork/mission-closure/v2':
        _require_shape(closure, (*expected, 'effect_closure_ref'), 'settlement closure')
        expected['effect_closure_ref'] = closure.get('effect_closure_ref')
        if expected['effect_closure_ref'] is None:
            raise MissionRefusal('settlement closure has no effect closure reference')
        effect_closure = _read_effect_closure(tower, mission, expected['effect_closure_ref'], current=current)
    elif expected['schema'] != 'orch-dork/mission-closure/v1':
        raise MissionRefusal('unsupported settlement closure')
    completion_failed = False
    if effect_closure is not None and effect_closure['schema'] == 'orch-dork/mission-effect-closure/v2':
        # These original readbacks were validated above against their exact
        # completion operations. A known refusal/failure can settle FAILED;
        # physical cessation of UNKNOWN supplies no failure or acceptance.
        for name in ('completion_target_cleanup_ref', 'final_staging_cleanup_ref'):
            cleanup_ref = effect_closure[name]
            if cleanup_ref is not None:
                cleanup = _read_mission_json(tower, cleanup_ref, limit=_MAX_HOST_OBSERVATION_BYTES)
                completion_failed |= cleanup['original_status'] in ('REFUSED', 'FAILED')
    _settlement_outcome(mission, request['outcome'], effect_closure, completion_failed=completion_failed)
    if closure != expected:
        raise MissionRefusal("settlement closure does not bind retained evidence")
    _require_root_custody(tower, closure_ref, frozen, expected["schema"])
    required_lineage = [mission["frozen_mission_ref"], *responses]
    required_lineage += [parent for parent in (mission.get("verification_observation_ref"),
                         mission.get("publication_observation_ref")) if parent is not None]
    if any(parent not in tower.artifacts.record(closure_ref)["source_lineage"] for parent in required_lineage):
        raise MissionRefusal("settlement closure lineage is unavailable")
    if effect_closure is not None and expected['effect_closure_ref'] not in tower.artifacts.record(closure_ref)['source_lineage']:
        raise MissionRefusal('settlement effect-closure lineage is unavailable')
    receipt = _read_mission_json(tower, receipt_ref)
    # Worker cleanup and full mission settlement are different facts. The
    # already signed worker receipt retains its exact terminal state/closure;
    # a later failed or stopped completion cannot replace or re-sign it.
    receipt_closure_ref = (mission['worker_release_intent']['terminal_evidence_ref']
                           if separate_worker_release else closure_ref)
    receipt_terminal = (mission['worker_release_intent']['terminal_state']
                        if separate_worker_release else _SETTLEMENT_STATES[request['outcome']])
    if (not capacity.validate_release_receipt(receipt, lane_id=frozen['capacity_lane_id'],
            run_id=frozen['run_id'], route=MISSION_CAPACITY_ROUTE, terminal_state=receipt_terminal)
            or receipt['terminal_evidence_sha256'] != receipt_closure_ref['sha256']):
        raise MissionRefusal('settlement release receipt does not bind its closure')
    _require_root_custody(tower, receipt_ref, frozen, capacity.RELEASE_SCHEMA)
    request_parents = [closure_ref, receipt_ref]
    if separate_worker_release:
        if effect_closure is None:
            raise MissionRefusal('separate worker release requires full mission effect closure')
        request_parents.append(mission['worker_release_observation_ref'])
    if (receipt_closure_ref not in tower.artifacts.record(receipt_ref)['source_lineage']
            or any(parent not in tower.artifacts.record(ref)['source_lineage'] for parent in request_parents)):
        raise MissionRefusal('settlement request lineage is unavailable')
    return request, receipt


def _apply_settlement_intent(tower, state, payload):
    mission = state["missions"].get(payload["mission_id"])
    if mission is None or mission.get("claim_state") != "HELD":
        raise MissionRefusal("settlement has no held mission claim")
    if "settlement_intent" in mission:
        raise MissionRefusal("settlement intent is already retained")
    request, _receipt = _read_settlement_request(tower, mission, payload["request_ref"], current=state)
    mission.update(settlement_intent=request, settlement_intent_ref=payload["request_ref"],
                   status="SETTLEMENT_PENDING")


def _apply_settlement_observation(tower, state, payload):
    mission = state["missions"].get(payload["mission_id"])
    if mission is None or "settlement_intent" not in mission or mission.get("claim_state") != "HELD":
        raise MissionRefusal("settlement observation has no pending held claim")
    ref = payload["evidence_ref"]
    value = _read_mission_json(tower, ref)
    expected = {"schema": "orch-dork/mission-settlement-observation/v1", "mission_id": payload["mission_id"],
                "settlement_intent_ref": mission["settlement_intent_ref"]}
    _require_shape(value, (*expected, "capacity_state_sha256"), "settlement observation")
    if (any(value[key] != item for key, item in expected.items()) or
            type(value["capacity_state_sha256"]) is not str or not _SHA.fullmatch(value["capacity_state_sha256"])):
        raise MissionRefusal("settlement observation does not bind its intent")
    _require_root_custody(tower, ref, mission["freeze"], expected["schema"])
    if mission["settlement_intent_ref"] not in tower.artifacts.record(ref)["source_lineage"]:
        raise MissionRefusal("settlement observation lineage is unavailable")
    if mission['freeze']['schema'] == FREEZE_SCHEMA_V2 and 'completion' in mission:
        mission['completion']['state'] = 'RELEASED'
    mission.update(status=mission["settlement_intent"]["outcome"], claim_state="RELEASED",
                   settlement_observation_ref=ref, settled_capacity_sha256=value["capacity_state_sha256"])


def _reduce_pool(tower, state, payload):
    _apply_pool(state, payload)


def _reduce_source(tower, state, payload):
    _apply_source(state, payload)


def _reduce_admission(tower, state, payload, capacity_sha, frozen):
    _apply_admission(state, frozen, payload["frozen_mission_ref"], capacity_sha)


def _prepare_admission_capacity(authority, _current, _payload, frozen):
    """Rule preparers share this arity; admission consumes the prepared freeze."""
    digest = authority._require_capacity_binding(frozen)
    authority._require_unclaimed_capacity(frozen['capacity_lane_id'])
    _validate_planned_workspace(frozen['workspace'])
    return digest


def _claimed_mission(current, payload):
    mission = current['missions'].get(payload['mission_id'])
    if mission is None:
        raise MissionRefusal('creation mission claim is unavailable')
    return mission


def _require_creation_capacity(authority, mission):
    if 'worker_release_intent' in mission:
        raise MissionRefusal('worker release closes worker creation')
    if 'settlement_intent' in mission:
        raise MissionRefusal('mission is settling or settled; creation is closed')
    return authority._require_capacity_binding(mission['freeze'])


def _prepare_creation_capacity(authority, current, payload):
    return _require_creation_capacity(authority, _claimed_mission(current, payload))


def _prepare_final_capacity(authority, current, payload):
    mission = _claimed_mission(current, payload)
    if mission['freeze']['schema'] == FREEZE_SCHEMA_V2:
        _require_completion(current, mission)
    return _require_completion_capacity(authority, mission)


def _prepare_settlement_capacity(authority, current, payload):
    return _require_completion_capacity(authority, _claimed_mission(current, payload))


def _prepare_receiver_capacity(authority, current, payload, request):
    mission = _claimed_mission(current, payload)
    if request['operation'] not in ('start', 'follow_up'):
        return mission['capacity_sha256']
    return _prepare_creation_capacity(authority, current, payload)


def _prepare_release_capacity(authority, current, payload):
    return authority._require_settlement_release(current, payload)


def _validate_recorded_capacity(_tower, _payload, evidence, key):
    digest = evidence[key]
    if not isinstance(digest, str) or not _SHA.fullmatch(digest):
        raise MissionRefusal('invalid mission capacity evidence')


def _validate_recorded_release(tower, payload, evidence, key):
    _validate_recorded_capacity(tower, payload, evidence, key)
    value = _read_mission_json(tower, payload['evidence_ref'])
    if evidence[key] != value.get('capacity_state_sha256'):
        raise MissionRefusal('invalid committed mission capacity release evidence')


def _initialize_capacity(authority):
    # Initialize before another stream's checked transaction. This early read
    # grants no reservation; admission accepts only its later checked binding.
    authority.tower.read_shared_capacity_authority()


@dataclass(frozen=True)
class _EvidenceRule:
    key: str
    prepare: object
    validate: object = _validate_recorded_capacity
    initialize: object = None


def _admission_material(tower, _current, payload):
    return (_read_freeze(tower, payload['frozen_mission_ref']),)


def _receiver_material(tower, current, payload):
    return (_read_worker_request(tower, _claimed_mission(current, payload), payload['request_ref']),)


@dataclass(frozen=True)
class _TransitionRule:
    reducer: object
    payload_fields: tuple
    identities: tuple = ()
    payload_validator: object = None
    evidence: _EvidenceRule | None = None
    reducer_evidence: tuple = ()
    material_reader: object = None

    def read_material(self, tower, current, payload):
        return () if self.material_reader is None else self.material_reader(tower, current, payload)


_MISSION_IDENTITY = (('mission_id', _ID),)
_RECEIVER_KEY = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z')
_EFFECT_IDENTITIES = (*_MISSION_IDENTITY, ('idempotency_key', _ID))
_CREATION_CAPACITY = _EvidenceRule('mission_capacity', _prepare_creation_capacity)
_FINAL_CAPACITY = _EvidenceRule('mission_capacity', _prepare_final_capacity)
_TRANSITION_RULES = {
    'observe_pool': _TransitionRule(_reduce_pool, ('observation_id', 'ledger_sha256', 'tickets'), payload_validator=_validate_pool_payload),
    'observe_source': _TransitionRule(_reduce_source, ('observation_id', 'ledger_sha256', 'source_version', 'sequence', 'observed_at', 'tickets'), payload_validator=_validate_source_payload),
    'admit': _TransitionRule(_reduce_admission, ('frozen_mission_ref',), reducer_evidence=('mission_capacity',), evidence=_EvidenceRule('mission_capacity', _prepare_admission_capacity, initialize=_initialize_capacity), material_reader=_admission_material),
    'receiver_intent': _TransitionRule(_apply_receiver_intent, ('mission_id', 'request_ref'), _MISSION_IDENTITY, evidence=_EvidenceRule('mission_capacity', _prepare_receiver_capacity), material_reader=_receiver_material),
    'receiver_observation': _TransitionRule(_apply_receiver_observation, ('mission_id', 'idempotency_key', 'response_ref'), (*_MISSION_IDENTITY, ('idempotency_key', _RECEIVER_KEY))),
    'completion_claim': _TransitionRule(_apply_completion_claim, ('mission_id', 'completion_id'), (*_MISSION_IDENTITY, ('completion_id', _ID)), evidence=_EvidenceRule('mission_capacity', _prepare_completion_claim_capacity)),
    'completion_target': _TransitionRule(_apply_completion_target, ('mission_id', 'target_observation_ref'), _MISSION_IDENTITY, evidence=_FINAL_CAPACITY),
    'completion_seal': _TransitionRule(_apply_completion_seal, ('mission_id', 'candidate_ref'), _MISSION_IDENTITY, evidence=_FINAL_CAPACITY),
    'candidate_seal': _TransitionRule(_apply_candidate_seal, ('mission_id', 'candidate_ref'), _MISSION_IDENTITY, evidence=_CREATION_CAPACITY),
    'verification_intent': _TransitionRule(_apply_verification_intent, ('mission_id', 'request_ref'), _MISSION_IDENTITY, evidence=_FINAL_CAPACITY),
    'verification_observation': _TransitionRule(_apply_verification_observation, ('mission_id', 'idempotency_key', 'evidence_ref'), _EFFECT_IDENTITIES),
    'publication_intent': _TransitionRule(_apply_publication_intent, ('mission_id', 'request_ref'), _MISSION_IDENTITY, evidence=_FINAL_CAPACITY),
    'publication_observation': _TransitionRule(_apply_publication_observation, ('mission_id', 'idempotency_key', 'evidence_ref'), _EFFECT_IDENTITIES),
    'worker_release_intent': _TransitionRule(_apply_worker_release_intent, ('mission_id', 'request_ref'), _MISSION_IDENTITY, evidence=_CREATION_CAPACITY),
    'worker_release_observation': _TransitionRule(_apply_worker_release_observation, ('mission_id', 'evidence_ref'), _MISSION_IDENTITY, evidence=_EvidenceRule('mission_capacity_release', _prepare_worker_release_observation, _validate_recorded_release)),
    'settlement_intent': _TransitionRule(_apply_settlement_intent, ('mission_id', 'request_ref'), _MISSION_IDENTITY, evidence=_EvidenceRule('mission_capacity', _prepare_settlement_capacity)),
    'settlement_observation': _TransitionRule(_apply_settlement_observation, ('mission_id', 'evidence_ref'), _MISSION_IDENTITY, evidence=_EvidenceRule('mission_capacity_release', _prepare_release_capacity, _validate_recorded_release)),
}


def _reduce_transition(tower, state, transition, evidence, *, material=None):
    """Apply the same explicit handler and evidence check on write and read."""
    kind = transition["kind"]
    rule = _TRANSITION_RULES.get(kind)
    if rule is None:
        raise MissionRefusal("unsupported mission transition")
    if rule.evidence is not None:
        rule.evidence.validate(tower, transition['payload'], evidence, rule.evidence.key)
    if material is None:
        material = rule.read_material(tower, state, transition['payload'])
    rule.reducer(tower, state, transition['payload'],
                 *[evidence[key] for key in rule.reducer_evidence], *material)


def _coordination_plan(run_id, repository):
    return run_engine.make_plan(
        run_id, "Repository mission coordination", ("mission",),
        deliverable=False,
        actors=(run_engine.actor("observer", "deterministic-missions/v1",
                                 "mission", "coordinate:missions/v1"),),
        origin={"mission_authority": {"schema": SCHEMA,
                                      "repository": repository}},
    )


class MissionAuthority:
    """One host repository's typed facts in the existing canonical store."""

    def __init__(self, tower, repository):
        if not getattr(tower.store, "durable", False):
            raise MissionRefusal("mission authority requires the durable run store")
        self.tower = tower
        path = Path(repository).resolve(strict=True)
        if not path.is_dir():
            raise MissionRefusal("repository common directory is unavailable")
        observed = path.stat()
        self.repository = {"path": str(path), "device": observed.st_dev,
                           "inode": observed.st_ino}
        # A move must find the existing owner and refuse the changed binding,
        # rather than opening an unclaimed stream at the new pathname.
        self.run_id = "ctmission-" + _sha({"device": observed.st_dev,
                                          "inode": observed.st_ino})
        self.plan = _coordination_plan(self.run_id, self.repository)

    def initialize(self):
        """Explicit host mutation creating the repository coordination run.

        A retained anchor proves this repository's authority existed. If the
        store no longer holds that history, initialization quarantines instead
        of constructing an empty authority that could relaunch work.
        """
        if not self.tower.store.exists(self.run_id):
            if self.anchor_retained():
                raise MissionRefusal("mission authority history is missing but its anchor is "
                                     "retained; quarantine and reconcile receivers")
            try:
                self.tower.engine.start(self.plan)
            except run_engine.ProtocolError:
                if not self.tower.store.exists(self.run_id):
                    raise
        self._publish_anchor()
        return self.read()

    def _anchor_body(self):
        return canonical_text({"schema": ANCHOR_SCHEMA, "run_id": self.run_id,
                               "repository": {"device": self.repository["device"],
                                              "inode": self.repository["inode"]}})

    def anchor_retained(self):
        """Whether the independent artifact ledger retains this authority's anchor."""
        ref = artifact_ledger.project_artifact_ref(self._anchor_body(), media_type="application/json")
        try:
            self.tower.artifacts.read(ref)
        except KeyError:
            return False
        return True

    def _publish_anchor(self):
        body = self._anchor_body()
        digest = hashlib.sha256(body.encode()).hexdigest()
        self.tower.artifacts.publish(body, media_type="application/json", provenance={
            "producer_run_id": self.run_id, "producer_node_id": "root", "task_spec_sha256": digest,
            "content_schema": ANCHOR_SCHEMA, "privacy_class": "local_only",
            "custody_receipt_sha256": digest, "source_lineage": [], "consumer_node_ids": ["mission"],
            "retention_state": "retained_evidence"})

    def read(self):
        if not self.tower.store.exists(self.run_id):
            raise MissionRefusal("mission authority is not initialized")
        return self._read_history(self.repository, self.run_id)

    def read_verified_settlement(self, mission_id, *, run_id, ticket_id, root_task_id):
        """Read an exact verified, released mission; confer no tracker-write authority.

        The caller keeps its durable authorization guard through any subsequent
        effect. This reader also refuses other retained claims in this repository.
        Historical capacity readback validates the original signed release even
        when another repository has since advanced the shared capacity stream.
        """
        state = self.read()
        mission = state['missions'].get(mission_id)
        if mission is None:
            raise MissionRefusal('tracker has no named canonical mission')
        frozen = mission['freeze']
        if (frozen['run_id'] != run_id or frozen['ticket_id'] != ticket_id or
                not is_run_owner(self.tower, frozen, root_task_id)):
            raise MissionRefusal('tracker does not bind the frozen run, ticket and Root')
        ticket = (state.get('pool') or {}).get('tickets', {}).get(ticket_id)
        if ticket is None or ticket['revision_sha256'] != frozen['revision_sha256']:
            raise MissionRefusal('tracker mission no longer matches the current ticket revision')
        if any(item['claim_state'] != 'RELEASED' for item in state['missions'].values()):
            raise MissionRefusal('tracker repository still has a retained mission claim')
        if (mission['status'] not in ('VERIFIED', 'LANDED') or
                mission.get('verification_observation', {}).get('status') != 'VERIFIED' or
                'candidate' not in mission or 'settlement_observation_ref' not in mission):
            raise MissionRefusal('tracker mission has no verified canonical settlement')
        receipt = _read_mission_json(self.tower, mission['settlement_intent']['release_receipt_ref'])
        released = self.tower.read_shared_capacity_release(receipt)
        if (released['status'] != 'RELEASED' or
                released['receipt_sha256'] != receipt['receipt_sha256']):
            raise MissionRefusal('tracker exact signed capacity release is not committed')
        return state, mission

    def _read_history(self, repository, run_id):
        events = list(self.tower.engine.events(run_id))
        started = json.loads(events[0]["payload"])
        if started["plan_sha256"] != _sha(run_engine.plan_core(_coordination_plan(run_id, repository))):
            raise MissionRefusal("repository coordination plan changed")
        state = {"schema": SCHEMA, "run_id": run_id,
                 "repository": deepcopy(repository), "generation": 0,
                 "pool": None, "missions": {}, "operations": {},
                 "observations": {}}
        for event in events[1:]:
            if event["kind"] != "applied" or event["actor_key"] != "mission":
                raise MissionRefusal("invalid mission fact kind or actor")
            facts = json.loads(event["payload"])
            _require_shape(facts, ("roles", "status", "deliverables", "evidence"),
                           "mission fact")
            if facts["roles"] != ["mission"] or facts["status"] != "SUCCESS":
                raise MissionRefusal("invalid mission fact roles or status")
            _require_shape(facts["deliverables"], ("mission_transition",),
                           "mission deliverable")
            transition = _validate_transition(json.loads(
                facts["deliverables"]["mission_transition"]))
            evidence_fields = {"mission_transition"}
            rule = _TRANSITION_RULES[transition['kind']]
            if rule.evidence is not None:
                evidence_fields.add(rule.evidence.key)
            _require_shape(facts["evidence"], evidence_fields, "mission evidence")
            digest = _sha(transition)
            if facts["evidence"]["mission_transition"] != digest:
                raise MissionRefusal("mission evidence does not bind its fact")
            if (transition["expected_generation"] != state["generation"] or
                    transition["expected_seq"] != event["seq"] - 1 or
                    transition["expected_prev_hash"] != event["prev_hash"]):
                raise MissionRefusal("mission fact violates its expected history")
            operation_id = transition["operation_id"]
            if operation_id in state["operations"]:
                raise MissionRefusal("duplicate durable mission operation")
            # Reduction sees the same predecessor cursor as a checked write.
            state.update(seq=event["seq"] - 1, event_hash=event["prev_hash"])
            _reduce_transition(self.tower, state, transition, facts["evidence"])
            state["generation"] += 1
            state["operations"][operation_id] = digest
        state["seq"] = events[-1]["seq"]
        state["event_hash"] = events[-1]["event_hash"]
        return state

    def _require_unclaimed_capacity(self, lane_id):
        # The same durable store transaction serializes every repository claim.
        # Inspect canonical histories, including relocated repositories, instead
        # of maintaining a second mutable index of lane owners.
        streams = [identity for identity in self.tower.store.run_ids()
                   if identity.startswith("ctmission-")]
        if len(streams) > 512:
            raise MissionRefusal("mission capacity ownership census is unbounded")
        for identity in streams:
            events = list(self.tower.engine.events(identity))
            try:
                binding = json.loads(events[0]["payload"])["plan"]["origin"][
                    "mission_authority"]
                _require_shape(binding, ("schema", "repository"), "mission binding")
                repository = binding["repository"]
                _require_shape(repository, ("path", "device", "inode"), "repository")
                if (binding["schema"] != SCHEMA or
                        not isinstance(repository["path"], str) or
                        not is_canonical_absolute_path(repository["path"]) or
                        any(type(repository[field]) is not int or repository[field] < 0
                            for field in ("device", "inode")) or
                        identity != "ctmission-" + _sha({
                            "device": repository["device"], "inode": repository["inode"]})):
                    raise MissionRefusal("invalid canonical repository binding")
                history = self._read_history(repository, identity)
            except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
                raise MissionRefusal("mission capacity ownership is unknown") from error
            for mission in history["missions"].values():
                if mission["freeze"]["capacity_lane_id"] == lane_id:
                    raise MissionRefusal("mission capacity is already claimed")

    def _require_capacity_binding(self, frozen, *, released_receipt=None):
        try:
            authority = self.tower.read_shared_capacity_authority()
            if authority["status"] != "VERIFIED":
                raise MissionRefusal("canonical capacity is unavailable")
            state = authority["state"]
            if released_receipt is not None:
                released = self.tower.read_shared_capacity_release(released_receipt)
                if (released['status'] != 'RELEASED'
                        or released['receipt_sha256'] != released_receipt['receipt_sha256']
                        or released['state_sha256'] != authority['state_sha256']):
                    raise MissionRefusal('original worker release is not committed in current capacity')
            lane = state["identity_ledger"]["entries"]
            matching = [entry for entry in lane
                        if entry["lane_id"] == frozen["capacity_lane_id"]]
            run = next((run for run in state["runs"]
                        if run["run_id"] == frozen["run_id"]), None)
            active = frozen["capacity_lane_id"] in state["active_lane_ids"]
            if (active != (released_receipt is None) or
                    len(matching) != 1 or matching[0]["run_id"] != frozen["run_id"] or
                    matching[0]["route"] != MISSION_CAPACITY_ROUTE or run is None or
                    not is_run_owner(self.tower, frozen, run['root_thread_id']) or
                    run["plan_revisions"][-1]["plan_sha256"] != frozen["plan_sha256"] or
                    self.tower.engine.run(frozen["run_id"])["plan_sha256"] !=
                    frozen["plan_sha256"]):
                raise MissionRefusal("mission does not own its canonical capacity")
            return authority["state_sha256"]
        except (run_engine.NotFoundError, run_engine.RunKernelError, KeyError,
                IndexError, TypeError) as error:
            raise MissionRefusal("canonical capacity binding is unavailable") from error

    def check_completion(self, mission_id):
        """Read current final-effect ownership; never acquire or release a slot."""
        current = self.read()
        mission = _claimed_mission(current, {'mission_id': mission_id})
        _require_completion(current, mission)
        _require_completion_capacity(self, mission)
        return current

    def check_creation(self, mission_id):
        """Read current typed state and re-validate the canonical authority.

        The composed Root host calls this before its actual verifier,
        containment and Git join so it can reuse the same canonical
        capacity check the admission recorded instead of duplicating the
        lane, run, plan and root-model validation. This method performs
        no writes, no transition and confers no permission; it only
        returns the current state when the existing claim, the current
        ready revision and the canonical capacity binding still match.
        The Root host must still observe physical creation, target write
        and containment separately. Refusals here are observed and
        historical; they do not release the claim or capacity.
        """
        current = self.read()
        mission = current["missions"].get(mission_id)
        if mission is None:
            raise MissionRefusal("creation check has no claimed mission")
        frozen = mission["freeze"]
        if not _matches_current_ready_revision(current, frozen):
            raise MissionRefusal("creation check no longer matches the current ready revision")
        # Reuse the same _require_capacity_binding gate the admission and
        # the verify-time intent recorded. The full root/plan/run/lane
        # validation lives there; the Root host does not need to copy it.
        _require_creation_capacity(self, mission)
        return current

    def _require_settlement_release(self, current, payload):
        return self._require_retained_release(current, payload, 'settlement_intent')

    def _require_retained_release(self, current, payload, intent_name):
        mission = current["missions"].get(payload["mission_id"])
        if mission is None or intent_name not in mission:
            raise MissionRefusal("capacity release has no pending original intent")
        request = mission[intent_name]
        receipt = _read_mission_json(self.tower, request["release_receipt_ref"])
        observed = self.tower.read_shared_capacity_release(receipt)
        value = _read_mission_json(self.tower, payload["evidence_ref"])
        if (observed["status"] != "RELEASED" or observed["receipt_sha256"] != receipt["receipt_sha256"] or
                observed["state_sha256"] != value.get("capacity_state_sha256")):
            raise MissionRefusal("exact signed capacity release is not committed")
        return observed["state_sha256"]

    def transition(self, value):
        transition = _validate_transition(value)
        digest = _sha(transition)
        current = self.read()
        operation_id = transition["operation_id"]
        if operation_id in current["operations"]:
            if current["operations"][operation_id] != digest:
                raise MissionRefusal("mission operation identity was reused")
            return current
        rule = _TRANSITION_RULES[transition['kind']]
        if rule.evidence is not None and rule.evidence.initialize is not None:
            rule.evidence.initialize(self)

        def build():
            current = self.read()
            if transition["expected_generation"] != current["generation"]:
                raise MissionRefusal("mission generation changed")
            evidence = {"mission_transition": digest}
            rule = _TRANSITION_RULES[transition['kind']]
            material = rule.read_material(self.tower, current, transition['payload'])
            if rule.evidence is not None:
                evidence[rule.evidence.key] = rule.evidence.prepare(self, current, transition['payload'], *material)
            _reduce_transition(self.tower, current, transition, evidence, material=material)
            return {"roles": ["mission"], "status": "SUCCESS",
                    "deliverables": {"mission_transition": _canonical(transition)},
                    "evidence": evidence}

        self.tower.engine.append_event_checked(
            self.run_id, "applied", "mission", build,
            expected_seq=transition["expected_seq"],
            expected_prev_hash=transition["expected_prev_hash"],
        )
        return self.read()
