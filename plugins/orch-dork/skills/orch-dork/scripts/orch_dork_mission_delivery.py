"""Current canonical permission held through one local publication effect.

The receiver retains and reconciles its own original operation. This adapter
supplies the canonical store's held descriptors; it does not infer cessation,
release claims/capacity, confirm a tracker edit or replace an unknown operation.
The canonical publication intent and protected observation are prerequisites.
Same-UID advisory exclusion requires the worker/verifier containment boundary
to deny access to the store, its metadata and publication custody.
"""
from contextlib import ExitStack, contextmanager
from dataclasses import asdict

from orch_dork_mission_authority import (MissionAuthority, MissionRefusal,
    is_run_owner, expected_publication_binding, FREEZE_SCHEMA_V2)
from orch_dork_mission_publication import (
    HeldAuthorization, PublicationRequest, PublicationRefusal, SCHEMA,
)
from orch_dork_run_store import StoreError


class MissionDeliveryRefusal(PublicationRefusal):
    """Current canonical publication permission cannot be established."""


def _check_publication(tower, repository, request, requesting_task_id):
    if type(request) is not PublicationRequest:
        raise MissionDeliveryRefusal('publication request must have the closed type')
    request.validate()
    canonical = MissionAuthority(tower, repository)
    observed = canonical.read()
    mission = observed['missions'].get(request.mission_id)
    if mission is None:
        raise MissionDeliveryRefusal('publication mission claim is unavailable')
    if mission['freeze']['schema'] == FREEZE_SCHEMA_V2:
        current = canonical.check_completion(request.mission_id)
    else:
        current = canonical.check_creation(request.mission_id)
    mission = current['missions'].get(request.mission_id)
    if mission is None:
        raise MissionDeliveryRefusal('publication mission claim is unavailable')
    frozen = mission['freeze']
    if not is_run_owner(tower, frozen, requesting_task_id):
        raise MissionDeliveryRefusal('publication requester is not the run-owning root')
    if mission.get('publication_intent') != {'schema': SCHEMA, **asdict(request)}:
        raise MissionDeliveryRefusal('publication request differs from the original intent')
    expected = expected_publication_binding(mission,
        authorization_generation=mission['publication_intent_generation'])
    if (any(getattr(request, name) != value for name, value in expected.items()) or
            mission['verification_observation']['status'] != 'VERIFIED'):
        raise MissionDeliveryRefusal('publication does not bind the protected verified candidate')
    if (canonical.repository != frozen['repository'] or
            mission['publication_intent_generation'] != request.authorization_generation):
        raise MissionDeliveryRefusal('publication repository or accepted generation changed')


@contextmanager
def hold_publication_authorization(tower, repository, request, *, requesting_task_id):
    """Yield the complete request digest and inherited canonical lock descriptors.

    Only pre-yield validation failures are translated. An effect-body exception
    retains its original identity, and closing the context releases its own fd
    without unlocking an inherited effect child's open file description.
    Historical reconciliation uses PublicationReceiver.reconcile separately.
    """
    if (not tower.store.durable or
            not callable(getattr(tower.store, 'authorization_guard', None))):
        raise MissionDeliveryRefusal('durable canonical authorization is unavailable')
    with ExitStack() as scope:
        try:
            fds = scope.enter_context(tower.store.authorization_guard())
        except StoreError as error:
            raise MissionDeliveryRefusal('durable canonical authorization is unavailable') from error
        try:
            _check_publication(tower, repository, request, requesting_task_id)
        except MissionDeliveryRefusal:
            raise
        except (MissionRefusal, PublicationRefusal, OSError, KeyError, TypeError) as error:
            raise MissionDeliveryRefusal('canonical publication binding is unavailable') from error
        yield HeldAuthorization(request.sha256, fds)
