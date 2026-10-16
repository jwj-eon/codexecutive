"""Thin wiring to existing public lifecycle constructors and controller seams.

All protocol construction, validation, scheduling, grant/capacity transitions,
cleanup and succession remain in the existing production modules. This adapter
returns their complete objects and never constructs a schema or action field.
"""
from __future__ import annotations

import orch_dork_governed_native_controller as native
import orch_dork_qualification_successor as successor

from lifecycle_conformance import host_adapter, values


class ProductionLifecycleAdapter:
    """One real controller and one qualified host transport; no retry policy."""

    def __init__(self, controller: native.GovernedNativeController,
                 host: host_adapter.CodexHostAdapter, transport):
        if not isinstance(controller, native.GovernedNativeController):
            raise values.LifecycleContractError("production_adapter:controller")
        if not isinstance(host, host_adapter.CodexHostAdapter) or not callable(transport):
            raise values.LifecycleContractError("production_adapter:transport")
        self.controller = controller
        self.host = host
        self.transport = transport

    @staticmethod
    def prepare_activation(**inputs) -> dict:
        program = native.build_governed_native_activation_preparation_program(**inputs)
        report = native.prepare_governed_native_activation(program)
        if native.validate_activation_preparation_report(report).get("valid") is not True:
            raise values.LifecycleContractError("production_adapter:activation_report")
        return report

    @staticmethod
    def activation_program(**inputs) -> dict:
        return native.build_governed_native_activation_program(**inputs)

    @staticmethod
    def stage_program(**inputs) -> dict:
        return native.build_governed_native_stage_program(**inputs)

    @staticmethod
    def first_action_preparation(bootstrap_artifact) -> dict:
        return successor.build_issue94_successor_first_action_preparation(bootstrap_artifact)

    @staticmethod
    def validate_first_action(report) -> dict:
        return successor.validate_issue94_successor_first_action_report(report)

    @staticmethod
    def validate_action_advance(report) -> dict:
        return successor.validate_issue94_successor_action_advance_report(report)

    def advance(self, program, *, native_request_meta=None) -> dict:
        if native_request_meta is None:
            report = self.controller.advance(program)
        else:
            report = self.controller.advance(program, native_request_meta=native_request_meta)
        if native.validate_governed_native_controller_report(report).get("valid") is not True:
            raise values.LifecycleContractError("production_adapter:controller_report")
        return report

    def execute(self, action) -> object:
        return self.host.execute_current(action, self.controller.grants, self.transport)
