"""Lossless coverage composition; this catalog does not attest execution.

Only an executing campaign may use this intermediate value. Supplying reports
or a self-sealed catalog cannot authorize release, installation or qualification.
Each original component and its registry remain required for readback validation.
"""
from __future__ import annotations

from lifecycle_conformance import fragment, registries, reference_values as rv, values

SCHEMA = "orch-dork/lifecycle-coverage-catalog/v1"


def _refuse(reason: str) -> None:
    raise values.LifecycleContractError("catalog:" + reason)


def component(owner: str, registry: dict, coverage: dict, report: dict) -> rv.FrozenValue:
    """Bind the whole originating report, exact registry and coverage together."""
    return rv.freeze({"owner": owner, "registry": registry, "coverage": coverage, "report": report})


def build_catalog(components: list[rv.FrozenValue]) -> rv.FrozenValue:
    """Validate components and join actual item/case identities without rewriting."""
    if type(components) is not list or not components:
        _refuse("components")
    joined = registries.RegistryStore()
    owners, bindings, entries, cases, source_reports = set(), {}, [], {}, {}
    for value in components:
        if type(value) is not rv.FrozenValue:
            _refuse("component_type")
        data = value.to_plain()
        if type(data) is not dict or set(data) != {"owner", "registry", "coverage", "report"}:
            _refuse("component_shape")
        owner, registry, coverage = data["owner"], data["registry"], data["coverage"]
        if type(owner) is not str or not values._TOKEN.fullmatch(owner) or owner in owners:
            _refuse("component_owner")
        if (type(registry) is not dict or not registry or set(registry) - set(values.REGISTRY_ITEMS)
                or type(data["report"]) is not dict):
            _refuse("registry_shape")
        if (rv.freeze(data["report"].get("registry")) != rv.freeze(registry)
                or rv.freeze(data["report"].get("coverage")) != rv.freeze(coverage)):
            _refuse("report_binding")
        store = registries.RegistryStore()
        for kind, rows in registry.items():
            if type(rows) is not dict:
                _refuse("registry_shape")
            for item, record in rows.items():
                store.add(kind, item, owner, record)
                if item in bindings:
                    _refuse("duplicate_item")
                joined.add(kind, item, owner, record)
                bindings[item] = owner
        fragment.validate_fragment(coverage, owner=owner, store=store)
        if coverage["digests"]["vocab"] != values.vocabulary_digest():
            _refuse("vocabulary_drift")
        # Foundation validation binds fragment shape, references and coverage.
        # Preserve each complete source entry and its owner without relabeling.
        for entry in coverage["entries"]:
            for case in entry["cases"]:
                case_id = case["id"]
                if case_id in cases and cases[case_id]["owner"] != owner:
                    _refuse("case_collision")
                case_row = cases.setdefault(case_id, {"owner": owner, "items": set()})
                case_row["items"].update(entry["id"])
            entries.append({"owner": owner, "entry": entry})
        owners.add(owner)
        source_reports[owner] = {"component_sha256": value.digest(),
                                "report_sha256": values.canonical_digest(data["report"]),
                                "registry_sha256": store.digest(),
                                "coverage_sha256": values.canonical_digest(coverage)}
    registry = {kind: joined.items_of(kind) for kind in joined.kinds()}
    entries.sort(key=lambda row: (row["owner"], values.canonical_json(row["entry"])))
    return rv.freeze({"schema": SCHEMA, "vocabulary_sha256": values.vocabulary_digest(),
                      "components": source_reports, "registry": registry,
                      "registry_sha256": joined.digest(), "item_owners": bindings,
                      "source_entries": entries,
                      "cases": {case: {"owner": row["owner"], "items": sorted(row["items"])}
                                for case, row in sorted(cases.items())},
                      "execution_attested": False, "qualification_authorized": False})


def validate_catalog(catalog: rv.FrozenValue, components: list[rv.FrozenValue]) -> None:
    """Readback requires complete original inputs; resealing cannot invent them."""
    if type(catalog) is not rv.FrozenValue or catalog != build_catalog(components):
        _refuse("catalog_binding")
