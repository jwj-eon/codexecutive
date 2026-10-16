"""Shared provider-free lifecycle conformance foundation (Issue 165).

This package is the finite-claim foundation for SPEC G16, FR65, section 12,
acceptance criterion 53, and delivery step 42: one closed vocabulary, one
pure reference-model interface, stable registries, and one machine-readable
coverage-fragment contract. It implements no transitions of its own, reads
no production store, performs no live effect, and never speaks for a live
provider, host, or preflight.
"""
