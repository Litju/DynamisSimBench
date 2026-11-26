"""RES-555 Gate B2 probe-only qualification package.

Nothing in this package is imported by the production execution route. The package is
reachable only from the probe harness and its tests, and every entry point requires the
explicit ``DYNAMISBENCH_RES555_B2_PROBE=1`` gate.
"""
