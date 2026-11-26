"""The probe harness exercises the production cgroup boundary, not a private copy."""

from __future__ import annotations

import pytest
from tools.res555_gate_b2 import linux_cgroup

from dynamisbench.host import protected_cgroup


def test_the_probe_shim_is_the_production_mechanism() -> None:
    assert linux_cgroup.CgroupV2 is protected_cgroup.CgroupV2
    assert linux_cgroup.delegated_root is protected_cgroup.delegated_root
    assert linux_cgroup.attach_code is protected_cgroup.attach_code


def test_an_attempt_name_must_be_one_component() -> None:
    with pytest.raises(ValueError):
        protected_cgroup.CgroupLimits(pids_max=0, memory_max_bytes=1)
    with pytest.raises(ValueError):
        protected_cgroup.CgroupLimits(pids_max=1, memory_max_bytes=0)
