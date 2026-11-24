"""RES-555 Gate B2: Linux cgroup v2 process containment qualifications.

These tests are probe-only. They require a host that has delegated a writable cgroup v2 leaf
to the test process and placed the test process in a child of that leaf. The hosted CI
provisions that placement explicitly; a host without it is refused, never downgraded to the
session/process-group primitive.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from tools.res555_gate_b2.linux_cgroup import (
    CgroupError,
    CgroupLimits,
    CgroupUnavailableError,
    CgroupV2,
    cgroup_available,
    delegated_root,
)

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="cgroup v2 containment is Linux-only"
)

_LIMITS = CgroupLimits(pids_max=64, memory_max_bytes=2 * 1024 * 1024 * 1024)


def _root() -> Path:
    if not cgroup_available():
        message = "a delegated cgroup v2 root with supervisor placement is unavailable"
        if os.environ.get("DYNAMISBENCH_REQUIRE_MUJOCO") == "1":
            pytest.fail(message)
        pytest.skip(message)
    return delegated_root()


def _spawn(root: Path, script: str, *arguments: str, name: str = "test"):
    attempt = CgroupV2.create(name=f"{name}-{os.getpid()}-{time.time_ns()}", limits=_LIMITS)
    command = attempt.launcher_command(
        launcher_python=Path(sys.executable),
        worker_program=Path(sys.executable),
        worker_arguments=("-I", "-S", "-c", script, *arguments),
    )
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert attempt.verify_attached(process.pid, 5.0)
    return attempt, process


def _wait_for(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file() and path.read_text(encoding="utf-8").strip():
            return
        time.sleep(0.02)
    raise AssertionError(f"{path} was not written")


def _cleanup(attempt: CgroupV2, process: subprocess.Popen[bytes]) -> None:
    attempt.kill()
    try:
        process.wait(5.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(5.0)
    assert attempt.wait_empty(5.0)
    assert attempt.close()


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


_SETSID_CHILD = r"""
import os, sys, time
pid_file = sys.argv[1]
pid = os.fork()
if pid == 0:
    os.setsid()
    with open(pid_file, "a") as handle:
        handle.write(f"child {os.getpid()}\n")
    time.sleep(30)
    os._exit(0)
with open(pid_file, "a") as handle:
    handle.write(f"parent {os.getpid()}\n")
time.sleep(30)
"""

_ORPHAN_CHILD = r"""
import os, sys, time
pid_file = sys.argv[1]
pid = os.fork()
if pid == 0:
    os.setsid()
    with open(pid_file, "w") as handle:
        handle.write(str(os.getpid()))
    time.sleep(30)
    os._exit(0)
# Give the supervisor time to observe the launcher in cgroup.procs before this parent
# exits; the child remains and is the containment subject.
time.sleep(0.5)
os._exit(0)
"""


def test_forked_and_setsid_children_stay_in_the_supervisor_subtree(tmp_path: Path) -> None:
    root = _root()
    pid_file = tmp_path / "pids.txt"
    attempt, process = _spawn(root, _SETSID_CHILD, str(pid_file), name="setsid")
    try:
        _wait_for(pid_file)
        lines = pid_file.read_text(encoding="utf-8").splitlines()
        pids = {int(line.split()[1]) for line in lines}
        assert len(pids) == 2
        assert pids <= set(attempt.procs())
        assert attempt.events().get("populated") == 1
    finally:
        pids = set()
        if pid_file.is_file():
            try:
                pids = {
                    int(line.split()[1])
                    for line in pid_file.read_text(encoding="utf-8").splitlines()
                }
            except (OSError, ValueError, IndexError):
                pids = set()
        _cleanup(attempt, process)
    for pid in pids:
        assert not _alive(pid)


def test_a_child_that_outlives_its_direct_parent_is_still_killed(tmp_path: Path) -> None:
    root = _root()
    pid_file = tmp_path / "orphan.pid"
    attempt, process = _spawn(root, _ORPHAN_CHILD, str(pid_file), name="orphan")
    try:
        _wait_for(pid_file)
        child = int(pid_file.read_text(encoding="utf-8"))
        process.wait(5.0)
        assert process.poll() == 0
        assert child in attempt.procs()
        assert attempt.events().get("populated") == 1
    finally:
        _cleanup(attempt, process)
    assert not _alive(child)


def test_cancellation_uses_the_same_subtree_kill(tmp_path: Path) -> None:
    root = _root()
    attempt, process = _spawn(root, "import time; time.sleep(30)", name="cancel")
    try:
        time.sleep(0.2)
        attempt.kill()
        assert attempt.wait_empty(5.0)
        assert process.poll() is not None
    finally:
        _cleanup(attempt, process)
    assert attempt.path.exists() is False


def test_timeout_uses_the_same_subtree_kill(tmp_path: Path) -> None:
    root = _root()
    attempt, process = _spawn(root, "import time; time.sleep(30)", name="timeout")
    try:
        try:
            process.wait(0.2)
        except subprocess.TimeoutExpired:
            pass
        attempt.kill()
        assert attempt.wait_empty(5.0)
        assert process.wait(5.0) is not None
    finally:
        _cleanup(attempt, process)
    assert attempt.path.exists() is False


def test_repeated_launches_leave_no_attempt_subtrees(tmp_path: Path) -> None:
    root = _root()
    names: list[str] = []
    for index in range(3):
        attempt, process = _spawn(root, "import time; time.sleep(0.05)", name=f"repeat{index}")
        names.append(attempt.path.name)
        try:
            process.wait(5.0)
            assert process.poll() == 0
            assert attempt.wait_empty(5.0)
        finally:
            _cleanup(attempt, process)
        assert not (root / names[-1]).exists()


def test_failed_setup_does_not_leave_a_subtree(tmp_path: Path) -> None:
    root = _root()
    if not (root / "cpu.max").exists():
        pytest.skip("the delegated root does not expose the optional cpu controller")
    name = f"bad-{os.getpid()}-{time.time_ns()}"
    with pytest.raises(CgroupError):
        CgroupV2.create(
            name=name,
            limits=CgroupLimits(
                pids_max=8,
                memory_max_bytes=64 * 1024 * 1024,
                cpu_max="not-a-cpu-quota",
            ),
        )
    assert not (root / name).exists()


def test_a_host_without_a_delegated_cgroup_is_refused(tmp_path: Path) -> None:
    with pytest.raises(CgroupUnavailableError):
        CgroupV2.create(root=tmp_path, limits=_LIMITS)


def test_pids_max_counts_tasks_including_threads(tmp_path: Path) -> None:
    _root()
    script = r"""
import json, threading, time, sys
started = 0
blocked = 0
def sleeper():
    time.sleep(2)
threads = []
for _ in range(12):
    thread = threading.Thread(target=sleeper)
    try:
        thread.start()
    except RuntimeError:
        blocked += 1
    else:
        started += 1
        threads.append(thread)
print(json.dumps({"started": started, "blocked": blocked}), flush=True)
time.sleep(0.2)
"""
    attempt = CgroupV2.create(
        name=f"threads-{os.getpid()}-{time.time_ns()}",
        limits=CgroupLimits(pids_max=4, memory_max_bytes=256 * 1024 * 1024),
    )
    command = attempt.launcher_command(
        launcher_python=Path(sys.executable),
        worker_program=Path(sys.executable),
        worker_arguments=("-I", "-S", "-c", script),
    )
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        assert attempt.verify_attached(process.pid, 5.0)
        stdout, _ = process.communicate(timeout=10)
        observed = json.loads(stdout.decode("utf-8"))
        assert observed["started"] >= 1
        assert observed["blocked"] >= 1
        assert attempt.observe().pids_events_max >= 1
    finally:
        _cleanup(attempt, process)


def test_the_real_numpy_and_mujoco_runtime_fits_the_qualified_task_bound() -> None:
    if not os.environ.get("DYNAMISBENCH_MUJOCO_PYTHON"):
        pytest.skip("the locked MuJoCo worker interpreter is not configured")
    worker = Path(os.environ["DYNAMISBENCH_MUJOCO_PYTHON"])
    _root()
    attempt = CgroupV2.create(
        name=f"runtime-{os.getpid()}-{time.time_ns()}",
        limits=CgroupLimits(pids_max=64, memory_max_bytes=2 * 1024 * 1024 * 1024),
    )
    command = attempt.launcher_command(
        launcher_python=worker,
        worker_program=worker,
        worker_arguments=("-I", "-c", "import numpy, mujoco; print(numpy.__version__)"),
    )
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        assert attempt.verify_attached(process.pid, 5.0)
        stdout, stderr = process.communicate(timeout=120)
        assert process.returncode == 0, stderr.decode("utf-8", "replace")
        observation = attempt.observe()
        assert observation.pids_peak <= 64
        assert observation.pids_events_max == 0
    finally:
        _cleanup(attempt, process)
