"""Probe-only protected launch orchestrator for RES-555 Gate B2.

This module connects an already-prepared input set to a real worker launch under the
platform sandbox, but only from the unadmitted qualification harness. It is not a
production execution route: the supervisor, preflight, API and CLI never import it, and
every entry point requires ``DYNAMISBENCH_RES555_B2_PROBE=1``.

The orchestration is deliberately fail-closed. A missing mechanism, a changed input view,
a changed runtime snapshot, a replayed binding or a missing in-worker denial observation
is a refusal, never a fallback to an unprotected launch.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from tools.res555_gate_b2.linux_cgroup import CgroupLimits, CgroupV2
from tools.res555_gate_b2.profile import build_profile, mechanism_available
from tools.res555_gate_b2.runtime import ProtectedRuntime
from tools.res555_gate_b2.scratch import (
    ScratchBudgetError,
    ScratchUsage,
    ScratchWatchdog,
    measure_scratch,
    resolve_scratch_budget,
    scratch_headroom,
)
from tools.res555_gate_b2.view import build_input_view

from dynamisbench.adapters.mujoco import reference
from dynamisbench.adapters.mujoco._b2_probe_common import (
    MAX_RECEIPT_BYTES,
    ConsumptionReceipt,
    ProbeTargets,
    SupervisorObservation,
    assert_probe_authorized,
    measure_runtime_identity,
    read_bounded_regular,
    sha256_bytes,
    summarize_runtime,
    write_canonical_atomic,
)
from dynamisbench.execution import (
    PreparedExecutionInputs,
    WorkerEnvironmentManifest,
)
from dynamisbench.execution._process_tree import PosixProcessTree
from dynamisbench.execution.contracts import (
    MAX_WORKER_MESSAGE_BYTES,
    WorkerProtocolError,
    WorkerStatus,
    canonical_worker_request_bytes,
    parse_worker_response,
)
from dynamisbench.execution.input_binding import build_worker_input_binding
from dynamisbench.execution.input_verification import (
    VerifiedWorkerInputs,
    verify_worker_input_view,
)
from dynamisbench.identity import canonical_semantic_bytes
from dynamisbench.workspace import PersistenceClass, Workspace

__all__ = [
    "ProtectedLaunchError",
    "ProbeLaunchResult",
    "consume_attempt",
    "run_protected_probe",
]

_MAX_STDOUT: Final = 1024 * 1024
_MAX_STDERR: Final = 256 * 1024
_POLL_SECONDS: Final = 0.02
_NETWORK_PROBE_NAMES: Final = frozenset(
    {
        "network_connect",
        "network_udp",
        "network_raw",
        "network_unix",
        "network_socketpair",
        "io_uring_setup",
        "inherited_sockets",
    }
)


class ProtectedLaunchError(RuntimeError):
    """A probe attempt was refused before a protected process could start."""


@dataclass(frozen=True, slots=True)
class ProbeLaunchResult:
    observation: SupervisorObservation
    observation_path: Path | None


def consume_attempt(runtime: ProtectedRuntime, nonce: str, binding_sha256: str) -> Path:
    """Mark one binding as used before process creation; a replay raises.

    The marker is supervisor-owned and outside the sandbox. It is intentionally not
    removed after the run: a second use of the same binding is the replay this refuses.
    """
    attempts = runtime.registry_root
    attempts.mkdir(parents=True, exist_ok=True)
    marker = attempts / f"{nonce}.used"
    try:
        descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise ProtectedLaunchError("this binding was already used") from error
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(binding_sha256.encode("ascii"))
        handle.flush()
        os.fsync(handle.fileno())
    return marker


class _BoundedReader(threading.Thread):
    def __init__(self, stream: Any, limit: int, *, fail_on_overflow: bool) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._limit = limit
        self._fail_on_overflow = fail_on_overflow
        self.buffer = bytearray()
        self.truncated = False
        self.overflow = threading.Event()

    def run(self) -> None:
        try:
            while True:
                chunk = self._stream.read(64 * 1024)
                if not chunk:
                    return
                room = self._limit - len(self.buffer)
                if room > 0:
                    self.buffer.extend(chunk[:room])
                if len(chunk) > max(room, 0):
                    self.truncated = True
                    if self._fail_on_overflow:
                        self.overflow.set()
        except (OSError, ValueError):
            if self._fail_on_overflow:
                self.overflow.set()
            else:
                self.truncated = True


class _Writer(threading.Thread):
    def __init__(self, stream: Any, payload: bytes) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._payload = payload
        self.delivered = False
        self.failure: str | None = None

    def run(self) -> None:
        view = memoryview(self._payload)
        try:
            while view:
                written = self._stream.write(view)
                if written <= 0:
                    raise BrokenPipeError("the worker closed its stdin")
                view = view[written:]
            self._stream.flush()
            self.delivered = True
        except (BrokenPipeError, OSError, ValueError) as error:
            self.failure = f"{type(error).__name__}: {error}"
        finally:
            try:
                self._stream.close()
            except OSError:
                return


class _NetworkCanary:
    """Localhost listeners for every channel the worker might still reach.

    TCP is the original canary. UDP delivery is measured separately because a Windows
    AppContainer can accept ``sendto`` and then drop the datagram in the firewall; the return
    value of ``sendto`` is not evidence that a packet left the process. A Unix-domain
    listener is included where the host supports it. A zero count on all three is the
    supervisor's observation that no connection or datagram arrived.
    """

    def __init__(self) -> None:
        self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp.bind(("127.0.0.1", 0))
        self._tcp.listen(1)
        self._tcp.settimeout(0.2)
        self.port = int(self._tcp.getsockname()[1])

        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind(("127.0.0.1", 0))
        self._udp.settimeout(0.2)
        self.udp_port = int(self._udp.getsockname()[1])

        self._unix_path: Path | None = None
        self._unix: socket.socket | None = None
        unix_family = getattr(socket, "AF_UNIX", None)
        if unix_family is not None:
            self._unix_path = Path(tempfile.mkdtemp(prefix="res555-canary-")) / "worker.sock"
            listener = socket.socket(unix_family, socket.SOCK_STREAM)
            listener.bind(str(self._unix_path))
            listener.listen(1)
            listener.settimeout(0.2)
            self._unix = listener

        self.accepted = 0
        self.udp_received = 0
        self.unix_accepted = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    @property
    def unix_path(self) -> str | None:
        return None if self._unix_path is None else str(self._unix_path)

    @property
    def tcp_connections(self) -> int:
        return self._count("accepted")

    @property
    def udp_datagrams(self) -> int:
        return self._count("udp_received")

    @property
    def unix_connections(self) -> int:
        return self._count("unix_accepted")

    def _count(self, name: str) -> int:
        with self._lock:
            return int(getattr(self, name))

    def _wait_for(self, name: str, target: int, timeout: float = 2.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._count(name) >= target:
                return True
            time.sleep(0.01)
        return self._count(name) >= target

    def _reset(self, name: str) -> None:
        with self._lock:
            setattr(self, name, 0)

    def self_check(self) -> dict[str, bool]:
        """Prove each active canary can receive before the worker is launched.

        A zero worker count is meaningful only if the same listener demonstrably received a
        control connection or datagram from the supervisor. The control traffic is counted,
        confirmed and then reset so it cannot be mistaken for worker traffic.
        """
        results: dict[str, bool] = {}
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=1.0):
                pass
            results["tcp"] = self._wait_for("accepted", 1)
        except OSError:
            results["tcp"] = False
        finally:
            self._reset("accepted")

        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.sendto(b"RES555-CANARY-CONTROL", ("127.0.0.1", self.udp_port))
        finally:
            probe.close()
        results["udp"] = self._wait_for("udp_received", 1)
        self._reset("udp_received")

        # AF_UNIX is absent from some Windows socket builds; the path is None there.
        unix_family = getattr(socket, "AF_UNIX", None)  # noqa: B009
        if self._unix_path is not None and unix_family is not None:
            control = socket.socket(unix_family, socket.SOCK_STREAM)
            try:
                control.connect(str(self._unix_path))
            except OSError:
                results["unix"] = False
            else:
                results["unix"] = self._wait_for("unix_accepted", 1)
            finally:
                control.close()
                self._reset("unix_accepted")
        else:
            results["unix"] = True
        return results

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._tcp.accept()
            except (TimeoutError, OSError):
                pass
            else:
                with self._lock:
                    self.accepted += 1
                try:
                    connection.close()
                except OSError:
                    pass
            try:
                self._udp.recvfrom(4096)
            except (TimeoutError, OSError):
                pass
            else:
                with self._lock:
                    self.udp_received += 1
            if self._unix is not None:
                try:
                    connection, _ = self._unix.accept()
                except (TimeoutError, OSError):
                    pass
                else:
                    with self._lock:
                        self.unix_accepted += 1
                    try:
                        connection.close()
                    except OSError:
                        pass

    def close(self) -> None:
        self._stop.set()
        for listener in (self._tcp, self._udp, self._unix):
            if listener is None:
                continue
            try:
                listener.close()
            except OSError:
                pass
        self._thread.join(1.0)
        if self._unix_path is not None:
            shutil.rmtree(self._unix_path.parent, ignore_errors=True)


def _check(name: str, passed: bool, observed: object, limit: object) -> dict[str, object]:
    return {"name": name, "passed": bool(passed), "observed": observed, "limit": limit}


def _environment(scratch: Path) -> dict[str, str]:
    values = {
        "DYNAMISBENCH_RES555_B2_PROBE": "1",
        "MUJOCO_GL": "disable",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUTF8": "1",
        "TZ": "UTC",
    }
    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR"):
            if name in os.environ:
                values[name] = os.environ[name]
        values["TEMP"] = str(scratch)
        values["TMP"] = str(scratch)
    else:
        values["HOME"] = str(scratch)
        values["LANG"] = "C.UTF-8"
        values["LC_ALL"] = "C.UTF-8"
        values["TMPDIR"] = str(scratch)
    return values


def _write_sandbox_config(path: Path, value: dict[str, object]) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    path.write_bytes(data)
    return sha256_bytes(data)


def _read_proc_status(pid: int) -> dict[str, object]:
    path = Path(f"/proc/{pid}/status")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    values: dict[str, object] = {}
    for line in lines:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        values[name.strip()] = value.strip()
    return {
        "no_new_privs": values.get("NoNewPrivs"),
        "seccomp": values.get("Seccomp"),
        "seccomp_filters": values.get("Seccomp_filters"),
        "cap_eff": values.get("CapEff"),
        "cap_prm": values.get("CapPrm"),
        "cap_bnd": values.get("CapBnd"),
        "uid": values.get("Uid"),
        "gid": values.get("Gid"),
    }


def _read_proc_cgroup(pid: int) -> str | None:
    try:
        for line in Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8").splitlines():
            if line.startswith("0::"):
                return line[3:].strip()
    except OSError:
        return None
    return None


def _environment_policy(scratch: Path) -> tuple[set[str], set[str]]:
    """Return the allowed and required worker environment names for this launch."""
    allowed = set(_environment(scratch))
    allowed.discard("PYTHONHASHSEED")
    allowed.update({"TEMP", "TMP", "HOME"})
    if os.name == "nt":
        allowed.update(
            {
                "PATH",
                "PROCESSOR_ARCHITECTURE",
                "PROCESSOR_ARCHITEW6432",
                "PROCESSOR_IDENTIFIER",
            }
        )
    required = {
        "DYNAMISBENCH_RES555_B2_PROBE",
        "HOME",
        "MUJOCO_GL",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONIOENCODING",
        "PYTHONNOUSERSITE",
        "PYTHONUTF8",
        "TEMP",
        "TMP",
        "TZ",
    }
    return allowed, required


def _capture_worker_ready(ready_path: Path, pid: int | None, external: dict[str, object]) -> None:
    """Read the worker's ready echo and, on Linux, the supervisor's /proc facts."""
    if external.get("ready") is not None or not ready_path.is_file():
        return
    try:
        ready = json.loads(ready_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        ready = {"invalid": True}
    external["ready"] = ready
    if pid is not None:
        external["proc"] = _read_proc_status(pid)
        external["cgroup_path"] = _read_proc_cgroup(pid)
        external["fds"] = _read_proc_sockets(pid)


def _read_proc_sockets(pid: int) -> dict[str, object]:
    """Count inherited socket descriptors from outside the worker."""
    import stat

    descriptors = 0
    sockets: list[int] = []
    try:
        entries = list(Path(f"/proc/{pid}/fd").iterdir())
    except OSError:
        return {"readable": False, "descriptors": 0, "sockets": []}
    for entry in entries:
        descriptors += 1
        try:
            info = entry.stat()
        except OSError:
            continue
        if stat.S_ISSOCK(info.st_mode):
            sockets.append(int(entry.name))
    return {"readable": True, "descriptors": descriptors, "sockets": sockets}


def _terminate(
    process: Any,
    tree: PosixProcessTree | None,
    *,
    windows: bool,
    cgroup: CgroupV2 | None = None,
) -> tuple[bool, bool]:
    if windows:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(5.0)
        except TimeoutError:
            pass
        reaped = process.poll() is not None
        try:
            cleaned = int(process.job_accounting()["active_processes"]) == 0
        except Exception:  # noqa: BLE001 - cleanup is best effort at this boundary
            cleaned = False
        return reaped, cleaned
    cgroup_killed = False
    if cgroup is not None:
        # The cgroup is authoritative: it reaches a setsid() child and a descendant whose
        # direct parent exited, which the session/process group cannot. The process group is
        # still signalled as a cheap first step, but its emptiness is not the cleanup proof.
        if tree is not None:
            try:
                tree.request_termination()
            except OSError:
                pass
        cgroup_killed = cgroup.kill()
    elif tree is not None:
        try:
            tree.request_termination()
        except OSError:
            pass
    try:
        process.wait(5.0)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(5.0)
        except subprocess.TimeoutExpired:
            pass
    reaped = process.poll() is not None
    if cgroup is not None:
        cleaned = cgroup_killed and cgroup.wait_empty(5.0)
    else:
        cleaned = tree.wait_empty(5.0) if tree is not None else False
    return reaped, cleaned


def _scratch_usage(scratch: Path) -> tuple[int, int, int, int]:
    """Compatibility wrapper around the exact post-exit scratch measurement."""
    usage = measure_scratch(scratch)
    return usage.bytes, usage.files, usage.links, usage.unmeasured


def _create_sentinel(root: Path, token: str, *, create_root: bool) -> Path:
    if create_root:
        root.mkdir(parents=True, exist_ok=True)
    path = root / f"res555-b2-sentinel-{token}.txt"
    path.write_bytes(f"RES555-B2-SENTINEL {token}\n".encode())
    return path


def _linux_allowlists(
    runtime: ProtectedRuntime, attempt: Path, inputs: Path, scratch: Path
) -> tuple[list[str], list[str], list[str]]:
    # Only shared-library/system-data paths the pinned interpreter and its native wheels
    # actually need. /bin, /sbin, /usr/bin and /usr/sbin are deliberately absent: a scientific
    # worker has no reason to exec a system helper, and an execute grant over /usr would make
    # every installed tool part of the worker's surface.
    system = [
        Path("/usr/lib"),
        Path("/usr/lib64"),
        Path("/usr/local/lib"),
        Path("/lib"),
        Path("/lib64"),
        Path("/etc/ld.so.cache"),
        Path("/etc/localtime"),
        Path("/dev/urandom"),
        Path("/proc/cpuinfo"),
        Path("/proc/sys/kernel/seccomp"),
        Path("/sys/devices/system/cpu"),
    ]
    read_execute = [str(path) for path in system if path.exists()]
    read_execute.append(str(runtime.base_prefix))
    # The Linux launch path is the provisioned venv interpreter, which may be a symlink
    # into the base installation. Allow both the link's own directory and the resolved
    # target directory so the kernel can open either form.
    read_execute.append(str(runtime.interpreter.parent))
    read_execute.append(str(runtime.interpreter.resolve().parent))
    read_only = [
        str(runtime.site_packages),
        str(runtime.source_root),
        str(attempt),
        str(inputs),
        # The worker's own descriptor table is a read-only observation surface used by the
        # inherited-socket probe. It exposes no file content; the probe fstats the fd numbers.
        "/proc/self/fd",
        # The seccomp installer refuses a multithreaded process and the bootstrap records
        # its filter status from this file. It is a read-only process observation.
        "/proc/self/status",
    ]
    read_write = [str(scratch)]
    return read_execute, read_only, read_write


def run_protected_probe(
    *,
    workspace: Workspace,
    prepared: PreparedExecutionInputs,
    selection: WorkerEnvironmentManifest,
    runtime: ProtectedRuntime,
    mode: str,
    sandbox_parent: Path | None = None,
    profile: Any | None = None,
    platform_tag: str | None = None,
    forbidden_read_roots: tuple[Path, ...] = (),
    force_mechanism_unavailable: bool = False,
    tamper: Any | None = None,
    view_tamper: Any | None = None,
    expected_trajectory_sha256: str | None = None,
    evidence_dir: Path | None = None,
    evidence_name: str | None = None,
    scratch_root: Path | None = None,
) -> ProbeLaunchResult:
    """Verify, launch and observe one probe attempt, or refuse before any process.

    A materialized attempt must name the independently qualified trajectory digest.
    ``evidence_name`` is required whenever ``evidence_dir`` is set and is a plain ``.json``
    file name; only the positive materialized test names the acceptance observation.
    """
    assert_probe_authorized()
    if evidence_dir is not None and evidence_name is None:
        raise ProtectedLaunchError(
            "an evidence directory requires an explicit per-attempt evidence name; "
            "a later test must not overwrite the acceptance observation"
        )
    if evidence_name is not None:
        candidate = Path(evidence_name)
        if evidence_dir is None:
            raise ProtectedLaunchError("an evidence name requires an evidence directory")
        if candidate.name != evidence_name or candidate.suffix != ".json":
            raise ProtectedLaunchError("the evidence name must be one plain .json file name")
    if expected_trajectory_sha256 is not None:
        expected_trajectory_sha256 = expected_trajectory_sha256.strip().lower()
        if len(expected_trajectory_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in expected_trajectory_sha256
        ):
            raise ProtectedLaunchError(
                "the expected trajectory reference must be one sha256 hex digest"
            )
    if mode == "materialized-mujoco" and expected_trajectory_sha256 is None:
        raise ProtectedLaunchError(
            "a materialized attempt requires the independently qualified trajectory digest"
        )
    tag = platform_tag or reference.platform_tag()
    base_profile = build_profile(tag)
    configured_scratch = scratch_root
    if configured_scratch is None:
        configured = os.environ.get("DYNAMISBENCH_RES555_B2_SCRATCH_ROOT")
        configured_scratch = Path(configured) if configured else None
    try:
        scratch_budget = resolve_scratch_budget(
            explicit_root=configured_scratch,
            max_bytes=base_profile.max_scratch_bytes,
        )
    except ScratchBudgetError as error:
        raise ProtectedLaunchError(f"the scratch bound is unavailable: {error}") from error
    isolation = build_profile(tag, scratch=scratch_budget)
    if force_mechanism_unavailable or not mechanism_available():
        raise ProtectedLaunchError(
            f"the required {isolation.mechanism} mechanism is unavailable; no fallback "
            "execution is attempted"
        )
    if os.name == "nt" and profile is None:
        raise ProtectedLaunchError("a Windows AppContainer profile is required")
    request = prepared.request
    if request is None or prepared.report.decision.value != "ready":
        raise ProtectedLaunchError("the preparation did not retain a ready request")

    binding = build_worker_input_binding(
        prepared,
        selection,
        runtime_closure_sha256=runtime.snapshot.digest,
        isolation_profile_sha256=isolation.digest(),
    )
    binding_digest = sha256_bytes(canonical_semantic_bytes(binding))
    created_parent: Path | None = None
    if scratch_budget.root is not None:
        parent = scratch_budget.root
    elif sandbox_parent is not None:
        parent = sandbox_parent
    elif os.name == "nt":
        # The AppContainer profile's AC folder is writable by the package SID. An attempt
        # beneath it would let the worker write outside the measured scratch tree with
        # ``..``. The attempt lives in a supervisor-owned temporary parent instead; the AC
        # folder is later reduced to read/execute for the package SID.
        # Resolve the 8.3 temporary path to its exact long NTFS name; the A1 input-view
        # reader refuses an alias path even though Windows can open it.
        parent = Path(tempfile.mkdtemp(prefix="res555-b2-attempt-parent-")).resolve()
        created_parent = parent
    else:
        parent = runtime.root.parent
    attempt = parent / f"attempt-{binding.launch_nonce[:16]}"
    inputs = attempt / "inputs"
    scratch = attempt / "scratch"
    if attempt.exists():
        raise ProtectedLaunchError("the attempt directory already exists")
    scratch.mkdir(parents=True)
    try:
        scratch_available = scratch_headroom(scratch)
    except ScratchBudgetError as error:
        raise ProtectedLaunchError(f"the scratch volume is not measurable: {error}") from error
    # A dedicated mount is already capacity-bounded; require half of the bound free so a
    # nearly-full mount cannot start a doomed run. A shared volume is not capacity-bounded,
    # so require twice the bound before allowing the sampled watchdog to cover the attempt.
    headroom_required = (
        max(1, isolation.max_scratch_bytes // 2)
        if scratch_budget.enforcement == "dedicated-filesystem"
        else isolation.max_scratch_bytes * 2
    )
    if scratch_available < headroom_required:
        raise ProtectedLaunchError(
            "the scratch volume cannot absorb the configured bound before launch: "
            f"{scratch_available} < {headroom_required} bytes"
        )
    build_input_view(inputs, workspace, prepared, binding)
    if view_tamper is not None:
        view_tamper(inputs)
    pre_view = verify_worker_input_view(inputs, expected=binding, request=request)
    if runtime.source.digest != runtime.snapshot.digest:
        raise ProtectedLaunchError("the source and snapshot runtime closures disagree")
    if runtime.bootstrap_sha256() != runtime.bootstrap_digest:
        raise ProtectedLaunchError("the probe bootstrap changed after it was measured")
    runtime.rescan_for_model()
    re_measured = measure_runtime_identity(
        executable=runtime.interpreter,
        base_prefix=runtime.base_prefix,
        site_packages=runtime.site_packages,
        source_root=runtime.source_root,
        model_asset_relative="assets/reference_pendulum.xml",
    )
    if re_measured.digest != runtime.snapshot.digest:
        raise ProtectedLaunchError("the runtime snapshot changed after it was measured")
    if tamper is not None:
        tamper(runtime)

    token = uuid.uuid4().hex
    sentinels: list[Path] = []
    forbidden_writes: list[Path] = []
    staging = workspace.location(PersistenceClass.STAGING).path
    sealed = workspace.location(PersistenceClass.SEALED_EVIDENCE).path
    windows_process: Any | None = None
    cgroup: CgroupV2 | None = None
    cgroup_observation: dict[str, object] | None = None
    cgroup_cleaned = False
    scratch_watchdog: ScratchWatchdog | None = None
    try:
        for root in forbidden_read_roots:
            sentinels.append(_create_sentinel(root, token, create_root=root in {staging, sealed}))
        forbidden_writes = [
            inputs / "forbidden-write.txt",
            staging / f"res555-b2-write-{token}.txt",
            sealed / f"res555-b2-write-{token}.txt",
        ]
        if os.name == "nt":
            assert profile is not None
            forbidden_writes.extend(
                [
                    attempt.parent / f"res555-b2-parent-{token}.txt",
                    profile.folder / f"res555-b2-ac-{token}.txt",
                ]
            )
        runtime_write = runtime.source_root / "dynamisbench" / f"res555-b2-write-{token}.txt"
        canary = _NetworkCanary()
        network_control = canary.self_check()
        if not all(network_control.values()):
            raise ProtectedLaunchError(
                "the supervisor's localhost canaries did not receive their control traffic; "
                "a zero worker count would not be interpretable"
            )
        try:
            targets = ProbeTargets(
                forbidden_reads=tuple(str(path) for path in sentinels),
                forbidden_writes=tuple(str(path) for path in forbidden_writes),
                forbidden_deletes=(str(inputs / "binding.json"),),
                allowed_read=str(inputs / "binding.json"),
                allowed_write=str(scratch / "probe-write.txt"),
                runtime_write=str(runtime_write),
                network_port=canary.port,
                network_udp_port=canary.udp_port,
                network_unix_path=canary.unix_path,
                write_token=token,
            )
            write_canonical_atomic(scratch / "probe-targets.json", targets, limit=64 * 1024)
            sandbox = {
                "schema": "dynamisbench.res555.sandbox/1",
                "mechanism": isolation.mechanism,
                "mode": mode,
                "profile_sha256": isolation.digest(),
                "runtime_closure_sha256": runtime.snapshot.digest,
                "inputs": str(inputs),
                "scratch": str(scratch),
                "source_root": str(runtime.source_root),
                "site_packages": str(runtime.site_packages),
                "base_prefix": str(runtime.base_prefix),
                "installed_site_packages": str(runtime.environment.site_packages),
                "installed_source_root": str(runtime.environment.source_root),
                "keep_paths": [str(runtime.base_prefix)],
                "landlock_module": str(
                    runtime.source_root / "dynamisbench" / "execution" / "_b2_landlock.py"
                ),
                "seccomp_module": str(
                    runtime.source_root / "dynamisbench" / "execution" / "_b2_seccomp.py"
                ),
                "scratch_backend": scratch_budget.enforcement,
                "scratch_capacity_bytes": scratch_budget.capacity_bytes,
                "memory_limit_bytes": isolation.memory_limit_bytes,
                "cpu_time_seconds": isolation.cpu_time_seconds,
                "max_file_bytes": isolation.max_scratch_bytes,
                "max_open_files": 256,
                "probe_targets": str(scratch / "probe-targets.json"),
            }
            read_execute, read_only, read_write = _linux_allowlists(
                runtime, attempt, inputs, scratch
            )
            sandbox["read_execute"] = read_execute
            sandbox["read_only"] = read_only
            sandbox["read_write"] = read_write
            sandbox_digest = _write_sandbox_config(attempt / "sandbox.json", sandbox)

            if os.name == "nt":
                from tools.res555_gate_b2.windows import grant_tree

                # The profile's AC folder is created with package-SID full control. Reduce it
                # to traverse/read before the worker starts, so ``..`` cannot create files
                # outside the measured attempt. The supervisor user keeps cleanup control;
                # the runtime/input/attempt trees are then granted explicitly.
                grant_tree(
                    profile.folder,
                    profile.sid_string,
                    "(OI)(CI)(RX)",
                    user_access="(OI)(CI)(F)",
                )
                grant_tree(
                    runtime.root,
                    profile.sid_string,
                    "(OI)(CI)(RX)",
                    user_access="(OI)(CI)(RX,DE,DC)",
                )
                grant_tree(
                    attempt,
                    profile.sid_string,
                    "(OI)(CI)(RX)",
                    user_access="(OI)(CI)(RX,DE,DC)",
                )
                grant_tree(
                    inputs,
                    profile.sid_string,
                    "(OI)(CI)(RX)",
                    user_access="(OI)(CI)(RX,DE,DC)",
                )
                grant_tree(scratch, profile.sid_string, "(OI)(CI)(F)")

            consume_attempt(runtime, binding.launch_nonce, binding_digest)

            launch_environment = _environment(scratch)
            windows_process = None
            posix_process = None
            tree = None
            if os.name == "nt":
                from tools.res555_gate_b2.windows import AppContainerProcess

                windows_process = AppContainerProcess.launch(
                    profile=profile,
                    application=runtime.interpreter,
                    arguments=("-I", str(runtime.bootstrap_path)),
                    working_directory=attempt,
                    environment=None,
                    memory_bytes=isolation.memory_limit_bytes,
                    cpu_seconds=isolation.cpu_time_seconds,
                    max_processes=isolation.max_processes,
                )
                process = windows_process
                external = {
                    "mechanism": isolation.mechanism,
                    "token": windows_process.token_observation,
                    "job": windows_process.job_accounting(),
                }
            else:
                cgroup = CgroupV2.create(
                    name=f"res555-{binding.launch_nonce[:16]}",
                    limits=CgroupLimits(
                        pids_max=isolation.max_processes,
                        memory_max_bytes=isolation.memory_limit_bytes,
                    ),
                )
                command = cgroup.launcher_command(
                    launcher_python=Path(sys.executable),
                    worker_program=runtime.interpreter,
                    worker_arguments=("-I", str(runtime.bootstrap_path)),
                )
                posix_process = subprocess.Popen(
                    command,
                    cwd=attempt,
                    env=launch_environment,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    bufsize=0,
                    close_fds=True,
                    start_new_session=True,
                )
                process = posix_process
                tree = PosixProcessTree(posix_process.pid)
                if not cgroup.verify_attached(posix_process.pid, 5.0):
                    cgroup.kill()
                    cgroup.close()
                    raise ProtectedLaunchError(
                        "the worker launcher did not attach to the supervisor cgroup"
                    )
                external = {
                    "mechanism": isolation.mechanism,
                    "ready": None,
                    "proc": {},
                    "cgroup": cgroup.observe().as_json(),
                }
            external["network_control"] = network_control

            def _on_scratch_overrun(_usage: ScratchUsage) -> None:
                if cgroup is not None:
                    cgroup.kill()
                try:
                    process.kill()
                except OSError:
                    pass

            if scratch_budget.enforcement == "sampled-watchdog":
                scratch_watchdog = ScratchWatchdog(
                    root=scratch,
                    limit_bytes=isolation.max_scratch_bytes,
                    interval_seconds=scratch_budget.watchdog_interval_seconds or 0.02,
                    on_overrun=_on_scratch_overrun,
                )
                scratch_watchdog.start()

            request_bytes = canonical_worker_request_bytes(request) + b"\n"
            if len(request_bytes) > MAX_WORKER_MESSAGE_BYTES:
                raise ProtectedLaunchError("the canonical request exceeds the protocol bound")
            assert process.stdin is not None
            assert process.stdout is not None
            assert process.stderr is not None
            stdin_writer = _Writer(process.stdin, request_bytes)
            stdout_reader = _BoundedReader(process.stdout, _MAX_STDOUT, fail_on_overflow=True)
            stderr_reader = _BoundedReader(process.stderr, _MAX_STDERR, fail_on_overflow=False)
            stdin_writer.start()
            stdout_reader.start()
            stderr_reader.start()
            deadline = time.monotonic() + isolation.wall_time_seconds
            ready_path = scratch / "sandbox-ready.json"
            while process.poll() is None:
                _capture_worker_ready(
                    ready_path,
                    None if posix_process is None else posix_process.pid,
                    external,
                )
                if stdout_reader.overflow.is_set():
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(_POLL_SECONDS)
            # A fast worker can write the ready marker and exit between poll ticks. Capture
            # the /proc facts before reaping it; this is the last point at which they exist.
            _capture_worker_ready(
                ready_path,
                None if posix_process is None else posix_process.pid,
                external,
            )
            reaped, cleaned = _terminate(
                process,
                tree,
                windows=windows_process is not None,
                cgroup=cgroup,
            )
            if scratch_watchdog is not None:
                scratch_watchdog.stop()
            stdin_writer.join(5.0)
            stdout_reader.join(5.0)
            stderr_reader.join(5.0)
            _capture_worker_ready(
                ready_path,
                None if posix_process is None else posix_process.pid,
                external,
            )
            stdout_bytes = bytes(stdout_reader.buffer)
            stderr_bytes = bytes(stderr_reader.buffer)
            exit_code = process.poll()
            response = None
            response_error = None
            try:
                response = parse_worker_response(stdout_bytes)
            except WorkerProtocolError as error:
                response_error = str(error)
            receipt_bytes: bytes | None = None
            receipt: ConsumptionReceipt | None = None
            receipt_error: str | None = None
            try:
                receipt_bytes = read_bounded_regular(
                    scratch / "consumption.json", limit=MAX_RECEIPT_BYTES
                )
                receipt = ConsumptionReceipt.model_validate_json(receipt_bytes)
                if canonical_semantic_bytes(receipt) != receipt_bytes:
                    receipt_error = "the receipt is not canonical"
            except Exception as error:  # noqa: BLE001 - a missing receipt is a refusal
                receipt_error = f"{type(error).__name__}"

            post_view: VerifiedWorkerInputs | None = None
            post_view_error: str | None = None
            try:
                post_view = verify_worker_input_view(inputs, expected=binding, request=request)
            except Exception as error:  # noqa: BLE001
                post_view_error = f"{type(error).__name__}"

            post_runtime_digest: str | None = None
            post_runtime_error: str | None = None
            try:
                post_runtime = measure_runtime_identity(
                    executable=runtime.interpreter,
                    base_prefix=runtime.base_prefix,
                    site_packages=runtime.site_packages,
                    source_root=runtime.source_root,
                    model_asset_relative="assets/reference_pendulum.xml",
                )
                post_runtime_digest = post_runtime.digest
            except Exception as error:  # noqa: BLE001
                post_runtime_error = f"{type(error).__name__}"

            usage = measure_scratch(scratch)
            scratch_bytes, scratch_files, scratch_links = usage.bytes, usage.files, usage.links
            scratch_unmeasured = usage.unmeasured
            capacity_ok = (
                scratch_budget.capacity_bytes is None
                or scratch_bytes <= scratch_budget.capacity_bytes
            )
            scratch_ok = (
                scratch_bytes <= isolation.max_scratch_bytes
                and scratch_links == 0
                and scratch_unmeasured == 0
                and capacity_ok
            )
            if cgroup is not None:
                cgroup_observation = cgroup.observe().as_json()
                external["cgroup"] = cgroup_observation
                cgroup_cleaned = cgroup.close()
            checks: list[dict[str, object]] = [
                _check("process_exit_zero", exit_code == 0, exit_code, 0),
                _check("stdin_delivered", stdin_writer.delivered, stdin_writer.delivered, True),
                _check("worker_reaped", reaped, reaped, True),
                _check("process_tree_cleaned", cleaned, cleaned, True),
                _check(
                    "response_valid",
                    response is not None,
                    response_error or "valid",
                    "one protocol v1 response",
                ),
            ]
            if cgroup is not None:
                assert cgroup_observation is not None
                pids_peak = cgroup_observation.get("pids_peak")
                pids_events_max = cgroup_observation.get("pids_events_max")
                assert isinstance(pids_peak, int)
                assert isinstance(pids_events_max, int)
                checks.append(
                    _check(
                        "cgroup_process_limit",
                        pids_peak <= isolation.max_processes and pids_events_max == 0,
                        cgroup_observation,
                        {
                            "pids_peak_at_most": isolation.max_processes,
                            "pids_events_max": 0,
                        },
                    )
                )
                checks.append(
                    _check(
                        "cgroup_tree_cleaned",
                        cgroup_cleaned and not bool(cgroup_observation["populated"]),
                        cgroup_observation,
                        "an empty attempt subtree",
                    )
                )
            response_matches = bool(
                response is not None
                and response.protocol_version == request.protocol_version
                and response.run_id == request.run_id
                and response.execution_fingerprint == request.execution_fingerprint
                and response.environment == request.environment
                and response.adapter == request.adapter
            )
            checks.append(
                _check("response_matches_request", response_matches, response_matches, True)
            )
            checks.append(
                _check(
                    "response_completed",
                    response is not None and response.status is WorkerStatus.COMPLETED,
                    None if response is None else response.status.value,
                    WorkerStatus.COMPLETED.value,
                )
            )
            checks.append(
                _check(
                    "receipt_present", receipt is not None, receipt_error or "present", "present"
                )
            )
            checks.append(
                _check(
                    "receipt_canonical",
                    receipt_error is None,
                    receipt_error or "canonical",
                    "canonical",
                )
            )
            numerical_reference: dict[str, object] | None = None
            if receipt is not None:
                receipt_checks = {
                    "receipt_completed": (receipt.completed, True),
                    "receipt_failure_absent": (receipt.failure, None),
                    "receipt_run_id": (receipt.run_id, str(request.run_id)),
                    "receipt_nonce": (receipt.attempt_nonce, binding.launch_nonce),
                    "receipt_binding": (receipt.binding_sha256, binding_digest),
                    "receipt_request": (receipt.request_sha256, binding.request_sha256),
                    "receipt_preflight": (receipt.preflight_sha256, binding.preflight_sha256),
                    "receipt_manifest": (
                        receipt.input_manifest_sha256,
                        binding.input_manifest_sha256,
                    ),
                    "receipt_fingerprint": (
                        receipt.execution_fingerprint,
                        request.execution_fingerprint.hex,
                    ),
                    "receipt_environment": (
                        receipt.environment_sha256,
                        binding.environment_sha256,
                    ),
                    "receipt_worker_selection": (
                        receipt.worker_selection_sha256,
                        binding.worker_selection_sha256,
                    ),
                    "receipt_runtime": (receipt.runtime_closure_sha256, runtime.snapshot.digest),
                    "receipt_profile": (
                        receipt.isolation_profile_sha256,
                        isolation.digest(),
                    ),
                    "receipt_adapter": (
                        receipt.adapter_implementation_sha256,
                        binding.adapter_implementation_sha256,
                    ),
                }
                for name, (observed, expected) in receipt_checks.items():
                    checks.append(_check(name, observed == expected, observed, expected))
                if receipt.runtime_summary is not None:
                    summary = receipt.runtime_summary
                    checks.append(
                        _check(
                            "receipt_runtime_roots",
                            summary.base_digest == runtime.snapshot.base.digest
                            and summary.site_packages_digest
                            == runtime.snapshot.site_packages_closure.digest
                            and summary.source_digest == runtime.snapshot.source.digest
                            and summary.executable_sha256 == runtime.snapshot.executable_sha256,
                            summary.model_dump(mode="json"),
                            "the measured snapshot roots",
                        )
                    )
                else:
                    checks.append(_check("receipt_runtime_roots", False, None, "a runtime summary"))
                checks.append(
                    _check(
                        "receipt_probes",
                        bool(receipt.probes)
                        and all(
                            probe.passed
                            for probe in receipt.probes
                            if probe.name not in _NETWORK_PROBE_NAMES
                        ),
                        [
                            probe.name
                            for probe in receipt.probes
                            if probe.name not in _NETWORK_PROBE_NAMES and not probe.passed
                        ],
                        "every file/isolation probe observed its expected outcome",
                    )
                )
                network_probes = {
                    probe.name: probe
                    for probe in receipt.probes
                    if probe.name in _NETWORK_PROBE_NAMES
                }
                tcp_probe = network_probes.get("network_connect")
                udp_probe = network_probes.get("network_udp")
                raw_probe = network_probes.get("network_raw")
                unix_probe = network_probes.get("network_unix")
                socketpair_probe = network_probes.get("network_socketpair")
                io_uring_probe = network_probes.get("io_uring_setup")
                inherited_probe = network_probes.get("inherited_sockets")
                checks.append(
                    _check(
                        "network_tcp_denied",
                        canary.tcp_connections == 0
                        and tcp_probe is not None
                        and tcp_probe.observed == "denied",
                        {
                            "canary_connections": canary.tcp_connections,
                            "worker": None if tcp_probe is None else tcp_probe.observed,
                            "canary_control": network_control.get("tcp"),
                        },
                        "zero localhost connections and a denied connect",
                    )
                )
                checks.append(
                    _check(
                        "network_udp_not_delivered",
                        canary.udp_datagrams == 0
                        and (
                            os.name == "nt"
                            or (udp_probe is not None and udp_probe.observed == "denied")
                        ),
                        {
                            "canary_datagrams": canary.udp_datagrams,
                            "worker": None if udp_probe is None else udp_probe.observed,
                            "canary_control": network_control.get("udp"),
                        },
                        "zero localhost datagrams after a successful canary control; on Linux the "
                        "worker's UDP socket is denied as well; on Windows a successful sendto "
                        "is recorded but is not delivery evidence, and this is not a universal "
                        "UDP-denial claim",
                    )
                )
                checks.append(
                    _check(
                        "network_canary_control",
                        all(network_control.values()),
                        network_control,
                        "each active localhost canary received the supervisor's control traffic",
                    )
                )
                checks.append(
                    _check(
                        "network_raw_denied",
                        raw_probe is not None and raw_probe.observed == "denied",
                        None if raw_probe is None else raw_probe.observed,
                        "denied",
                    )
                )
                unix_unavailable = bool(
                    unix_probe is not None
                    and unix_probe.observed == "error"
                    and "unavailable" in unix_probe.detail
                )
                checks.append(
                    _check(
                        "network_unix_denied",
                        unix_probe is not None
                        and (unix_probe.observed == "denied" or unix_unavailable)
                        and canary.unix_connections == 0,
                        {
                            "canary_connections": canary.unix_connections,
                            "canary_control": network_control.get("unix"),
                            "worker": None if unix_probe is None else unix_probe.observed,
                            "worker_detail": None if unix_probe is None else unix_probe.detail,
                        },
                        "zero Unix-domain connections and a denied socket (or an unavailable "
                        "AF_UNIX family, which is not a communication path)",
                    )
                )
                checks.append(
                    _check(
                        "network_socketpair_denied",
                        os.name == "nt"
                        or (socketpair_probe is not None and socketpair_probe.observed == "denied"),
                        None if socketpair_probe is None else socketpair_probe.observed,
                        "denied on Linux; local IPC remains on Windows",
                    )
                )
                if os.name != "nt":
                    checks.append(
                        _check(
                            "seccomp_io_uring_denied",
                            io_uring_probe is not None and io_uring_probe.observed == "denied",
                            None if io_uring_probe is None else io_uring_probe.observed,
                            "io_uring_setup denied by the seccomp policy",
                        )
                    )
                    checks.append(
                        _check(
                            "inherited_sockets_absent",
                            inherited_probe is not None and inherited_probe.observed == "denied",
                            None if inherited_probe is None else inherited_probe.observed,
                            "no inherited socket descriptors",
                        )
                    )
                if mode == "materialized-mujoco":
                    checks.append(
                        _check(
                            "receipt_engine_imported",
                            receipt.engine_imported,
                            receipt.engine_imported,
                            True,
                        )
                    )
                    checks.append(
                        _check(
                            "receipt_model_present",
                            receipt.model is not None,
                            receipt.model is not None,
                            True,
                        )
                    )
                    if receipt.model is not None:
                        checks.append(
                            _check(
                                "receipt_model_hash",
                                receipt.model.sha256 == reference.MODEL_SHA256,
                                receipt.model.sha256,
                                reference.MODEL_SHA256,
                            )
                        )
                        checks.append(
                            _check(
                                "receipt_model_source",
                                receipt.model.source == "input_view",
                                receipt.model.source,
                                "input_view",
                            )
                        )
                        checks.append(
                            _check(
                                "receipt_package_asset_absent",
                                not receipt.model.package_asset_present
                                and receipt.model.package_asset_probe == "denied",
                                receipt.model.package_asset_probe,
                                "denied",
                            )
                        )
                    checks.append(
                        _check(
                            "receipt_steps",
                            receipt.physics is not None
                            and receipt.physics.steps == reference.STEPS,
                            None if receipt.physics is None else receipt.physics.steps,
                            reference.STEPS,
                        )
                    )
                    observed_trajectory = (
                        None if receipt.physics is None else receipt.physics.trajectory_sha256
                    )
                    assert expected_trajectory_sha256 is not None
                    trajectory_matches = observed_trajectory == expected_trajectory_sha256
                    checks.append(
                        _check(
                            "receipt_trajectory_reference",
                            trajectory_matches,
                            observed_trajectory,
                            expected_trajectory_sha256,
                        )
                    )
                    numerical_reference = {
                        "expected_trajectory_sha256": expected_trajectory_sha256,
                        "observed_trajectory_sha256": observed_trajectory,
                        "matches": trajectory_matches,
                    }
                else:
                    checks.append(
                        _check(
                            "receipt_engine_not_imported",
                            receipt.engine_imported is False,
                            receipt.engine_imported,
                            False,
                        )
                    )
            checks.append(
                _check(
                    "input_view_unchanged",
                    post_view is not None and post_view == pre_view,
                    post_view_error or "unchanged",
                    "the pre-launch verified view",
                )
            )
            checks.append(
                _check(
                    "runtime_unchanged",
                    post_runtime_digest == runtime.snapshot.digest,
                    post_runtime_error or post_runtime_digest,
                    runtime.snapshot.digest,
                )
            )
            checks.append(
                _check(
                    "network_denied",
                    canary.tcp_connections == 0
                    and canary.udp_datagrams == 0
                    and canary.unix_connections == 0,
                    {
                        "tcp_connections": canary.tcp_connections,
                        "udp_datagrams": canary.udp_datagrams,
                        "unix_connections": canary.unix_connections,
                        "canary_control": network_control,
                    },
                    "zero worker localhost TCP connections, UDP datagrams and Unix-domain "
                    "connections after each active canary received its control traffic",
                )
            )
            checks.append(
                _check(
                    "scratch_within_limit",
                    scratch_ok,
                    {
                        "bytes": scratch_bytes,
                        "files": scratch_files,
                        "links": scratch_links,
                        "unmeasured": scratch_unmeasured,
                        "limit_bytes": isolation.max_scratch_bytes,
                        "backend": scratch_budget.enforcement,
                        "capacity_bytes": scratch_budget.capacity_bytes,
                        "available_bytes": scratch_available,
                    },
                    scratch_budget.detail,
                )
            )
            checks.append(
                _check(
                    "scratch_headroom",
                    scratch_available >= headroom_required,
                    {
                        "available_bytes": scratch_available,
                        "required_bytes": headroom_required,
                    },
                    "the scratch volume can absorb the configured bound",
                )
            )
            if scratch_watchdog is not None:
                checks.append(
                    _check(
                        "scratch_watchdog_not_triggered",
                        not scratch_watchdog.triggered,
                        {
                            "triggered": scratch_watchdog.triggered,
                            "peak_bytes": scratch_watchdog.peak_bytes,
                            "samples": scratch_watchdog.samples,
                            "unmeasured_samples": scratch_watchdog.unmeasured_samples,
                            "peak_unmeasured": scratch_watchdog.peak_unmeasured,
                        },
                        "a sampled watchdog that observed no over-budget write",
                    )
                )
                external["scratch_watchdog"] = {
                    "triggered": scratch_watchdog.triggered,
                    "peak_bytes": scratch_watchdog.peak_bytes,
                    "samples": scratch_watchdog.samples,
                    "unmeasured_samples": scratch_watchdog.unmeasured_samples,
                    "peak_unmeasured": scratch_watchdog.peak_unmeasured,
                    "interval_seconds": scratch_watchdog.interval_seconds,
                }
            unexpected_writes = [str(path) for path in forbidden_writes if path.exists()]
            checks.append(
                _check(
                    "forbidden_writes_absent",
                    not unexpected_writes,
                    unexpected_writes,
                    [],
                )
            )
            if runtime_write.exists():
                runtime_write.unlink(missing_ok=True)
                checks.append(
                    _check(
                        "runtime_write_denied",
                        False,
                        "the worker wrote a runtime file",
                        "denied",
                    )
                )
            else:
                checks.append(_check("runtime_write_denied", True, "denied", "denied"))
            if windows_process is not None:
                token_observation = windows_process.token_observation
                checks.append(
                    _check(
                        "external_appcontainer",
                        bool(token_observation.get("is_appcontainer"))
                        and bool(token_observation.get("sid_matches"))
                        and int(token_observation.get("capability_count", -1)) == 0,
                        token_observation,
                        "an appcontainer token with the expected package SID and zero package "
                        "capabilities; elevation and privileges are recorded, not claimed "
                        "absent, and a production launch must not rely on the elevated CI "
                        "principal as its isolation fact",
                    )
                )
            else:
                ready = external.get("ready")
                proc = external.get("proc", {})
                raw_abi = ready.get("abi") if isinstance(ready, dict) else None
                abi = raw_abi if isinstance(raw_abi, int) else -1
                raw_filters = proc.get("seccomp_filters")
                try:
                    seccomp_filters = int(str(raw_filters)) if raw_filters is not None else 0
                except ValueError:
                    seccomp_filters = 0
                checks.append(
                    _check(
                        "external_proc_facts",
                        proc.get("no_new_privs") == "1"
                        and str(proc.get("cap_eff", "")).lower() == "0000000000000000"
                        and proc.get("seccomp") == "2"
                        and seccomp_filters >= 1,
                        proc,
                        "supervisor-read /proc facts: NoNewPrivs=1, zero effective "
                        "capabilities and seccomp filter mode with at least one filter",
                    )
                )
                checks.append(
                    _check(
                        "worker_landlock_echo",
                        isinstance(ready, dict)
                        and ready.get("mechanism") == "linux-landlock"
                        and abi >= 4,
                        ready,
                        "worker-authored configuration echo (corroboration, not independent "
                        "proof); the ABI/mechanism claim is not supervisor-read",
                    )
                )
                external_cgroup_path = external.get("cgroup_path")
                checks.append(
                    _check(
                        "external_cgroup",
                        cgroup is not None
                        and isinstance(external_cgroup_path, str)
                        and external_cgroup_path.endswith("/" + cgroup.path.name),
                        {
                            "proc_cgroup": external_cgroup_path,
                            "expected_suffix": None if cgroup is None else "/" + cgroup.path.name,
                        },
                        "the worker's own cgroup membership, read from /proc by the supervisor",
                    )
                )
                fds = external.get("fds")
                sockets = fds.get("sockets") if isinstance(fds, dict) else None
                checks.append(
                    _check(
                        "external_inherited_sockets_absent",
                        isinstance(fds, dict)
                        and fds.get("readable") is True
                        and isinstance(sockets, list)
                        and not sockets,
                        fds,
                        "a readable descriptor table with no socket descriptors",
                    )
                )
            ready = external.get("ready")
            allowed_environment, required_environment = _environment_policy(scratch)
            if isinstance(ready, dict) and isinstance(ready.get("environment_keys"), list):
                observed_keys = {str(name) for name in ready["environment_keys"]}
            else:
                observed_keys = set()
            unexpected_environment = sorted(observed_keys - allowed_environment)
            missing_environment = sorted(required_environment - observed_keys)
            checks.append(
                _check(
                    "environment_sanitized",
                    isinstance(ready, dict)
                    and ready.get("environment_sanitized") is True
                    and not unexpected_environment
                    and not missing_environment,
                    {
                        "unexpected": unexpected_environment,
                        "missing": missing_environment,
                    },
                    "the worker echo contains exactly the launch-policy names (the echo is "
                    "not independent proof)",
                )
            )
            checks.append(
                _check(
                    "headless_gl",
                    "MUJOCO_GL" in observed_keys
                    and b"pyvenv.cfg" not in stderr_bytes
                    and b"GLFW" not in stderr_bytes,
                    {
                        "mujoco_gl": "MUJOCO_GL" in observed_keys,
                        "stderr_has_venv_error": b"pyvenv.cfg" in stderr_bytes,
                        "stderr_has_glfw_error": b"GLFW" in stderr_bytes,
                    },
                    "the headless worker starts no GLFW helper and has no venv config error",
                )
            )
            checks.append(
                _check(
                    "sandbox_ready_binding",
                    isinstance(ready, dict)
                    and ready.get("profile_sha256") == isolation.digest()
                    and ready.get("runtime_closure_sha256") == runtime.snapshot.digest,
                    ready,
                    "the measured profile and runtime closure",
                )
            )
            checks.append(
                _check(
                    "sandbox_config_written",
                    sandbox_digest == sha256_bytes((attempt / "sandbox.json").read_bytes()),
                    sandbox_digest,
                    "the exact written sandbox config",
                )
            )
            verdict = (
                "demonstrated" if all(bool(check["passed"]) for check in checks) else "refused"
            )
            refusals = tuple(str(check["name"]) for check in checks if not bool(check["passed"]))
            observation = SupervisorObservation(
                verdict=verdict,
                refusals=refusals,
                profile=isolation,
                attempt_nonce=binding.launch_nonce,
                binding_sha256=binding_digest,
                request_sha256=binding.request_sha256,
                input_manifest_sha256=binding.input_manifest_sha256,
                execution_fingerprint=request.execution_fingerprint.hex,
                source_runtime=summarize_runtime(runtime.source),
                snapshot_runtime=summarize_runtime(runtime.snapshot),
                worker_runtime=(
                    receipt.runtime_summary.model_dump(mode="json")
                    if receipt is not None and receipt.runtime_summary is not None
                    else None
                ),
                runtime_matches=bool(
                    receipt is not None
                    and receipt.runtime_closure_sha256 == runtime.snapshot.digest
                    and post_runtime_digest == runtime.snapshot.digest
                ),
                external_isolation=external,
                receipt_sha256=(sha256_bytes(receipt_bytes) if receipt_bytes is not None else None),
                receipt=receipt,
                numerical_reference=numerical_reference,
                process={
                    "exit_code": exit_code,
                    "pid": int(process.pid),
                    "reaped": reaped,
                    "tree_cleaned": cleaned,
                    "stdin_delivered": stdin_writer.delivered,
                    "stdout_bytes": len(stdout_bytes),
                    "stderr_bytes": len(stderr_bytes),
                    "stdout_truncated": stdout_reader.truncated,
                    "stderr_truncated": stderr_reader.truncated,
                    "stderr_excerpt": stderr_bytes[:4096].decode("utf-8", "replace"),
                    "scratch": {
                        "bytes": scratch_bytes,
                        "files": scratch_files,
                        "links": scratch_links,
                        "unmeasured": scratch_unmeasured,
                        "limit_bytes": isolation.max_scratch_bytes,
                        "capacity_bytes": scratch_budget.capacity_bytes,
                        "available_bytes": scratch_available,
                        "backend": scratch_budget.enforcement,
                        "detail": scratch_budget.detail,
                        "within_limit": scratch_ok,
                    },
                    "cgroup": cgroup_observation,
                    "cgroup_cleaned": cgroup_cleaned,
                    "scratch_watchdog": None
                    if scratch_watchdog is None
                    else {
                        "triggered": scratch_watchdog.triggered,
                        "peak_bytes": scratch_watchdog.peak_bytes,
                        "samples": scratch_watchdog.samples,
                        "unmeasured_samples": scratch_watchdog.unmeasured_samples,
                        "peak_unmeasured": scratch_watchdog.peak_unmeasured,
                        "interval_seconds": scratch_watchdog.interval_seconds,
                    },
                },
                response={
                    "valid": response is not None,
                    "status": None if response is None else response.status.value,
                    "matches_request": response_matches,
                    "message": None if response is None else response.message,
                    "error": response_error,
                },
                checks=tuple(checks),
            )
            observation_path = None
            if evidence_dir is not None:
                assert evidence_name is not None
                evidence_dir.mkdir(parents=True, exist_ok=True)
                observation_path = evidence_dir / evidence_name
                write_canonical_atomic(observation_path, observation, limit=2 * 1024 * 1024)
            return ProbeLaunchResult(observation=observation, observation_path=observation_path)
        finally:
            canary.close()
    finally:
        if scratch_watchdog is not None:
            scratch_watchdog.stop()
        if cgroup is not None:
            cgroup.close()
        for sentinel in sentinels:
            sentinel.unlink(missing_ok=True)
        for path in forbidden_writes:
            path.unlink(missing_ok=True)
        if windows_process is not None:
            windows_process.close()
        shutil.rmtree(attempt, ignore_errors=True)
        if created_parent is not None:
            shutil.rmtree(created_parent, ignore_errors=True)
        if os.name == "nt":
            from tools.res555_gate_b2.windows import restore_user_control

            try:
                restore_user_control(runtime.root)
            except Exception:  # noqa: BLE001 - cleanup must not mask the observation
                pass
