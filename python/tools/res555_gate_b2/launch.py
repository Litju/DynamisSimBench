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
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from tools.res555_gate_b2.profile import build_profile, mechanism_available
from tools.res555_gate_b2.runtime import ProtectedRuntime
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
    attempts = runtime.root.parent / "attempts"
    attempts.mkdir(parents=True, exist_ok=True)
    marker = attempts / f"{nonce}.used"
    try:
        descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise ProtectedLaunchError("this binding was already used") from error
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(binding_sha256.encode("ascii"))
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
    """A localhost listener that would accept a connection if network denial failed."""

    def __init__(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(1)
        self._socket.settimeout(0.2)
        self.port = int(self._socket.getsockname()[1])
        self.accepted = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except (TimeoutError, OSError):
                continue
            self.accepted += 1
            try:
                connection.close()
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        try:
            self._socket.close()
        except OSError:
            pass
        self._thread.join(1.0)


def _check(name: str, passed: bool, observed: object, limit: object) -> dict[str, object]:
    return {"name": name, "passed": bool(passed), "observed": observed, "limit": limit}


def _environment(scratch: Path) -> dict[str, str]:
    values = {
        "DYNAMISBENCH_RES555_B2_PROBE": "1",
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
        "cap_eff": values.get("CapEff"),
        "cap_prm": values.get("CapPrm"),
        "cap_bnd": values.get("CapBnd"),
        "uid": values.get("Uid"),
        "gid": values.get("Gid"),
    }


def _terminate(process: Any, tree: PosixProcessTree | None, *, windows: bool) -> tuple[bool, bool]:
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
    if tree is not None:
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
    cleaned = tree.wait_empty(5.0) if tree is not None else False
    return reaped, cleaned


def _create_sentinel(root: Path, token: str, *, create_root: bool) -> Path:
    if create_root:
        root.mkdir(parents=True, exist_ok=True)
    path = root / f"res555-b2-sentinel-{token}.txt"
    path.write_bytes(f"RES555-B2-SENTINEL {token}\n".encode())
    return path


def _linux_allowlists(
    runtime: ProtectedRuntime, attempt: Path, inputs: Path, scratch: Path
) -> tuple[list[str], list[str], list[str]]:
    system = [
        Path("/usr"),
        Path("/lib"),
        Path("/lib64"),
        Path("/bin"),
        Path("/sbin"),
        Path("/etc/ld.so.cache"),
        Path("/etc/localtime"),
        Path("/dev/urandom"),
        Path("/proc/cpuinfo"),
        Path("/sys/devices/system/cpu"),
    ]
    read_execute = [str(path) for path in system if path.exists()]
    read_execute.append(str(runtime.base_prefix))
    read_execute.append(str(runtime.interpreter.resolve().parent))
    read_only = [
        str(runtime.site_packages),
        str(runtime.source_root),
        str(attempt),
        str(inputs),
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
    evidence_dir: Path | None = None,
) -> ProbeLaunchResult:
    """Verify, launch and observe one probe attempt, or refuse before any process."""
    assert_probe_authorized()
    tag = platform_tag or reference.platform_tag()
    isolation = build_profile(tag)
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
    parent = sandbox_parent if sandbox_parent is not None else runtime.root.parent
    attempt = parent / f"attempt-{binding.launch_nonce[:16]}"
    inputs = attempt / "inputs"
    scratch = attempt / "scratch"
    if attempt.exists():
        raise ProtectedLaunchError("the attempt directory already exists")
    scratch.mkdir(parents=True)
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
    try:
        for root in forbidden_read_roots:
            sentinels.append(_create_sentinel(root, token, create_root=root in {staging, sealed}))
        forbidden_writes = [
            inputs / "forbidden-write.txt",
            staging / f"res555-b2-write-{token}.txt",
            sealed / f"res555-b2-write-{token}.txt",
        ]
        runtime_write = runtime.source_root / "dynamisbench" / f"res555-b2-write-{token}.txt"
        canary = _NetworkCanary()
        try:
            targets = ProbeTargets(
                forbidden_reads=tuple(str(path) for path in sentinels),
                forbidden_writes=tuple(str(path) for path in forbidden_writes),
                forbidden_deletes=(str(inputs / "binding.json"),),
                allowed_read=str(inputs / "binding.json"),
                allowed_write=str(scratch / "probe-write.txt"),
                runtime_write=str(runtime_write),
                network_port=canary.port,
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

                grant_tree(runtime.root, profile.sid_string, "(OI)(CI)(RX)")
                grant_tree(attempt, profile.sid_string, "(OI)(CI)(RX)")
                grant_tree(inputs, profile.sid_string, "(OI)(CI)(RX)")
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
                posix_process = subprocess.Popen(
                    [str(runtime.interpreter), "-I", str(runtime.bootstrap_path)],
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
                external = {
                    "mechanism": isolation.mechanism,
                    "ready": None,
                    "proc": {},
                }

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
                if external.get("ready") is None and ready_path.is_file():
                    try:
                        ready = json.loads(ready_path.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        ready = {"invalid": True}
                    external["ready"] = ready
                    if posix_process is not None:
                        external["proc"] = _read_proc_status(posix_process.pid)
                if stdout_reader.overflow.is_set():
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(_POLL_SECONDS)
            reaped, cleaned = _terminate(process, tree, windows=windows_process is not None)
            stdin_writer.join(5.0)
            stdout_reader.join(5.0)
            stderr_reader.join(5.0)
            if posix_process is not None and external.get("ready") is None and ready_path.is_file():
                try:
                    external["ready"] = json.loads(ready_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    external["ready"] = {"invalid": True}
                external["proc"] = _read_proc_status(posix_process.pid)
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
            if receipt is not None:
                receipt_checks = {
                    "receipt_completed": (receipt.completed, True),
                    "receipt_nonce": (receipt.attempt_nonce, binding.launch_nonce),
                    "receipt_binding": (receipt.binding_sha256, binding_digest),
                    "receipt_request": (receipt.request_sha256, binding.request_sha256),
                    "receipt_manifest": (
                        receipt.input_manifest_sha256,
                        binding.input_manifest_sha256,
                    ),
                    "receipt_fingerprint": (
                        receipt.execution_fingerprint,
                        request.execution_fingerprint.hex,
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
                        bool(receipt.probes) and all(probe.passed for probe in receipt.probes),
                        [probe.name for probe in receipt.probes if not probe.passed],
                        "every probe observed its expected outcome",
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
            checks.append(_check("network_denied", canary.accepted == 0, canary.accepted, 0))
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
                        and not bool(token_observation.get("elevated")),
                        token_observation,
                        "an appcontainer token with the expected SID and no elevation",
                    )
                )
            else:
                ready = external.get("ready")
                proc = external.get("proc", {})
                checks.append(
                    _check(
                        "external_landlock",
                        isinstance(ready, dict)
                        and ready.get("mechanism") == "linux-landlock"
                        and int(ready.get("abi", 0)) >= 4
                        and proc.get("no_new_privs") == "1"
                        and str(proc.get("cap_eff", "")).lower() == "0000000000000000",
                        {"ready": ready, "proc": proc},
                        "Landlock ABI 4+, NoNewPrivs=1 and zero effective capabilities",
                    )
                )
            ready = external.get("ready")
            checks.append(
                _check(
                    "environment_sanitized",
                    isinstance(ready, dict) and ready.get("environment_sanitized") is True,
                    ready,
                    "the bootstrap replaced the inherited environment before importing",
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
                evidence_dir.mkdir(parents=True, exist_ok=True)
                observation_path = evidence_dir / f"{tag}.json"
                write_canonical_atomic(observation_path, observation, limit=2 * 1024 * 1024)
            return ProbeLaunchResult(observation=observation, observation_path=observation_path)
        finally:
            canary.close()
    finally:
        for sentinel in sentinels:
            sentinel.unlink(missing_ok=True)
        for path in forbidden_writes:
            path.unlink(missing_ok=True)
        shutil.rmtree(attempt, ignore_errors=True)
