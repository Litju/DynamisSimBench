"""The protected pinned-reference launch boundary used by the supervisor.

This module connects five things that were qualified separately:

* the frozen :class:`~dynamisbench.execution.protected_profile.PinnedReferenceProfile`;
* a measured :class:`~dynamisbench.execution.protected_runtime.ProtectedRuntime` snapshot;
* the A1-verified read-only input view for one prepared run;
* the platform launch mechanism (Windows AppContainer + Job Object, or Linux Landlock +
  seccomp + cgroup v2);
* the supervisor's bounded request/response, deadline, cancellation, reaping and staging
  lifecycle.

It is an *internal* boundary. Nothing in :mod:`dynamisbench.api`, :mod:`dynamisbench.cli`,
the desktop shell or the workbench imports it, and the supervisor runs the diagnostic route
unless a caller explicitly passes a :class:`ProtectedExecutionRoute`. Constructing a route is
the activation decision: it measures a runtime snapshot and opens the host mechanism.

**Never a fallback.** Every precondition failure raises :class:`ProtectedLaunchError`
before a process exists, or produces a correlated refusal after exit. There is no code path
that starts an unsandboxed worker because the sandbox is unavailable, the receipt is missing,
the runtime moved, or a limit was exceeded.

**The worker is untrusted, but not independently re-executed.** ``scratch/consumption.json``
is read as untrusted input and correlated with the supervisor's own measurements: the exact
runtime roots, the verified input view, the external token/``proc`` facts, the single-use
binding and the committed reference constants. That makes the *process* admissible; it does
not independently reproduce the physics. A worker that fabricates a canonical receipt with
the pinned constants is not excluded by this boundary, which is why the pinned adapter is
trusted code and why the persisted record is a supervisor-authored diagnostic
(``protected-consumption.json``) rather than native evidence, canonical output, an
assessment or a seal.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, Protocol, cast

from pydantic import ConfigDict, Field

from dynamisbench.adapters.mujoco import reference
from dynamisbench.adapters.mujoco.protected_contracts import (
    MAX_RECEIPT_BYTES,
    ConsumptionReceipt,
    ProbeObservation,
    ProbeTargets,
    RuntimeSummary,
    measure_runtime_identity,
    read_bounded_regular,
    sha256_bytes,
    sha256_file,
    summarize_runtime,
)
from dynamisbench.domain.spec.base import DomainModel
from dynamisbench.domain.spec.identifiers import Sha256Hex
from dynamisbench.evidence.bundle import RunId
from dynamisbench.evidence.staging import StagingBundle
from dynamisbench.execution._process_tree import PosixProcessTree
from dynamisbench.execution.contracts import (
    Refusal,
    RefusalCode,
    RunLifecycleState,
    WorkerRequest,
    WorkerResponse,
    canonical_worker_request_bytes,
    refusal,
)
from dynamisbench.execution.environment import WorkerEnvironmentManifest
from dynamisbench.execution.input_binding import (
    WorkerInputBinding,
    build_worker_input_binding,
)
from dynamisbench.execution.input_verification import (
    VerifiedWorkerInputs,
    verify_worker_input_view,
)
from dynamisbench.execution.preflight import PreparedExecutionInputs
from dynamisbench.execution.protected_profile import (
    PROTECTED_RECEIPT_SCHEMA,
    PROTECTED_SUPERVISOR_RECORD_NAME,
    PROTECTED_SUPERVISOR_RECORD_SCHEMA,
    PinnedReferenceProfile,
    build_protected_profile,
)
from dynamisbench.execution.protected_runtime import (
    ProtectedRuntime,
    ProtectedRuntimeError,
    build_protected_sandbox_config,
    prepare_protected_runtime,
    protected_environment,
    protected_runtime_digest,
    protected_worker_command,
    write_protected_sandbox_config,
)
from dynamisbench.execution.protected_scratch import (
    ScratchBudget,
    ScratchBudgetError,
    ScratchUsage,
    ScratchWatchdog,
    measure_scratch,
    resolve_scratch_budget,
    scratch_headroom,
)
from dynamisbench.host.protected_canary import ProtectedNetworkCanary
from dynamisbench.identity import canonical_semantic_bytes, semantic_sha256
from dynamisbench.materialization import (
    MaterializationError,
    MaterializationRefusalCode,
    MaterializationStore,
)
from dynamisbench.workspace import PersistenceClass, Workspace

__all__ = [
    "PROTECTED_RECORD_MEDIA_TYPE",
    "ProtectedAttempt",
    "ProtectedConsumptionRecord",
    "ProtectedExecutionRoute",
    "ProtectedLaunchError",
    "ProtectedRun",
    "ProtectedTree",
    "RuntimeExpectation",
    "begin_protected_attempt",
    "correlate_receipt",
    "prepare_protected_route",
    "write_protected_input_view",
]

PROTECTED_RECORD_MEDIA_TYPE: Final = "application/vnd.dynamisbench.protected-consumption+json"
"""How ``protected-consumption.json`` is described: a supervisor diagnostic, not evidence."""

_MODEL_ASSET_RELATIVE: Final = "assets/reference_pendulum.xml"
_WORKER_ENTRY_RELATIVE: Final = "dynamisbench/adapters/mujoco/protected_worker.py"
_TIME_TOLERANCE_S: Final = 1e-9
_MAX_SANDBOX_READY_BYTES: Final = 64 * 1024
_MAX_SMALL_FILE_BYTES: Final = 256 * 1024
_POLL_SECONDS: Final = 0.02

_LINUX_SYSTEM_READ_EXECUTE: Final = (
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib",
    "/lib",
    "/lib64",
    "/etc/ld.so.cache",
    "/etc/localtime",
    "/dev/urandom",
    "/proc/cpuinfo",
    "/proc/sys/kernel/seccomp",
    "/sys/devices/system/cpu",
)

_NON_GATING_PROBES_WINDOWS: Final = frozenset(
    {
        "network_udp",
        "network_unix",
        "network_socketpair",
        "io_uring_setup",
        "inherited_sockets",
    }
)
"""Windows probe outcomes that record a limitation instead of gating the attempt.

A successful ``sendto`` is not delivery evidence (the canary is), the Windows descriptor
table is checked by the supervised handle list rather than a POSIX ``/proc`` walk, and
``io_uring``/AF_UNIX are not Windows facilities. The Linux route gates on every probe.
"""


class ProtectedLaunchError(RuntimeError):
    """A protected attempt was refused before any process was created.

    ``code`` is the closed protocol refusal the supervisor records. The exception exists so
    the launcher can refuse with a specific reason without inventing a second refusal
    vocabulary; it never escapes :func:`execute_preflighted`.
    """

    def __init__(self, code: RefusalCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# --------------------------------------------------------------------------------------
# Supervisor-authored record
# --------------------------------------------------------------------------------------


class ProtectedConsumptionRecord(DomainModel):
    """The supervisor's correlated account of one protected attempt.

    Every field is either a digest the supervisor measured, a fact the supervisor observed
    from outside the worker, or a bounded echo of the worker's untrusted receipt. It carries
    no native output, no canonical quantity and no scientific verdict.

    The record is written into mutable staging as ``protected-consumption.json``. It is not
    sealed by the execution boundary and it is never promoted to ``native/``; ADR-027 owns
    native output and remains proposed.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        populate_by_name=True,
        serialize_by_alias=True,
    )

    schema_id: Literal["dynamisbench.protected-consumption/1"] = Field(
        default=PROTECTED_SUPERVISOR_RECORD_SCHEMA, alias="schema"
    )
    run_id: RunId
    execution_fingerprint: Sha256Hex
    state: RunLifecycleState
    refusals: tuple[str, ...]
    platform: str
    mechanism: str
    profile_sha256: Sha256Hex
    adapter_implementation_sha256: Sha256Hex
    model_sha256: Sha256Hex
    reference_trajectory_sha256: Sha256Hex
    binding_sha256: Sha256Hex
    request_sha256: Sha256Hex
    preflight_sha256: Sha256Hex
    input_manifest_sha256: Sha256Hex
    environment_sha256: Sha256Hex
    worker_selection_sha256: Sha256Hex
    launch_nonce: Sha256Hex
    bootstrap_sha256: Sha256Hex
    worker_entry_sha256: Sha256Hex
    sandbox_config_sha256: Sha256Hex
    runtime_closure_sha256: Sha256Hex
    source_runtime_digest: Sha256Hex
    snapshot_runtime_digest: Sha256Hex
    post_runtime_digest: Sha256Hex | None
    worker_runtime_digest: Sha256Hex | None
    venv_config_sha256: Sha256Hex | None
    view_before_digest: Sha256Hex
    view_after_digest: Sha256Hex | None
    view_files: tuple[dict[str, object], ...]
    receipt_present: bool
    receipt_canonical: bool
    receipt_sha256: Sha256Hex | None
    receipt_completed: bool | None
    receipt_failure: str | None
    receipt_document: dict[str, object] | None
    receipt: dict[str, object] | None
    probes: tuple[ProbeObservation, ...]
    checks: tuple[dict[str, object], ...]
    external_isolation: dict[str, object]
    supervisor_principal: dict[str, object]
    sandbox_ready: dict[str, object] | None
    scratch: dict[str, object]
    process: dict[str, object]
    source_runtime: RuntimeSummary
    snapshot_runtime: RuntimeSummary

    def digest(self) -> str:
        return sha256_bytes(canonical_semantic_bytes(self))


# --------------------------------------------------------------------------------------
# Trusted preparation
# --------------------------------------------------------------------------------------


def write_protected_input_view(
    root: Path,
    workspace: Workspace,
    prepared: PreparedExecutionInputs,
    binding: WorkerInputBinding,
) -> Path:
    """Compose the exact read-only view the protected worker is allowed to consume.

    The bytes are the already-admitted CAS objects: the canonical binding, the exact input-
    manifest bytes, the five resolved definitions and the single declared asset. The worker
    receives no caller-supplied path; it reads this fixed relative layout.
    """
    store = MaterializationStore(workspace)
    (root / "assets").mkdir(parents=True, exist_ok=False)
    (root / "definitions").mkdir()
    (root / "binding.json").write_bytes(canonical_semantic_bytes(binding))
    (root / "manifest.json").write_bytes(
        _read_cas_object(
            store.manifest_path(prepared.inputs.manifest_digest.hex),
            prepared.inputs.manifest_digest.hex,
            limit=_MAX_SMALL_FILE_BYTES,
        )
    )
    for item in prepared.inputs.manifest.definitions:
        (root / "definitions" / f"{item.kind.value}.json").write_bytes(
            _read_cas_object(
                store.object_path(item.semantic_digest.hex),
                item.semantic_digest.hex,
                limit=_MAX_SMALL_FILE_BYTES,
            )
        )
    for item in prepared.inputs.manifest.assets:
        path = root / "assets" / item.logical_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            _read_cas_object(
                store.object_path(item.observed_sha256),
                item.observed_sha256,
                limit=_MAX_SMALL_FILE_BYTES,
            )
        )
    return root


def _read_cas_object(path: Path, expected_sha256: str, *, limit: int) -> bytes:
    """Read one content-addressed object through the bounded, link-refusing reader."""
    data = read_bounded_regular(path, limit=limit)
    if sha256_bytes(data) != expected_sha256:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_OBJECT_CORRUPT,
            "a content-addressed object changed after it was admitted",
        )
    return data


def _view_digest(view: VerifiedWorkerInputs) -> str:
    payload = {
        "schema": "dynamisbench.protected.input-view-observation/1",
        "binding_sha256": view.binding_sha256,
        "input_manifest_sha256": view.input_manifest_sha256,
        "files": [
            {"path": item.path, "size_bytes": item.size_bytes, "sha256": item.sha256}
            for item in view.files
        ],
    }
    return sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


def _pycache_present(runtime: ProtectedRuntime) -> list[str]:
    """Every ``__pycache__`` directory in the executed runtime roots.

    The closure excludes bytecode, so a `.pyc` added in a measurement window would be
    imported without changing any digest. The worker cannot create one inside a read-only
    runtime, so a post-exit entry is a refusal rather than a warning.
    """
    found: list[str] = []
    for root in (runtime.source_root, runtime.site_packages):
        for current, directories, _files in os.walk(root):
            for name in list(directories):
                if name == "__pycache__":
                    found.append(str(Path(current) / name))
                    directories.remove(name)
    return sorted(found)


def _model_size_bytes(view: VerifiedWorkerInputs) -> int:
    """The verified view's model size, from the supervisor's own observation."""
    for item in view.files:
        if item.path.startswith("assets/"):
            return item.size_bytes
    raise ProtectedLaunchError(
        RefusalCode.WORKER_START_FAILED, "the verified input view has no model asset entry"
    )


def _view_files(view: VerifiedWorkerInputs) -> tuple[dict[str, object], ...]:
    return tuple(
        {"path": item.path, "size_bytes": item.size_bytes, "sha256": item.sha256}
        for item in view.files
    )


def consume_binding(
    route: ProtectedExecutionRoute, request_sha256: str, staging_root: Path, launch_nonce: str
) -> Path:
    """Mark one admitted request in one workspace as used before process creation.

    The key is the request digest together with the workspace's staging root. A nonce-keyed
    marker can never collide because every attempt mints a fresh nonce; a request-only marker
    would wrongly refuse the same scientific request in a second workspace. The pair is the
    correct identity for "this admission, in this workspace, has already run". The marker is
    supervisor-owned and outside the sandbox-visible tree, and it is deliberately not removed
    after the run.
    """
    attempts = route.runtime.registry_root
    attempts.mkdir(parents=True, exist_ok=True)
    key = sha256_bytes(f"{request_sha256}:{staging_root}".encode())
    marker = attempts / f"{key}.used"
    try:
        descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED, "this protected binding was already used"
        ) from error
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(launch_nonce.encode("ascii"))
        handle.flush()
        os.fsync(handle.fileno())
    if os.name != "nt":
        # Persist the new directory entry, not only the file bytes. Windows has no
        # equivalent directory fsync; the create-exclusive name is the available primitive.
        directory = os.open(attempts, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return marker


# --------------------------------------------------------------------------------------
# Platform mechanism
# --------------------------------------------------------------------------------------


class _ProcessLike(Protocol):
    """The attributes the supervisor's bounded loop needs from either platform process."""

    pid: int
    returncode: int | None

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def kill(self) -> None: ...


class ProtectedTree:
    """The ownership primitive for one protected attempt's process tree.

    Windows can only be emptied through the Job Object; Linux can only be *proven* empty
    through the cgroup's ``populated``/``procs`` files. Both refuse to claim emptiness from
    the direct child alone, and neither falls back to a POSIX process group.
    """

    def __init__(
        self,
        *,
        platform: str,
        process: _ProcessLike,
        posix: PosixProcessTree | None = None,
        cgroup: Any | None = None,
        windows_process: Any | None = None,
    ) -> None:
        self._process = process
        self._posix = posix
        self._cgroup = cgroup
        self._windows = windows_process
        self.termination_requested = False
        self.cleanup_failed = False

    def request_termination(self) -> None:
        self.termination_requested = True
        if self._windows is not None:
            self._windows.kill()
            return
        # A same-user writer can move a task out of the attempt cgroup, so the POSIX
        # session is terminated too, and the direct child is killed even if it left both.
        if self._cgroup is not None:
            self._cgroup.kill()
        if self._posix is not None:
            self._posix.request_termination()
        try:
            self._process.kill()
        except OSError:
            pass

    def wait_empty(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        if self._windows is not None:
            while True:
                try:
                    accounting = self._windows.job_accounting()
                except Exception:  # noqa: BLE001 - an unreadable job is not empty
                    return False
                if int(accounting["active_processes"]) == 0:
                    return True
                if time.monotonic() >= deadline:
                    return False
                time.sleep(_POLL_SECONDS)
        if self._cgroup is not None:
            if not bool(self._cgroup.wait_empty(max(0.0, deadline - time.monotonic()))):
                return False
            if self._posix is None:
                return True
            return bool(self._posix.wait_empty(max(0.05, deadline - time.monotonic())))
        if self._posix is not None:
            return bool(self._posix.wait_empty(timeout))
        return False

    def close(self) -> None:
        if self._windows is not None:
            try:
                # Close the process/thread handles and the Job Object. `_terminate_and_reap`
                # already emptied the tree; this releases the ownership primitive itself so a
                # later attempt cannot inherit a live job or a stale handle.
                self._windows.close()
            except Exception:  # noqa: BLE001 - an unclosed job is reported, not hidden
                self.cleanup_failed = True
        if self._cgroup is not None and not bool(self._cgroup.close()):
            self.cleanup_failed = True
        if self._posix is not None:
            self._posix.close()


class ProtectedPlatform:
    """One opened host mechanism for the protected route.

    Windows: a per-route AppContainer profile and a per-attempt Job Object.
    Linux: Landlock ABI >= 4, seccomp, a supervisor-owned cgroup v2 subtree and rlimits.

    The object is opened once per route and refuses to open when the adopted mechanism is
    unavailable. ``close`` releases the profile and any owned attempt parent.
    """

    def __init__(
        self,
        *,
        profile: PinnedReferenceProfile,
        sandbox_parent: Path | None,
        scratch_root: Path | None,
        cgroup_root: Path | None,
        accept_elevated_windows_residual: bool,
    ) -> None:
        self.profile = profile
        self.platform = profile.platform
        self.windows = profile.platform == "windows-x86-64"
        self._sandbox_parent = sandbox_parent
        self._scratch_root = scratch_root
        self._cgroup_root = cgroup_root
        self._accept_elevated = accept_elevated_windows_residual
        self._app_container: Any | None = None
        self._owned_parent: Path | None = None
        self.principal: dict[str, object] = {}
        self.mechanism = "windows-appcontainer" if self.windows else "linux-landlock"
        self.scratch: ScratchBudget | None = None

    # -- lifecycle ------------------------------------------------------------------
    def open(self) -> None:
        if self.windows:
            self._open_windows()
        else:
            self.principal = _linux_supervisor_principal()
            _require_linux_mechanisms(self._cgroup_root)
        try:
            self.scratch = resolve_scratch_budget(
                explicit_root=self._scratch_root,
                max_bytes=self.profile.max_scratch_bytes,
            )
        except ScratchBudgetError as error:
            raise ProtectedLaunchError(
                RefusalCode.WORKER_START_FAILED, f"the scratch bound is unavailable: {error}"
            ) from error
        if not self.windows and self.profile.require_dedicated_scratch_linux:
            if self.scratch.enforcement != "dedicated-filesystem":
                raise ProtectedLaunchError(
                    RefusalCode.WORKER_START_FAILED,
                    "the Linux profile requires a dedicated scratch filesystem; a shared "
                    "volume with a sampled watchdog is not the adopted bound",
                )

    def _open_windows(self) -> None:
        from dynamisbench.host import protected_windows

        if not protected_windows.is_available():
            raise ProtectedLaunchError(
                RefusalCode.WORKER_START_FAILED,
                "the AppContainer mechanism is unavailable; no unprotected launch is attempted",
            )
        try:
            self.principal = protected_windows.require_non_elevated_supervisor(
                accept_elevated_residual=self._accept_elevated
            )
        except protected_windows.PrincipalError as error:
            raise ProtectedLaunchError(RefusalCode.WORKER_START_FAILED, str(error)) from error
        except protected_windows.AppContainerError as error:
            raise ProtectedLaunchError(
                RefusalCode.WORKER_START_FAILED,
                f"the supervisor principal could not be measured: {error}",
            ) from error
        try:
            self._app_container = protected_windows.AppContainerProfile.create(
                f"DynamisBench.Protected.{uuid.uuid4().hex[:16]}"
            )
        except protected_windows.AppContainerError as error:
            raise ProtectedLaunchError(
                RefusalCode.WORKER_START_FAILED,
                f"the AppContainer profile could not be created: {error}",
            ) from error

    def close(self) -> None:
        if self._app_container is not None:
            from dynamisbench.host import protected_windows

            folder = Path(self._app_container.folder)
            try:
                # The attempt reduced the supervisor user to RX,DE,DC on the runtime tree.
                # Restore full control so the snapshot can be removed, then delete the
                # profile itself rather than leaving an orphaned package folder behind.
                if folder.is_dir():
                    protected_windows.restore_user_control(folder)
            except Exception:  # noqa: BLE001 - cleanup is best effort at this boundary
                pass
            try:
                shutil.rmtree(folder, ignore_errors=True)
                self._app_container.delete()
            finally:
                self._app_container = None
        if self._owned_parent is not None:
            shutil.rmtree(self._owned_parent, ignore_errors=True)
            self._owned_parent = None

    # -- paths ----------------------------------------------------------------------
    def _host_parent(self) -> Path:
        """The supervisor-owned parent for a runtime snapshot or an attempt directory."""
        if self._sandbox_parent is not None:
            return self._sandbox_parent
        if self._owned_parent is None:
            self._owned_parent = Path(
                tempfile.mkdtemp(prefix="dynamisbench-protected-attempt-")
            ).resolve()
        return self._owned_parent

    @property
    def runtime_root(self) -> Path:
        if self.windows:
            assert self._app_container is not None
            # The copied interpreter must be package-SID readable/executable; the AC folder
            # is the only tree the profile owns by construction.
            return Path(self._app_container.folder) / "runtime"
        return self._host_parent() / "runtime"

    def attempt_parent(self) -> Path:
        # A dedicated scratch filesystem is capacity-bounded, so an attempt beneath it gets
        # the aggregate bound. A shared volume would not, and the attempt then lives under
        # the explicit sandbox parent instead.
        if self.scratch is not None and self.scratch.root is not None:
            return self.scratch.root
        return self._host_parent()

    def prepare_attempt(self, attempt: Path, inputs: Path, scratch: Path) -> None:
        if not self.windows:
            return
        from dynamisbench.host import protected_windows

        assert self._app_container is not None
        sid = self._app_container.sid_string
        try:
            # The profile's AC folder carries package-SID full control. Reduce it to
            # traverse/read so ``..`` cannot create files outside the measured attempt.
            protected_windows.grant_tree(
                Path(self._app_container.folder),
                sid,
                "(OI)(CI)(RX)",
                user_access="(OI)(CI)(F)",
            )
            protected_windows.grant_tree(
                self.runtime_root, sid, "(OI)(CI)(RX)", user_access="(OI)(CI)(RX,DE,DC)"
            )
            protected_windows.grant_tree(
                attempt, sid, "(OI)(CI)(RX)", user_access="(OI)(CI)(RX,DE,DC)"
            )
            protected_windows.grant_tree(
                inputs, sid, "(OI)(CI)(RX)", user_access="(OI)(CI)(RX,DE,DC)"
            )
            protected_windows.grant_tree(scratch, sid, "(OI)(CI)(F)")
        except protected_windows.AppContainerError as error:
            raise ProtectedLaunchError(
                RefusalCode.WORKER_START_FAILED,
                f"the attempt DACL could not be applied: {error}",
            ) from error

    # -- launch ---------------------------------------------------------------------
    def start(
        self,
        *,
        command: tuple[str, ...],
        working_directory: Path,
        environment: dict[str, str],
    ) -> tuple[_ProcessLike, ProtectedTree]:
        if self.windows:
            return self._start_windows(
                command=command,
                working_directory=working_directory,
                environment=environment,
            )
        return self._start_linux(
            command=command,
            working_directory=working_directory,
            environment=environment,
        )

    def _start_windows(
        self,
        *,
        command: tuple[str, ...],
        working_directory: Path,
        environment: dict[str, str],
    ) -> tuple[_ProcessLike, ProtectedTree]:
        from dynamisbench.host import protected_windows

        assert self._app_container is not None
        try:
            process = protected_windows.AppContainerProcess.launch(
                profile=self._app_container,
                application=Path(command[0]),
                arguments=command[1:],
                working_directory=working_directory,
                environment=environment,
                memory_bytes=self.profile.max_memory_bytes,
                cpu_seconds=self.profile.max_cpu_seconds,
                max_processes=self.profile.max_processes,
            )
        except protected_windows.AppContainerError as error:
            raise ProtectedLaunchError(
                RefusalCode.WORKER_START_FAILED,
                f"the AppContainer worker could not be started: {error}",
            ) from error
        tree = ProtectedTree(
            platform=self.platform,
            process=cast(_ProcessLike, process),
            windows_process=process,
        )
        return cast(_ProcessLike, process), tree

    def _start_linux(
        self,
        *,
        command: tuple[str, ...],
        working_directory: Path,
        environment: dict[str, str],
    ) -> tuple[_ProcessLike, ProtectedTree]:
        from dynamisbench.host import protected_cgroup

        try:
            cgroup = protected_cgroup.CgroupV2.create(
                root=self._cgroup_root,
                limits=protected_cgroup.CgroupLimits(
                    # cgroup pids count tasks, so the profile's task bound is explicit.
                    pids_max=self.profile.max_processes,
                    memory_max_bytes=self.profile.max_memory_bytes,
                ),
            )
        except protected_cgroup.CgroupError as error:
            raise ProtectedLaunchError(
                RefusalCode.WORKER_START_FAILED,
                f"the cgroup v2 subtree could not be created: {error}",
            ) from error
        vector = cgroup.launcher_command(
            launcher_python=Path(sys.executable),
            worker_program=Path(command[0]),
            worker_arguments=command[1:],
        )
        try:
            process = subprocess.Popen(
                vector,
                cwd=working_directory,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                bufsize=0,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as error:
            cgroup.close()
            raise ProtectedLaunchError(
                RefusalCode.WORKER_START_FAILED,
                f"the attached worker could not be started: {error}",
            ) from error
        posix = PosixProcessTree(process.pid)
        tree = ProtectedTree(
            platform=self.platform,
            process=cast(_ProcessLike, process),
            posix=posix,
            cgroup=cgroup,
        )
        return cast(_ProcessLike, process), tree

    def external_isolation(self, process: _ProcessLike | None = None) -> dict[str, object]:
        """The mechanism facts observed from outside the worker."""
        facts: dict[str, object] = {
            "mechanism": self.mechanism,
            "principal": dict(self.principal),
        }
        if process is None:
            return facts
        if self.windows:
            windows_process = cast(Any, process)
            facts["token"] = dict(windows_process.token_observation)
            facts["job"] = dict(windows_process.job_accounting())
            return facts
        facts["proc"] = _read_proc_status(process.pid)
        return facts


class _LinuxWorkerSampler(threading.Thread):
    """Capture the protected worker's own `/proc/<pid>/status` once it is ready.

    The supervisor's `Popen` pid is the trusted attach launcher; it applies no_new_privs and
    seccomp only after the worker execs. Sampling the launcher would either fail every
    attempt or pass without proving anything about the worker. The bootstrap publishes its
    own pid in `sandbox-ready.json` before importing the scientific package, and this thread
    reads that process's status while it is alive.
    """

    def __init__(self, scratch: Path, facts: dict[str, object]) -> None:
        super().__init__(daemon=True)
        self._scratch = scratch
        self._facts = facts
        self._stop = threading.Event()

    def run(self) -> None:
        path = self._scratch / "sandbox-ready.json"
        deadline = time.monotonic() + 120.0
        while not self._stop.is_set() and time.monotonic() < deadline:
            try:
                raw = read_bounded_regular(path, limit=_MAX_SANDBOX_READY_BYTES)
                ready = json.loads(raw)
            except Exception:  # noqa: BLE001 - readiness is polled, not required
                time.sleep(_POLL_SECONDS)
                continue
            pid = ready.get("worker_pid") if isinstance(ready, dict) else None
            if isinstance(pid, int) and pid > 0:
                for _ in range(50):
                    status = _read_proc_status(pid)
                    if status:
                        self._facts["worker_proc"] = status
                        return
                    if self._stop.wait(_POLL_SECONDS):
                        return
                return

    def stop(self) -> None:
        self._stop.set()


def _read_proc_status(pid: int) -> dict[str, object]:
    """Read a process's ``/proc/<pid>/status`` facts the supervisor can verify externally."""
    try:
        lines = Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    values: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        values[name.strip()] = value.strip()
    return {
        "NoNewPrivs": values.get("NoNewPrivs"),
        "Seccomp": values.get("Seccomp"),
        "CapEff": values.get("CapEff"),
        "CapPrm": values.get("CapPrm"),
        "CapBnd": values.get("CapBnd"),
        "Uid": values.get("Uid"),
        "Gid": values.get("Gid"),
    }


def _linux_supervisor_principal() -> dict[str, object]:
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    principal: dict[str, object] = {
        "uid": int(getuid()) if getuid is not None else None,
        "gid": int(getgid()) if getgid is not None else None,
    }
    principal["status"] = _read_proc_status(os.getpid())
    return principal


def _require_linux_mechanisms(cgroup_root: Path | None) -> None:
    from dynamisbench.execution import landlock, seccomp
    from dynamisbench.host import protected_cgroup

    try:
        abi = landlock.abi_version()
    except Exception as error:  # noqa: BLE001 - availability is a refusal, not a crash
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED,
            f"the Landlock mechanism could not be queried: {type(error).__name__}",
        ) from error
    if abi < 4:
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED,
            f"Landlock ABI {abi} is below the adopted ABI 4; no unprotected launch is attempted",
        )
    if not seccomp.seccomp_available():
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED,
            "the seccomp mechanism is unavailable; no unprotected launch is attempted",
        )
    if not protected_cgroup.cgroup_available(cgroup_root):
        # The availability check must validate the exact root the attempt will use, or a
        # preflight could approve one delegation and create the subtree in another.
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED,
            "the delegated cgroup v2 root or supervisor placement is unavailable; no "
            "unprotected launch is attempted",
        )


# --------------------------------------------------------------------------------------
# Route
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProtectedExecutionRoute:
    """One opened, measured protected route.

    Passing this to :func:`~dynamisbench.execution.supervisor.execute_preflighted` is the
    activation decision. It is not reachable from the API, the CLI, the desktop shell or the
    workbench, and no environment variable enables it.
    """

    profile: PinnedReferenceProfile
    runtime: ProtectedRuntime
    platform: ProtectedPlatform
    scratch: ScratchBudget
    dependency_closure_digest: str
    workspace: Workspace | None = None

    @property
    def digest(self) -> str:
        return self.profile.digest()

    def close(self) -> None:
        self.platform.close()


@dataclass(frozen=True, slots=True)
class ProtectedRun:
    """One prepared run bound to one opened protected route.

    This is the value :func:`~dynamisbench.execution.supervisor.execute_preflighted` accepts.
    The route is reusable for sequential attempts; the prepared inputs are this run's exact
    admitted definitions and asset bytes, and ``begin_protected_attempt`` refuses if they do
    not describe the request being supervised.
    """

    route: ProtectedExecutionRoute
    prepared: PreparedExecutionInputs


def prepare_protected_route(
    *,
    worker_python: Path,
    workspace: Workspace | None = None,
    platform_tag: str | None = None,
    bootstrap_path: Path | None = None,
    sandbox_parent: Path | None = None,
    scratch_root: Path | None = None,
    cgroup_root: Path | None = None,
    registry_root: Path | None = None,
    accept_elevated_windows_residual: bool = False,
) -> ProtectedExecutionRoute:
    """Open the adopted mechanism and measure the runtime snapshot it will execute.

    This is the only supported way to construct a route. It refuses when the platform
    mechanism is unavailable, when the supervisor principal is not the adopted one, when the
    scratch bound cannot be provided, or when the measured snapshot does not reproduce the
    installed bytes. A refusal leaves no route and therefore no reachable launch.
    """
    tag = platform_tag or reference.platform_tag()
    profile = build_protected_profile(tag, bootstrap_path=bootstrap_path)
    platform = ProtectedPlatform(
        profile=profile,
        sandbox_parent=sandbox_parent,
        scratch_root=scratch_root,
        cgroup_root=cgroup_root,
        accept_elevated_windows_residual=accept_elevated_windows_residual,
    )
    try:
        platform.open()
        runtime = prepare_protected_runtime(
            worker_python=worker_python,
            root=platform.runtime_root,
            platform_tag=tag,
            registry_root=registry_root,
            profile=profile,
        )
    except BaseException:
        platform.close()
        raise
    assert platform.scratch is not None
    return ProtectedExecutionRoute(
        profile=profile,
        runtime=runtime,
        platform=platform,
        scratch=platform.scratch,
        dependency_closure_digest=runtime.environment.dependency_closure_digest,
        workspace=workspace,
    )


# --------------------------------------------------------------------------------------
# One attempt
# --------------------------------------------------------------------------------------


def _check(name: str, passed: bool, observed: object, limit: object) -> dict[str, object]:
    return {"name": name, "passed": bool(passed), "observed": observed, "limit": limit}


_EXPECTED_PROBE_OUTCOMES: Final = {
    "allowed_input_read": "allowed",
    "scratch_write": "allowed",
    "network_connect": "denied",
    "network_udp": "denied",
    "network_raw": "denied",
    "network_unix": "denied",
    "network_socketpair": "denied",
    "io_uring_setup": "denied",
    "inherited_sockets": "denied",
    "runtime_write": "denied",
    "package_model_asset": "denied",
}
"""The probe names and expected outcomes the pinned worker must report.

The worker authors the observations, so the supervisor requires the exact set it asked for:
a worker cannot omit a failing probe, relabel one, or duplicate a passing one.
"""


def expected_probe_outcomes(targets: ProbeTargets) -> dict[str, str]:
    """The exact probe name to expectation map for one attempt's targets."""
    expected = dict(_EXPECTED_PROBE_OUTCOMES)
    for index in range(len(targets.forbidden_reads)):
        expected[f"forbidden_read_{index}"] = "denied"
    for index in range(len(targets.forbidden_writes)):
        expected[f"forbidden_write_{index}"] = "denied"
    for index in range(len(targets.forbidden_deletes)):
        expected[f"forbidden_delete_{index}"] = "denied"
    return expected


def _source_entry_digest(runtime: ProtectedRuntime, relative: str) -> str:
    """The measured SHA-256 of one file in the executed source snapshot."""
    for entry in runtime.snapshot.source.entries:
        if entry.path == relative:
            return entry.sha256
    raise ProtectedLaunchError(
        RefusalCode.WORKER_START_FAILED,
        f"the measured source snapshot has no {relative!r} entry",
    )


@dataclass(frozen=True, slots=True)
class RuntimeExpectation:
    """The supervisor's independently measured runtime facts a receipt is compared with."""

    protected_digest: str
    executable_sha256: str
    base_digest: str
    site_packages_digest: str
    source_digest: str


def correlate_receipt(
    *,
    receipt: ConsumptionReceipt,
    receipt_error: str | None,
    binding: WorkerInputBinding,
    binding_sha256: str,
    request: WorkerRequest,
    profile: PinnedReferenceProfile,
    runtime: RuntimeExpectation,
    dependency_closure_digest: str,
    model_size_bytes: int,
    expected_probes: dict[str, str],
    windows: bool,
) -> tuple[list[dict[str, object]], list[Refusal], dict[str, object]]:
    """Correlate one untrusted worker receipt with the supervisor's own facts.

    The receipt is never evidence on its own. This function returns the checks the supervisor
    records, the refusals its disagreement produces, and the trajectory comparison against the
    committed profile reference. It is pure: it reads no file and starts no process, so the
    correlation itself can be tested against crafted receipts.
    """
    checks: list[dict[str, object]] = []
    refusals: list[Refusal] = []
    trajectory: dict[str, object] = {
        "expected_trajectory_sha256": profile.reference_trajectory_sha256,
        "observed_trajectory_sha256": None,
        "matches": False,
    }
    if receipt_error is not None:
        refusals.append(
            refusal(
                RefusalCode.WORKER_FAILED,
                f"the protected consumption receipt is not canonical: {receipt_error}",
            )
        )
    if receipt.schema_id != PROTECTED_RECEIPT_SCHEMA:
        checks.append(_check("receipt_schema", False, receipt.schema_id, PROTECTED_RECEIPT_SCHEMA))
        refusals.append(
            refusal(
                RefusalCode.WORKER_PROTOCOL_VIOLATION,
                "the protected consumption receipt declared an unknown schema",
            )
        )
    correlations: tuple[tuple[str, object, object], ...] = (
        ("receipt_completed", receipt.completed, True),
        ("receipt_failure_absent", receipt.failure, None),
        ("receipt_mode", receipt.mode, "materialized-mujoco"),
        ("receipt_nonce", receipt.attempt_nonce, binding.launch_nonce),
        ("receipt_run_id", receipt.run_id, str(request.run_id)),
        ("receipt_fingerprint", receipt.execution_fingerprint, request.execution_fingerprint.hex),
        ("receipt_request", receipt.request_sha256, binding.request_sha256),
        ("receipt_preflight", receipt.preflight_sha256, binding.preflight_sha256),
        ("receipt_manifest", receipt.input_manifest_sha256, binding.input_manifest_sha256),
        ("receipt_binding", receipt.binding_sha256, binding_sha256),
        ("receipt_environment", receipt.environment_sha256, binding.environment_sha256),
        ("receipt_selection", receipt.worker_selection_sha256, binding.worker_selection_sha256),
        (
            "receipt_adapter",
            receipt.adapter_implementation_sha256,
            binding.adapter_implementation_sha256,
        ),
        ("receipt_runtime", receipt.runtime_closure_sha256, runtime.protected_digest),
        ("receipt_profile", receipt.isolation_profile_sha256, profile.digest()),
        ("receipt_engine_imported", receipt.engine_imported, True),
        (
            "receipt_dependency_closure",
            receipt.dependency_closure_digest,
            dependency_closure_digest,
        ),
    )
    for name, observed, expected in correlations:
        agrees = observed == expected
        checks.append(_check(name, agrees, observed, expected))
        if not agrees:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_FAILED,
                    f"the protected receipt disagrees with the supervisor: {name}",
                )
            )
    summary = receipt.runtime_summary
    if summary is None:
        checks.append(_check("receipt_runtime_roots", False, None, "a runtime summary"))
        refusals.append(
            refusal(
                RefusalCode.WORKER_FAILED,
                "the protected receipt has no worker runtime summary",
            )
        )
    else:
        roots_match = (
            summary.base_digest == runtime.base_digest
            and summary.site_packages_digest == runtime.site_packages_digest
            and summary.source_digest == runtime.source_digest
            and summary.executable_sha256 == runtime.executable_sha256
            and summary.combined_digest == runtime.protected_digest
        )
        checks.append(
            _check(
                "receipt_runtime_roots",
                roots_match,
                summary.model_dump(mode="json"),
                "the measured snapshot roots",
            )
        )
        if not roots_match:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_FAILED,
                    "the worker measured a different runtime than the supervisor",
                )
            )
    source_paths = tuple(sorted(str(item.get("path", "")) for item in receipt.source_manifest))
    expected_paths = tuple(sorted(reference.ADAPTER_SOURCE_FILES))
    source_model = next(
        (
            item.get("sha256")
            for item in receipt.source_manifest
            if item.get("path") == reference.MODEL_ASSET_PATH
        ),
        None,
    )
    source_manifest_matches = source_paths == expected_paths and (
        source_model == profile.model_sha256
    )
    checks.append(
        _check(
            "receipt_source_manifest",
            source_manifest_matches,
            {"paths": len(source_paths), "model_sha256": source_model},
            {"paths": len(expected_paths), "model_sha256": profile.model_sha256},
        )
    )
    if not source_manifest_matches:
        refusals.append(
            refusal(
                RefusalCode.WORKER_FAILED,
                "the protected receipt's adapter source manifest is not the accepted closure",
            )
        )
    imports_hold = bool(receipt.imports) and all(item.under_runtime for item in receipt.imports)
    checks.append(
        _check(
            "receipt_imports",
            imports_hold,
            [item.module for item in receipt.imports if not item.under_runtime],
            "every scientific import resolved inside the measured runtime",
        )
    )
    if not imports_hold:
        refusals.append(
            refusal(
                RefusalCode.WORKER_FAILED,
                "a scientific import resolved outside the worker's measured runtime",
            )
        )
    observed_expectations: dict[str, str] = {}
    duplicate_probes: list[str] = []
    for probe in receipt.probes:
        if probe.name in observed_expectations:
            duplicate_probes.append(probe.name)
        observed_expectations[probe.name] = probe.expectation
    set_matches = observed_expectations == expected_probes and not duplicate_probes
    checks.append(
        _check(
            "receipt_probe_set",
            set_matches,
            {"probes": len(receipt.probes), "duplicates": sorted(duplicate_probes)},
            {"probes": len(expected_probes), "duplicates": []},
        )
    )
    if not set_matches:
        refusals.append(
            refusal(
                RefusalCode.WORKER_FAILED,
                "the protected receipt does not report exactly the probes the supervisor requested",
            )
        )
    gating_failures = [
        probe
        for probe in receipt.probes
        if not probe.passed and not (windows and probe.name in _NON_GATING_PROBES_WINDOWS)
    ]
    probes_hold = bool(receipt.probes) and not gating_failures
    checks.append(
        _check(
            "receipt_probes",
            probes_hold,
            [probe.name for probe in gating_failures],
            "every gating probe observed its expected outcome",
        )
    )
    if not probes_hold:
        refusals.append(
            refusal(
                RefusalCode.WORKER_FAILED,
                "an inside-worker isolation probe did not observe the adopted denial",
            )
        )
    if receipt.model is None:
        checks.append(_check("receipt_model_present", False, None, True))
        refusals.append(
            refusal(
                RefusalCode.WORKER_FAILED,
                "the protected worker did not report the compiled model",
            )
        )
    else:
        model_matches = (
            receipt.model.sha256 == profile.model_sha256
            and receipt.model.logical_path == profile.model_source_path
            and receipt.model.size_bytes == model_size_bytes
            and receipt.model.source == "input_view"
            and not receipt.model.package_asset_present
            and receipt.model.package_asset_probe == "denied"
        )
        checks.append(
            _check(
                "receipt_model",
                model_matches,
                {
                    "sha256": receipt.model.sha256,
                    "logical_path": receipt.model.logical_path,
                    "size_bytes": receipt.model.size_bytes,
                    "source": receipt.model.source,
                    "package_asset_present": receipt.model.package_asset_present,
                    "package_asset_probe": receipt.model.package_asset_probe,
                },
                "the pinned model bytes from the verified view, packaged asset absent",
            )
        )
        if not model_matches:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_FAILED,
                    "the consumed model is not the pinned view bytes with the packaged asset "
                    "absent",
                )
            )
    if receipt.physics is None:
        checks.append(_check("receipt_physics", False, None, "the pinned reference run"))
        refusals.append(
            refusal(
                RefusalCode.WORKER_FAILED,
                "the protected worker did not report the pinned reference run",
            )
        )
        return checks, refusals, trajectory
    physics = receipt.physics
    trajectory = {
        "expected_trajectory_sha256": profile.reference_trajectory_sha256,
        "observed_trajectory_sha256": physics.trajectory_sha256,
        "matches": physics.trajectory_sha256 == profile.reference_trajectory_sha256,
    }
    final_time_holds = abs(physics.final_time_s - profile.duration_s) <= _TIME_TOLERANCE_S
    checks.append(
        _check("receipt_final_time", final_time_holds, physics.final_time_s, profile.duration_s)
    )
    if not final_time_holds:
        refusals.append(
            refusal(
                RefusalCode.WORKER_FAILED,
                "the protected reference run did not reach the pinned duration",
            )
        )
    pinned: tuple[tuple[str, object, object], ...] = (
        ("receipt_steps", physics.steps, profile.steps),
        ("receipt_timestep", physics.timestep_s, profile.timestep_s),
        ("receipt_duration", physics.duration_s, profile.duration_s),
        ("receipt_final_angle", physics.final_angle_rad, profile.expected_final_angle_rad),
        (
            "receipt_final_angular_velocity",
            physics.final_angular_velocity_rad_s,
            profile.expected_final_angular_velocity_rad_s,
        ),
        ("receipt_energy_initial", physics.energy_initial_j, profile.expected_energy_initial_j),
        ("receipt_energy_final", physics.energy_final_j, profile.expected_energy_final_j),
        ("receipt_all_finite", physics.all_finite, True),
    )
    for name, observed, expected in pinned:
        agrees = observed == expected
        checks.append(_check(name, agrees, observed, expected))
        if not agrees:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_FAILED,
                    f"the protected reference run disagrees with the profile: {name}",
                )
            )
    checks.append(
        _check(
            "receipt_trajectory_reference",
            bool(trajectory["matches"]),
            physics.trajectory_sha256,
            profile.reference_trajectory_sha256,
        )
    )
    if not trajectory["matches"]:
        refusals.append(
            refusal(
                RefusalCode.WORKER_FAILED,
                "the protected reference trajectory is not the committed profile trajectory",
            )
        )
    return checks, refusals, trajectory


def _linux_allowlists(
    runtime: ProtectedRuntime, attempt: Path, inputs: Path, scratch: Path
) -> tuple[list[str], list[str], list[str]]:
    """The Linux filesystem policy: system libraries, the snapshot, the view and scratch.

    ``/bin``, ``/sbin``, ``/usr/bin`` and ``/usr/sbin`` are deliberately absent: a scientific
    worker has no reason to exec a system helper, and an execute grant over those directories
    would make every installed tool part of the worker's surface. The measured
    ``pyvenv.cfg`` is a read-only entry because the worker re-hashes it before physics.
    """
    read_execute = [path for path in _LINUX_SYSTEM_READ_EXECUTE if Path(path).exists()]
    read_execute.append(str(runtime.base_prefix))
    # The launch path is the resolved base interpreter; keep its directory readable so the
    # kernel can map the shared library the interpreter was built against.
    read_execute.append(str(runtime.interpreter.parent))
    read_only = [
        str(runtime.site_packages),
        str(runtime.source_root),
        str(attempt),
        str(inputs),
        "/proc/self/fd",
        "/proc/self/status",
    ]
    if runtime.venv_config_path is not None:
        read_only.append(str(runtime.venv_config_path))
    return read_execute, read_only, [str(scratch)]


def _create_sentinel(root: Path, token: str) -> Path:
    path = root / f"dynamisbench-protected-sentinel-{token}.txt"
    path.write_bytes(f"DYNAMISBENCH-PROTECTED-SENTINEL {token}\n".encode())
    return path


class ProtectedAttempt:
    """One prepared protected attempt, inside the supervisor's existing lifecycle.

    The supervisor owns the lifecycle. This object owns the pinned preparation (view,
    runtime revalidation, sandbox policy, single-use marker), the platform start, the
    post-exit measurements and the correlation. It never writes diagnostics or evidence; the
    supervisor does that.
    """

    def __init__(
        self,
        *,
        route: ProtectedExecutionRoute,
        request: WorkerRequest,
        prepared: PreparedExecutionInputs,
        binding: WorkerInputBinding,
        binding_sha256: str,
        attempt: Path,
        inputs: Path,
        scratch: Path,
        pre_view: VerifiedWorkerInputs,
        sandbox_digest: str,
        canary: ProtectedNetworkCanary,
        probe_targets: ProbeTargets,
        forbidden_writes: tuple[Path, ...],
        runtime_write: Path,
        sentinels: tuple[Path, ...],
        command: tuple[str, ...],
        environment: dict[str, str],
    ) -> None:
        self.route = route
        self.request = request
        self.prepared = prepared
        self.binding = binding
        self.binding_sha256 = binding_sha256
        self.attempt = attempt
        self.inputs = inputs
        self.scratch = scratch
        self.pre_view = pre_view
        self.sandbox_digest = sandbox_digest
        self.canary = canary
        self.probe_targets = probe_targets
        self.forbidden_writes = forbidden_writes
        self.runtime_write = runtime_write
        self.sentinels = sentinels
        self.command = command
        self.environment = environment
        self.process: _ProcessLike | None = None
        self.tree: ProtectedTree | None = None
        self.external_isolation: dict[str, object] = route.platform.external_isolation()
        self.checks: list[dict[str, object]] = []
        self.record: ProtectedConsumptionRecord | None = None
        self._sampler: _LinuxWorkerSampler | None = None
        self.post_runtime_digest: str | None = None
        self.view_after: VerifiedWorkerInputs | None = None
        self.usage: ScratchUsage | None = None
        self.trajectory: dict[str, object] = {}
        self.watchdog: ScratchWatchdog | None = None

    # -- start ----------------------------------------------------------------------
    def start(self) -> tuple[_ProcessLike, ProtectedTree]:
        process, tree = self.route.platform.start(
            command=self.command,
            working_directory=self.attempt,
            environment=self.environment,
        )
        self.process = process
        self.tree = tree
        self.external_isolation = self.route.platform.external_isolation(process)
        if not self.route.platform.windows:
            # `Popen.pid` is the attach launcher, which has not yet applied
            # ``no_new_privs`` or seccomp. The bootstrap publishes the worker's own pid in
            # `sandbox-ready.json`, and the sampler captures that process's status while it
            # is alive. The launcher's status is never used as the isolation fact.
            self._sampler = _LinuxWorkerSampler(self.scratch, self.external_isolation)
            self._sampler.start()
        profile = self.route.profile
        watchdog = ScratchWatchdog(
            root=self.scratch,
            limit_bytes=profile.max_scratch_bytes,
            interval_seconds=(
                self.route.scratch.watchdog_interval_seconds
                if self.route.scratch.watchdog_interval_seconds is not None
                else _POLL_SECONDS
            ),
            on_overrun=lambda _usage: tree.request_termination(),
            max_files=profile.max_scratch_entries,
            max_entries=profile.max_scratch_entries,
        )
        watchdog.start()
        self.watchdog = watchdog
        return process, tree

    # -- observation ----------------------------------------------------------------
    def observe(
        self,
        *,
        exit_code: int | None,
        response: WorkerResponse | None,
        response_matches: bool,
        stdout_truncated: bool,
        stdin_delivered: bool,
    ) -> list[Refusal]:
        """Correlate the finished attempt with the supervisor's own measurements.

        Returns the refusals this correlation adds. The caller owns the lifecycle state and
        refuses to report ``COMPLETED`` when this list is non-empty.
        """
        refusals: list[Refusal] = []
        checks = self.checks
        checks.append(_check("process_exit_zero", exit_code == 0, exit_code, 0))
        checks.append(_check("stdin_delivered", stdin_delivered, stdin_delivered, True))
        checks.append(
            _check(
                "response_valid",
                response is not None,
                "valid" if response is not None else "missing",
                "one protocol v1 response",
            )
        )
        checks.append(_check("response_matches_request", response_matches, response_matches, True))

        self.view_after = self._verify_view(checks, refusals)
        self.post_runtime_digest = self._verify_runtime(checks, refusals)
        self._verify_venv(checks, refusals)
        self._verify_sandbox_config(checks, refusals)
        ready = self._read_ready()
        self._verify_ready(ready, checks, refusals)
        receipt, receipt_bytes, receipt_error = self._read_receipt(checks)
        self._correlate_receipt(receipt, receipt_error, checks, refusals)
        self._verify_canary(checks, refusals)
        self.usage = self._verify_scratch(checks, refusals)
        self._verify_writes(checks, refusals)
        self._verify_external(checks, refusals)

        if stdout_truncated:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_OUTPUT_TOO_LARGE,
                    "the protected worker response exceeded the response message bound",
                )
            )
        if response is not None and not response_matches:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_PROTOCOL_VIOLATION,
                    "the protected worker response does not describe the request it was given",
                )
            )
        if response is None:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_PROTOCOL_VIOLATION,
                    "the protected worker did not write exactly one valid protocol response",
                )
            )
        elif response.status.value == "failed":
            refusals.append(
                refusal(
                    RefusalCode.WORKER_FAILED,
                    "the protected worker reported a failed status; see its bounded stderr",
                )
            )

        self.record = self._build_record(
            state=RunLifecycleState.FAILED,
            receipt=receipt,
            receipt_bytes=receipt_bytes,
            receipt_error=receipt_error,
            exit_code=exit_code,
            stdin_delivered=stdin_delivered,
            ready=ready,
        )
        return refusals

    # -- persistence ----------------------------------------------------------------
    def persist(
        self,
        bundle: StagingBundle,
        *,
        state: RunLifecycleState,
        refusals: tuple[Refusal, ...],
        process_tree_cleaned: bool,
        stdout_bytes: int,
        stderr_bytes: int,
    ) -> str:
        """Write the supervisor-authored correlated record into mutable staging.

        The record is a diagnostic. A write failure is the caller's to fold into a refusal;
        this function never reports success for a record it did not write.
        """
        if self.record is None:
            raise ProtectedLaunchError(
                RefusalCode.EVIDENCE_WRITE_FAILED,
                "the protected attempt has no correlated observation to persist",
            )
        record = self.record.model_copy(
            update={
                "state": state,
                "refusals": tuple(item.code.value for item in refusals),
                "process": {
                    **self.record.process,
                    # `process_tree_cleaned` is the supervisor's emptiness proof from the
                    # ownership primitive. `cleanup_failed` additionally reports a primitive
                    # that could not be released; it is not a substitute for the proof.
                    "tree_cleaned": bool(
                        process_tree_cleaned and (self.tree is None or not self.tree.cleanup_failed)
                    ),
                    "stdout_bytes": stdout_bytes,
                    "stderr_bytes": stderr_bytes,
                },
            }
        )
        bundle.write_payload(PROTECTED_SUPERVISOR_RECORD_NAME, canonical_semantic_bytes(record))
        self.record = record
        return PROTECTED_SUPERVISOR_RECORD_NAME

    def cleanup(self) -> None:
        """Release every resource this attempt owns; never raise, never skip a stage."""
        for path in (*self.sentinels, *self.forbidden_writes):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                continue
        try:
            self.canary.close()
        except Exception:  # noqa: BLE001 - cleanup is best effort at this boundary
            pass
        if self.watchdog is not None:
            try:
                self.watchdog.stop()
            except Exception:  # noqa: BLE001
                pass
        if self.tree is not None:
            try:
                self.tree.close()
            except Exception:  # noqa: BLE001
                pass
        shutil.rmtree(self.attempt, ignore_errors=True)

    # -- observation steps -----------------------------------------------------------
    def _verify_view(
        self, checks: list[dict[str, object]], refusals: list[Refusal]
    ) -> VerifiedWorkerInputs | None:
        try:
            post = verify_worker_input_view(
                self.inputs, expected=self.binding, request=self.request
            )
        except Exception as error:  # noqa: BLE001 - any failure is a refusal
            checks.append(
                _check("input_view_unchanged", False, type(error).__name__, "the pre-launch view")
            )
            refusals.append(
                refusal(
                    RefusalCode.FORBIDDEN_PATH,
                    "the protected input view could not be re-verified after exit",
                )
            )
            return None
        unchanged = post == self.pre_view
        checks.append(_check("input_view_unchanged", unchanged, unchanged, True))
        if not unchanged:
            refusals.append(
                refusal(
                    RefusalCode.FORBIDDEN_PATH,
                    "the protected input view changed between verification and exit",
                )
            )
        return post

    def _verify_runtime(
        self, checks: list[dict[str, object]], refusals: list[Refusal]
    ) -> str | None:
        runtime = self.route.runtime
        profile = self.route.profile
        try:
            post = measure_runtime_identity(
                executable=runtime.interpreter,
                base_prefix=runtime.base_prefix,
                site_packages=runtime.site_packages,
                source_root=runtime.source_root,
                model_asset_relative=_MODEL_ASSET_RELATIVE,
            )
        except Exception as error:  # noqa: BLE001
            checks.append(
                _check("runtime_unchanged", False, type(error).__name__, "the measured snapshot")
            )
            refusals.append(
                refusal(
                    RefusalCode.FORBIDDEN_PATH,
                    "the protected runtime could not be re-measured after exit",
                )
            )
            return None
        try:
            runtime.rescan_for_model()
            cached = _pycache_present(runtime)
        except Exception as error:  # noqa: BLE001
            checks.append(
                _check("runtime_unchanged", False, type(error).__name__, "the measured snapshot")
            )
            refusals.append(
                refusal(
                    RefusalCode.FORBIDDEN_PATH,
                    "the protected runtime gained an unmeasured model or bytecode after exit",
                )
            )
            return None
        checks.append(
            _check(
                "runtime_no_bytecode",
                not cached,
                cached,
                [],
            )
        )
        if cached:
            refusals.append(
                refusal(
                    RefusalCode.FORBIDDEN_PATH,
                    "the protected runtime gained __pycache__ entries after it was measured",
                )
            )
        unchanged = post.digest == runtime.snapshot.digest and runtime.protected_digest == (
            protected_runtime_digest(post, runtime.venv_config_sha256)
        )
        checks.append(_check("runtime_unchanged", unchanged, post.digest, runtime.snapshot.digest))
        if not unchanged:
            refusals.append(
                refusal(
                    RefusalCode.FORBIDDEN_PATH,
                    "the protected runtime changed between measurement and exit",
                )
            )
        try:
            bootstrap_digest = runtime.bootstrap_sha256()
        except Exception as error:  # noqa: BLE001
            bootstrap_digest = type(error).__name__
        bootstrap_current = bootstrap_digest == profile.bootstrap_sha256
        checks.append(
            _check(
                "bootstrap_pinned", bootstrap_current, bootstrap_digest, profile.bootstrap_sha256
            )
        )
        if not bootstrap_current:
            refusals.append(
                refusal(
                    RefusalCode.FORBIDDEN_PATH,
                    "the measured bootstrap is not the profile-pinned bytes after exit",
                )
            )
        return post.digest

    def _verify_venv(self, checks: list[dict[str, object]], refusals: list[Refusal]) -> None:
        runtime = self.route.runtime
        if runtime.venv_config_path is None:
            return
        try:
            _, observed = sha256_file(runtime.venv_config_path, max_bytes=_MAX_SMALL_FILE_BYTES)
        except Exception as error:  # noqa: BLE001
            checks.append(
                _check(
                    "venv_config_unchanged", False, type(error).__name__, runtime.venv_config_sha256
                )
            )
            refusals.append(
                refusal(
                    RefusalCode.FORBIDDEN_PATH,
                    "the measured pyvenv.cfg could not be re-read after exit",
                )
            )
            return
        unchanged = observed == runtime.venv_config_sha256
        checks.append(
            _check("venv_config_unchanged", unchanged, observed, runtime.venv_config_sha256)
        )
        if not unchanged:
            refusals.append(
                refusal(
                    RefusalCode.FORBIDDEN_PATH,
                    "the measured pyvenv.cfg changed between measurement and exit",
                )
            )

    def _verify_sandbox_config(
        self, checks: list[dict[str, object]], refusals: list[Refusal]
    ) -> None:
        try:
            data = read_bounded_regular(self.attempt / "sandbox.json", limit=_MAX_SMALL_FILE_BYTES)
        except Exception as error:  # noqa: BLE001 - an unreadable config is a refusal
            checks.append(
                _check("sandbox_config_written", False, type(error).__name__, self.sandbox_digest)
            )
            refusals.append(
                refusal(
                    RefusalCode.FORBIDDEN_PATH,
                    "the protected sandbox policy is no longer readable after the attempt",
                )
            )
            return
        observed = sha256_bytes(data)
        unchanged = observed == self.sandbox_digest
        checks.append(_check("sandbox_config_written", unchanged, observed, self.sandbox_digest))
        if not unchanged:
            refusals.append(
                refusal(
                    RefusalCode.FORBIDDEN_PATH,
                    "the protected sandbox policy changed during the attempt",
                )
            )

    def _read_ready(self) -> dict[str, object] | None:
        try:
            data = read_bounded_regular(
                self.scratch / "sandbox-ready.json", limit=_MAX_SANDBOX_READY_BYTES
            )
        except Exception:  # noqa: BLE001
            return None
        try:
            value = json.loads(data)
        except json.JSONDecodeError:
            return None
        return value if isinstance(value, dict) else None

    def _verify_ready(
        self,
        ready: dict[str, object] | None,
        checks: list[dict[str, object]],
        refusals: list[Refusal],
    ) -> None:
        profile = self.route.profile
        runtime = self.route.runtime
        checks.append(_check("sandbox_ready_present", ready is not None, ready, True))
        sanitized = ready is not None and ready.get("environment_sanitized") is True
        checks.append(
            _check(
                "environment_sanitized",
                sanitized,
                ready,
                "the bootstrap replaced the inherited environment before importing",
            )
        )
        if not sanitized:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_FAILED,
                    "the protected bootstrap did not confirm a sanitized environment",
                )
            )
        # The bootstrap's own allowlist deletes LOCALAPPDATA (a Windows launch requirement)
        # and PYTHONHASHSEED, so the expected set is the supervisor's environment minus those
        # two. Anything else is an undeclared key the launch did not authorize.
        expected_keys = sorted(set(self.environment) - {"LOCALAPPDATA", "PYTHONHASHSEED"})
        observed_keys = ready.get("environment_keys") if ready is not None else None
        keys_match = (
            isinstance(observed_keys, list)
            and sorted(str(key) for key in observed_keys) == expected_keys
        )
        checks.append(
            _check(
                "environment_keys",
                keys_match,
                None if ready is None else ready.get("environment_keys"),
                expected_keys,
            )
        )
        bound = (
            ready is not None
            and ready.get("profile_sha256") == profile.digest()
            and ready.get("runtime_closure_sha256") == runtime.protected_digest
            and ready.get("bootstrap_sha256") == profile.bootstrap_sha256
            and ready.get("config_sha256") == self.sandbox_digest
            and keys_match
        )
        checks.append(
            _check(
                "sandbox_ready_binding",
                bound,
                ready,
                "the measured profile, runtime closure, bootstrap and sandbox config",
            )
        )
        if ready is not None and not self.route.platform.windows:
            from dynamisbench.execution.seccomp import seccomp_status

            abi = ready.get("abi")
            control = ready.get("seccomp")
            seccomp_ok = (
                isinstance(abi, int)
                and abi >= 4
                and isinstance(control, dict)
                and str(control.get("Seccomp")) == "2"
                and str(control.get("NoNewPrivs")) == "1"
            )
            checks.append(
                _check(
                    "sandbox_mechanism",
                    seccomp_ok,
                    {"abi": abi, "seccomp": control, "host": seccomp_status()},
                    "Landlock ABI >= 4, Seccomp=2 and NoNewPrivs=1",
                )
            )
            if not seccomp_ok:
                refusals.append(
                    refusal(
                        RefusalCode.WORKER_FAILED,
                        "the protected worker did not report the adopted Landlock/seccomp state",
                    )
                )
        if ready is None:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_FAILED,
                    "the protected bootstrap did not publish its readiness observation",
                )
            )
        elif not bound:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_FAILED,
                    "the protected bootstrap published a different launch identity",
                )
            )

    def _read_receipt(
        self, checks: list[dict[str, object]]
    ) -> tuple[ConsumptionReceipt | None, bytes | None, str | None]:
        receipt_bytes: bytes | None = None
        receipt: ConsumptionReceipt | None = None
        error: str | None = None
        try:
            receipt_bytes = read_bounded_regular(
                self.scratch / "consumption.json", limit=MAX_RECEIPT_BYTES
            )
            receipt = ConsumptionReceipt.model_validate_json(receipt_bytes)
            if canonical_semantic_bytes(receipt) != receipt_bytes:
                error = "the receipt is not canonical"
        except Exception as failure:  # noqa: BLE001 - a missing receipt is a refusal
            error = type(failure).__name__
        checks.append(_check("receipt_present", receipt is not None, error or "present", "present"))
        checks.append(_check("receipt_canonical", error is None, error or "canonical", "canonical"))
        return receipt, receipt_bytes, error

    def _correlate_receipt(
        self,
        receipt: ConsumptionReceipt | None,
        receipt_error: str | None,
        checks: list[dict[str, object]],
        refusals: list[Refusal],
    ) -> None:
        runtime = self.route.runtime
        profile = self.route.profile
        self.trajectory = {
            "expected_trajectory_sha256": profile.reference_trajectory_sha256,
            "observed_trajectory_sha256": None,
            "matches": False,
        }
        if receipt is None:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_FAILED,
                    "the protected worker did not write a bounded, canonical consumption receipt",
                )
            )
            return
        expectation = RuntimeExpectation(
            protected_digest=runtime.protected_digest,
            executable_sha256=runtime.snapshot.executable_sha256,
            base_digest=runtime.snapshot.base.digest,
            site_packages_digest=runtime.snapshot.site_packages_closure.digest,
            source_digest=runtime.snapshot.source.digest,
        )
        added_checks, added_refusals, trajectory = correlate_receipt(
            receipt=receipt,
            receipt_error=receipt_error,
            binding=self.binding,
            binding_sha256=self.binding_sha256,
            request=self.request,
            profile=profile,
            runtime=expectation,
            dependency_closure_digest=self.route.dependency_closure_digest,
            model_size_bytes=_model_size_bytes(self.pre_view),
            expected_probes=expected_probe_outcomes(self.probe_targets),
            windows=self.route.platform.windows,
        )
        checks.extend(added_checks)
        refusals.extend(added_refusals)
        self.trajectory = trajectory

    def _verify_canary(self, checks: list[dict[str, object]], refusals: list[Refusal]) -> None:
        before = self.canary.cycles
        drained = True
        try:
            self.canary.drain()
        except Exception:  # noqa: BLE001 - a canary that cannot drain is not evidence
            drained = False
        # `drain` waits for two listener cycles; a listener thread that already died would
        # return without them, so the counter, not only the absence of an exception, is the
        # observation that the canary settled before its traffic was read.
        drained = drained and self.canary.cycles > before
        observed = {
            "tcp": self.canary.tcp_connections,
            "udp": self.canary.udp_datagrams,
            "unix": self.canary.unix_connections,
        }
        clean = drained and observed == {"tcp": 0, "udp": 0, "unix": 0}
        checks.append(
            _check(
                "network_denied",
                clean,
                {"drained": drained, **observed},
                {"drained": True, "tcp": 0, "udp": 0, "unix": 0},
            )
        )
        if not drained:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_FAILED,
                    "the supervision canary could not be drained after exit",
                )
            )
        if not clean:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_FAILED,
                    "the protected worker delivered network traffic to a supervisor canary",
                )
            )

    def _verify_scratch(
        self, checks: list[dict[str, object]], refusals: list[Refusal]
    ) -> ScratchUsage:
        profile = self.route.profile
        if self.watchdog is not None:
            self.watchdog.stop()
        try:
            usage = measure_scratch(self.scratch)
        except Exception as error:  # noqa: BLE001
            usage = ScratchUsage(bytes=0, files=0, links=1)
            checks.append(
                _check("scratch_within_limit", False, type(error).__name__, "a measurable tree")
            )
        within = (
            usage.links == 0
            and usage.unmeasured == 0
            and usage.bytes <= profile.max_scratch_bytes
            and usage.entries <= profile.max_scratch_entries
        )
        checks.append(
            _check(
                "scratch_within_limit",
                within,
                {
                    "bytes": usage.bytes,
                    "files": usage.files,
                    "directories": usage.directories,
                    "entries": usage.entries,
                    "links": usage.links,
                    "limit_bytes": profile.max_scratch_bytes,
                    "limit_entries": profile.max_scratch_entries,
                },
                "the post-exit entry and byte acceptance bound",
            )
        )
        if not within:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_FAILED,
                    "the protected worker exceeded or obfuscated its scratch budget",
                )
            )
        if self.watchdog is not None and self.watchdog.triggered:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_FAILED,
                    "the sampled scratch watchdog terminated an over-budget worker",
                )
            )
        return usage

    def _verify_writes(self, checks: list[dict[str, object]], refusals: list[Refusal]) -> None:
        try:
            unexpected = [str(path) for path in self.forbidden_writes if path.exists()]
        except OSError as error:
            unexpected = [type(error).__name__]
        checks.append(_check("forbidden_writes_absent", not unexpected, unexpected, []))
        if unexpected:
            refusals.append(
                refusal(
                    RefusalCode.FORBIDDEN_PATH,
                    "the protected worker wrote outside its scratch directory",
                )
            )
        try:
            runtime_written = self.runtime_write.exists()
        except OSError:
            runtime_written = True
        if runtime_written:
            try:
                self.runtime_write.unlink(missing_ok=True)
            except OSError:
                refusals.append(
                    refusal(
                        RefusalCode.FORBIDDEN_PATH,
                        "a protected runtime write artifact could not be removed",
                    )
                )
        checks.append(
            _check(
                "runtime_write_denied",
                not runtime_written,
                "written" if runtime_written else "denied",
                "denied",
            )
        )
        if runtime_written:
            refusals.append(
                refusal(
                    RefusalCode.FORBIDDEN_PATH,
                    "the protected worker wrote into its measured runtime snapshot",
                )
            )

    def _verify_external(self, checks: list[dict[str, object]], refusals: list[Refusal]) -> None:
        if self.route.platform.windows:
            token = self.external_isolation.get("token")
            job = self.external_isolation.get("job")
            holds = (
                isinstance(token, dict)
                and bool(token.get("is_appcontainer"))
                and bool(token.get("sid_matches"))
                and int(token.get("capability_count", -1)) == 0
                and isinstance(job, dict)
            )
            expectation: object = (
                "an AppContainer token with the expected package SID, zero capabilities "
                "and a Job Object"
            )
        else:
            if self._sampler is not None:
                self._sampler.stop()
            proc = self.external_isolation.get("worker_proc")
            holds = (
                isinstance(proc, dict)
                and proc.get("NoNewPrivs") == "1"
                and str(proc.get("Seccomp")) == "2"
                and str(proc.get("CapEff", "")).lower() == "0000000000000000"
            )
            expectation = (
                "the worker process reports NoNewPrivs=1, Seccomp=2 and zero effective capabilities"
            )
        checks.append(_check("external_isolation", holds, self.external_isolation, expectation))
        if not holds:
            refusals.append(
                refusal(
                    RefusalCode.WORKER_FAILED,
                    "the external isolation facts do not match the adopted mechanism",
                )
            )

    # -- record ---------------------------------------------------------------------
    def _build_record(
        self,
        *,
        state: RunLifecycleState,
        receipt: ConsumptionReceipt | None,
        receipt_bytes: bytes | None,
        receipt_error: str | None,
        exit_code: int | None,
        stdin_delivered: bool,
        ready: dict[str, object] | None,
    ) -> ProtectedConsumptionRecord:
        runtime = self.route.runtime
        profile = self.route.profile
        usage = self.usage if self.usage is not None else ScratchUsage(0, 0, 1)
        receipt_payload: dict[str, object] | None = None
        if receipt is not None:
            receipt_payload = {
                "mode": receipt.mode,
                "completed": receipt.completed,
                "failure": receipt.failure,
                "trajectory": dict(self.trajectory),
                "source_manifest": [dict(item) for item in receipt.source_manifest],
                "dependency_closure_digest": receipt.dependency_closure_digest,
                "imports": [
                    {"module": item.module, "under_runtime": item.under_runtime}
                    for item in receipt.imports
                ],
            }
        return ProtectedConsumptionRecord(
            run_id=self.request.run_id,
            execution_fingerprint=self.request.execution_fingerprint.hex,
            state=state,
            refusals=(),
            platform=profile.platform,
            mechanism=self.route.platform.mechanism,
            profile_sha256=profile.digest(),
            adapter_implementation_sha256=profile.adapter_implementation_digest,
            model_sha256=profile.model_sha256,
            reference_trajectory_sha256=profile.reference_trajectory_sha256,
            binding_sha256=self.binding_sha256,
            request_sha256=self.binding.request_sha256,
            preflight_sha256=self.binding.preflight_sha256,
            input_manifest_sha256=self.binding.input_manifest_sha256,
            environment_sha256=self.binding.environment_sha256,
            worker_selection_sha256=self.binding.worker_selection_sha256,
            launch_nonce=self.binding.launch_nonce,
            bootstrap_sha256=profile.bootstrap_sha256,
            worker_entry_sha256=_source_entry_digest(runtime, _WORKER_ENTRY_RELATIVE),
            sandbox_config_sha256=self.sandbox_digest,
            runtime_closure_sha256=runtime.protected_digest,
            source_runtime_digest=runtime.source.digest,
            snapshot_runtime_digest=runtime.snapshot.digest,
            post_runtime_digest=self.post_runtime_digest,
            worker_runtime_digest=(
                None
                if receipt is None or receipt.runtime_summary is None
                else receipt.runtime_summary.combined_digest
            ),
            venv_config_sha256=runtime.venv_config_sha256,
            view_before_digest=_view_digest(self.pre_view),
            view_after_digest=None if self.view_after is None else _view_digest(self.view_after),
            view_files=_view_files(self.pre_view),
            receipt_present=receipt is not None,
            receipt_canonical=receipt is not None and receipt_error is None,
            receipt_sha256=None if receipt_bytes is None else sha256_bytes(receipt_bytes),
            receipt_completed=None if receipt is None else receipt.completed,
            receipt_failure=None if receipt is None else receipt.failure,
            receipt_document=(None if receipt is None else receipt.model_dump(mode="json")),
            receipt=receipt_payload,
            probes=() if receipt is None else tuple(receipt.probes),
            checks=tuple(self.checks),
            external_isolation=dict(self.external_isolation),
            supervisor_principal=dict(self.route.platform.principal),
            sandbox_ready=ready,
            scratch={
                "bytes": usage.bytes,
                "files": usage.files,
                "directories": usage.directories,
                "entries": usage.entries,
                "links": usage.links,
                "enforcement": self.route.scratch.enforcement,
                "watchdog": {
                    "samples": 0 if self.watchdog is None else self.watchdog.samples,
                    "triggered": bool(self.watchdog is not None and self.watchdog.triggered),
                    "peak_bytes": 0 if self.watchdog is None else self.watchdog.peak_bytes,
                },
            },
            process={
                "exit_code": exit_code,
                "pid": None if self.process is None else int(self.process.pid),
                "reaped": bool(self.process is not None and self.process.poll() is not None),
                "stdin_delivered": stdin_delivered,
                "stdout_bytes": 0,
                "stderr_bytes": 0,
                "tree_cleaned": False,
            },
            source_runtime=summarize_runtime(runtime.source),
            snapshot_runtime=summarize_runtime(runtime.snapshot),
        )


def begin_protected_attempt(
    route: ProtectedExecutionRoute,
    *,
    request: WorkerRequest,
    prepared: PreparedExecutionInputs,
    selection: WorkerEnvironmentManifest,
    workspace: Workspace,
) -> ProtectedAttempt:
    """Prepare one protected attempt, or refuse before any process is created.

    The order is deliberate: pin the request authority, re-measure the runtime, compose and
    verify the view, write the pinned sandbox policy, apply the DACLs, and only then consume
    the single-use binding. A failure at any step leaves no consumed binding and no process.
    """
    profile = route.profile
    runtime = route.runtime

    if prepared.request is None or prepared.report.decision.value != "ready":
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED,
            "the prepared inputs did not retain a ready admission",
        )
    if canonical_worker_request_bytes(prepared.request) != canonical_worker_request_bytes(request):
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED,
            "the prepared inputs describe a different request than the one being supervised",
        )
    if semantic_sha256(selection).hex != prepared.worker_environment_digest.hex:
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED,
            "the worker selection does not match the prepared inputs",
        )
    differences = profile.authority_refusals(request)
    if differences:
        raise ProtectedLaunchError(
            RefusalCode.ADAPTER_ENGINE_MISMATCH,
            "the request is not the pinned protected reference: " + ", ".join(differences),
        )
    if request.adapter.implementation_digest != profile.adapter_implementation_digest:
        raise ProtectedLaunchError(
            RefusalCode.ADAPTER_ENGINE_MISMATCH,
            "the request adapter implementation is not the accepted protected identity",
        )

    if not runtime.matches:
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED,
            "the source and snapshot runtime closures disagree",
        )
    if runtime.bootstrap_sha256() != profile.bootstrap_sha256:
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED,
            "the measured bootstrap is not the profile-pinned bytes",
        )
    runtime.rescan_for_model()
    re_measured = measure_runtime_identity(
        executable=runtime.interpreter,
        base_prefix=runtime.base_prefix,
        site_packages=runtime.site_packages,
        source_root=runtime.source_root,
        model_asset_relative=_MODEL_ASSET_RELATIVE,
    )
    if re_measured.digest != runtime.snapshot.digest:
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED,
            "the runtime snapshot changed after it was measured",
        )
    if runtime.protected_digest != protected_runtime_digest(
        re_measured, runtime.venv_config_sha256
    ):
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED,
            "the protected runtime closure does not reproduce the measured identity",
        )
    if runtime.venv_config_path is not None:
        _, observed_venv = sha256_file(runtime.venv_config_path, max_bytes=_MAX_SMALL_FILE_BYTES)
        if observed_venv != runtime.venv_config_sha256:
            raise ProtectedLaunchError(
                RefusalCode.WORKER_START_FAILED,
                "the measured pyvenv.cfg changed after it was measured",
            )

    binding = build_worker_input_binding(
        prepared,
        selection,
        runtime_closure_sha256=runtime.protected_digest,
        isolation_profile_sha256=profile.digest(),
    )
    binding_sha256 = sha256_bytes(canonical_semantic_bytes(binding))

    attempt = route.platform.attempt_parent() / f"attempt-{binding.launch_nonce[:16]}"
    inputs = attempt / "inputs"
    scratch = attempt / "scratch"
    if attempt.exists():
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED, "the protected attempt directory already exists"
        )
    scratch.mkdir(parents=True)
    try:
        available = scratch_headroom(scratch)
    except ScratchBudgetError as error:
        shutil.rmtree(attempt, ignore_errors=True)
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED, f"the scratch volume is not measurable: {error}"
        ) from error
    required = (
        max(1, profile.max_scratch_bytes // 2)
        if route.scratch.enforcement == "dedicated-filesystem"
        else profile.max_scratch_bytes * 2
    )
    if available < required:
        shutil.rmtree(attempt, ignore_errors=True)
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED,
            "the scratch volume cannot absorb the configured bound before launch",
        )

    try:
        write_protected_input_view(inputs, workspace, prepared, binding)
        pre_view = verify_worker_input_view(inputs, expected=binding, request=request)
    except Exception as error:  # noqa: BLE001 - an unusable view is a refusal, not a crash
        shutil.rmtree(attempt, ignore_errors=True)
        raise ProtectedLaunchError(
            RefusalCode.FORBIDDEN_PATH,
            "the protected input view could not be composed from the admitted objects: "
            f"{type(error).__name__}",
        ) from error

    token = uuid.uuid4().hex
    staging = workspace.location(PersistenceClass.STAGING).path
    sealed = workspace.location(PersistenceClass.SEALED_EVIDENCE).path
    # A workspace's sealed root is deliberately absent until a run is sealed, so a write
    # target that does not exist is not part of this attempt's attack surface. Probing a
    # missing directory would report "error", and calling that a denial would be dishonest.
    forbidden_write_targets: tuple[Path, ...] = (
        inputs / "forbidden-write.txt",
        *(
            root / f"dynamisbench-protected-write-{token}.txt"
            for root in (staging, sealed)
            if root.is_dir()
        ),
    )
    runtime_write = runtime.source_root / "dynamisbench" / f"protected-write-{token}.txt"
    sentinels: list[Path] = []
    canary: ProtectedNetworkCanary | None = None
    succeeded = False
    try:
        for root in (
            staging,
            sealed,
            workspace.source_root,
            runtime.environment.source_root,
            runtime.registry_root,
        ):
            if root.is_dir():
                sentinels.append(_create_sentinel(root, token))
        canary = ProtectedNetworkCanary()
        control = canary.self_check()
        if not all(control.values()):
            raise ProtectedLaunchError(
                RefusalCode.WORKER_START_FAILED,
                "the network canary did not observe its own control traffic",
            )
        targets = ProbeTargets(
            forbidden_reads=tuple(str(path) for path in sentinels),
            forbidden_writes=tuple(str(path) for path in forbidden_write_targets),
            forbidden_deletes=(str(inputs / "binding.json"),),
            allowed_read=str(inputs / "binding.json"),
            allowed_write=str(scratch / "probe-write.txt"),
            runtime_write=str(runtime_write),
            network_port=canary.port,
            network_udp_port=canary.udp_port,
            network_unix_path=canary.unix_path,
            write_token=token,
        )
        (scratch / "probe-targets.json").write_bytes(canonical_semantic_bytes(targets))
        read_execute, read_only, read_write = _linux_allowlists(runtime, attempt, inputs, scratch)
        config = build_protected_sandbox_config(
            profile=profile,
            runtime=runtime,
            inputs=inputs,
            scratch=scratch,
            binding_sha256=binding_sha256,
            probe_targets=scratch / "probe-targets.json",
            read_execute=tuple(read_execute),
            read_only=tuple(read_only),
            read_write=tuple(read_write),
        )
        sandbox_digest = write_protected_sandbox_config(attempt / "sandbox.json", config)
        route.platform.prepare_attempt(attempt, inputs, scratch)
        command = protected_worker_command(
            interpreter=runtime.interpreter,
            bootstrap_path=runtime.bootstrap_path,
            config_sha256=sandbox_digest,
            bootstrap_sha256=profile.bootstrap_sha256,
        )
        try:
            environment = protected_environment(scratch)
        except ProtectedRuntimeError as error:
            raise ProtectedLaunchError(RefusalCode.WORKER_START_FAILED, str(error)) from error
        # The binding is consumed last, inside the managed scope, so a failure above leaves
        # the admitted request re-usable and a failure below has already unwound.
        consume_binding(route, binding.request_sha256, staging, binding.launch_nonce)
        succeeded = True
    except ProtectedLaunchError:
        raise
    except Exception as error:  # noqa: BLE001 - every refusal is bounded, never an escape
        raise ProtectedLaunchError(
            RefusalCode.WORKER_START_FAILED,
            f"the protected attempt could not be prepared: {type(error).__name__}",
        ) from error
    finally:
        if not succeeded:
            for sentinel in sentinels:
                try:
                    sentinel.unlink(missing_ok=True)
                except OSError:
                    continue
            if canary is not None:
                try:
                    canary.close()
                except Exception:  # noqa: BLE001 - cleanup is best effort
                    pass
            shutil.rmtree(attempt, ignore_errors=True)

    assert canary is not None
    return ProtectedAttempt(
        route=route,
        request=request,
        prepared=prepared,
        binding=binding,
        binding_sha256=binding_sha256,
        attempt=attempt,
        inputs=inputs,
        scratch=scratch,
        pre_view=pre_view,
        sandbox_digest=sandbox_digest,
        canary=canary,
        probe_targets=targets,
        forbidden_writes=forbidden_write_targets,
        runtime_write=runtime_write,
        sentinels=tuple(sentinels),
        command=command,
        environment=environment,
    )
