"""Measured runtime snapshot for the protected pinned-reference route.

The supervisor measures the installed worker environment, derives the exact snapshot the
worker will execute, removes every packaged copy of the reference XML, and re-measures the
snapshot. The worker measures the same roots inside the sandbox. A source/snapshot/worker
digest disagreement refuses the attempt before physics.

Windows copies the base installation and the approved worker site-packages into the
AppContainer's private folder. Linux copies site-packages and source, and launches the
resolved base interpreter rather than the venv launcher so ``pyvenv.cfg`` cannot select
system site-packages or a different prefix. The selected venv's ``pyvenv.cfg`` is still
measured and pinned as part of the protected runtime identity; a mutation refuses.

The production bootstrap is a source file inside the measured package tree, not a generated
file in the mutable runtime root. This module never writes a bootstrap; it measures the one
the source closure already contains and passes its digest to the launcher.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import dynamisbench
from dynamisbench.adapters.mujoco import reference
from dynamisbench.adapters.mujoco.protected_contracts import (
    RuntimeIdentity,
    measure_runtime_identity,
    sha256_file,
)
from dynamisbench.execution.protected_profile import PinnedReferenceProfile
from dynamisbench.identity import semantic_sha256

__all__ = [
    "ProtectedRuntime",
    "ProtectedRuntimeError",
    "RuntimeEnvironment",
    "build_protected_sandbox_config",
    "prepare_protected_runtime",
    "protected_environment",
    "protected_runtime_digest",
    "protected_worker_command",
    "write_protected_sandbox_config",
]

_MODEL_ASSET = "assets/reference_pendulum.xml"
_MODEL_SOURCE_RELATIVE = "dynamisbench/adapters/mujoco/assets/reference_pendulum.xml"
_BOOTSTRAP_RELATIVE = "dynamisbench/execution/protected_bootstrap.py"
_WORKER_RELATIVE = "dynamisbench/adapters/mujoco/protected_worker.py"
_SANDBOX_SCHEMA = "dynamisbench.protected.sandbox/1"
_MAX_CONFIG_BYTES: Final = 256 * 1024


class ProtectedRuntimeError(RuntimeError):
    """The probe runtime snapshot could not be established or verified."""


@dataclass(frozen=True, slots=True)
class RuntimeEnvironment:
    """The installed environment facts the probe needs, measured from the interpreter.

    ``executable`` is the selected venv interpreter, ``resolved_executable`` is the base
    interpreter target used for closure hashing and for the isolated launch, ``prefix`` is
    the venv root (whose ``pyvenv.cfg`` is measured), and ``site_packages`` is the exact
    worker dependency directory.
    """

    executable: Path
    resolved_executable: Path
    prefix: Path
    base_prefix: Path
    site_packages: Path
    source_root: Path


@dataclass(frozen=True, slots=True)
class ProtectedRuntime:
    """One measured runtime snapshot the worker is allowed to execute."""

    root: Path
    bootstrap_path: Path
    interpreter: Path
    base_prefix: Path
    site_packages: Path
    source_root: Path
    environment: RuntimeEnvironment
    source: RuntimeIdentity
    snapshot: RuntimeIdentity
    bootstrap_digest: str
    venv_config_path: Path | None
    venv_config_sha256: str | None
    protected_digest: str
    model_asset_scan_files: int
    removed_base_site_packages: tuple[str, ...]
    registry_root: Path

    @property
    def matches(self) -> bool:
        return self.source.digest == self.snapshot.digest

    def bootstrap_sha256(self) -> str:
        _, digest = sha256_file(self.bootstrap_path)
        return digest

    def rescan_for_model(self) -> int:
        return _scan_for_model(self.root)


def protected_runtime_digest(identity: RuntimeIdentity, venv_config_sha256: str | None) -> str:
    """Bind the measured runtime roots and the selected venv config into one digest."""
    payload = {
        "schema": "dynamisbench.protected.runtime-closure/1",
        "runtime_identity": identity.digest,
        "venv_config_sha256": venv_config_sha256,
    }
    return semantic_sha256(payload).hex


def protected_environment(scratch: Path) -> dict[str, str]:
    """The minimal supervisor-controlled environment for the protected launch.

    No inherited credential, `PYTHONPATH`, `PYTHONHOME` or user-site setting is passed. The
    bootstrap reduces the environment again after the -I -S startup. The operating-system
    values Windows requires are copied only by name.

    ``LOCALAPPDATA`` is required by the Windows AppContainer ``CreateProcess`` path: with a
    caller-supplied environment block and ``SECURITY_CAPABILITIES``, Windows refuses the
    launch with ``ERROR_ENVVAR_NOT_FOUND`` unless that variable is present. It is a path,
    not a secret, and the AppContainer token cannot read the user profile it names; the
    bootstrap removes it before importing any scientific code. Its absence is a refusal, not
    an inherited-environment fallback.
    """
    values = {
        "MUJOCO_GL": "disable",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUTF8": "1",
        "TZ": "UTC",
        "TEMP": str(scratch),
        "TMP": str(scratch),
        "HOME": str(scratch),
    }
    if os.name == "nt":
        for name in (
            "SYSTEMROOT",
            "WINDIR",
            # `platform.machine()` reads PROCESSOR_ARCHITECTURE from the environment on
            # Windows, and the pinned adapter refuses an unlabelled host. These are machine
            # facts, not secrets, and the bootstrap's allowlist already keeps them.
            "PROCESSOR_ARCHITECTURE",
            "PROCESSOR_ARCHITEW6432",
            "PROCESSOR_IDENTIFIER",
        ):
            if name in os.environ:
                values[name] = os.environ[name]
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise ProtectedRuntimeError(
                "the Windows AppContainer launch requires LOCALAPPDATA in the supervisor "
                "environment; refusing rather than inheriting a full environment"
            )
        values["LOCALAPPDATA"] = local_app_data
        values["PATH"] = str(Path(values.get("SYSTEMROOT", "C:/Windows")) / "System32")
    else:
        values["PATH"] = "/usr/bin:/bin"
        values["LANG"] = "C.UTF-8"
        values["LC_ALL"] = "C.UTF-8"
        values["TMPDIR"] = str(scratch)
    return values


def protected_worker_command(
    *,
    interpreter: Path,
    bootstrap_path: Path,
    config_sha256: str,
    bootstrap_sha256: str,
) -> tuple[str, ...]:
    """The exact isolated command vector: resolved interpreter, -I -S, pinned digests."""
    return (
        str(interpreter),
        "-I",
        "-S",
        str(bootstrap_path),
        config_sha256,
        bootstrap_sha256,
    )


def _venv_config(environment: RuntimeEnvironment) -> tuple[Path | None, str | None]:
    if os.name == "nt":
        # The Windows snapshot launches a copied base interpreter, not the venv launcher.
        # The venv config is not part of the executed startup and is not exposed to the
        # AppContainer worker; the Linux closure is the one that can select system packages.
        return None, None
    candidate = environment.prefix / "pyvenv.cfg"
    if not candidate.is_file():
        raise ProtectedRuntimeError(
            "the selected Linux worker environment has no pyvenv.cfg to measure"
        )
    info = candidate.lstat()
    if info.st_nlink != 1:
        raise ProtectedRuntimeError("the selected pyvenv.cfg is not a single-link file")
    _, digest = sha256_file(candidate, max_bytes=_MAX_CONFIG_BYTES)
    return candidate, digest


def _run_environment_probe(worker_python: Path) -> RuntimeEnvironment:
    """Read the installed base/site-packages/source facts from the worker interpreter.

    This is a provisioning observation made once, before any attempt. It is not a
    scientific execution and it reads no admitted input.
    """
    script = (
        "import json,sys;"
        "print(json.dumps({"
        "'executable':sys.executable,"
        "'base_prefix':sys.base_prefix,"
        "'prefix':sys.prefix,"
        "'site_packages':[p for p in sys.path if p.endswith('site-packages')]"
        "}))"
    )
    environment = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUTF8": "1",
    }
    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR"):
            if name in os.environ:
                environment[name] = os.environ[name]
    else:
        environment["LANG"] = "C.UTF-8"
        environment["LC_ALL"] = "C.UTF-8"
        environment["TMPDIR"] = os.environ.get("TMPDIR", "/tmp")
        environment["HOME"] = os.environ.get("HOME", "/tmp")
    completed = subprocess.run(
        [str(worker_python), "-I", "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=environment,
    )
    if completed.returncode != 0:
        raise ProtectedRuntimeError(
            f"the worker environment probe failed: {completed.stderr[-1000:]}"
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ProtectedRuntimeError("the worker environment probe did not emit JSON") from error
    launch_executable = Path(value["executable"])
    resolved_executable = launch_executable.resolve()
    prefix = Path(value["prefix"]).resolve()
    base_prefix = Path(value["base_prefix"]).resolve()
    candidates = [Path(item).resolve() for item in value["site_packages"]]
    site_packages = next((item for item in candidates if item.is_dir()), None)
    if site_packages is None:
        raise ProtectedRuntimeError("the worker environment has no site-packages directory")
    source_root = Path(dynamisbench.__file__).resolve().parent.parent
    for label, path in (
        ("executable", launch_executable),
        ("resolved executable", resolved_executable),
        ("prefix", prefix),
        ("base_prefix", base_prefix),
        ("site_packages", site_packages),
        ("source_root", source_root),
    ):
        if not path.exists():
            raise ProtectedRuntimeError(f"the worker environment {label} is absent")
    return RuntimeEnvironment(
        executable=launch_executable,
        resolved_executable=resolved_executable,
        prefix=prefix,
        base_prefix=base_prefix,
        site_packages=site_packages,
        source_root=source_root,
    )


def _system32_tool(name: str) -> str:
    root = os.environ.get("SYSTEMROOT") or os.environ.get("SystemRoot") or "C:/Windows"
    candidate = Path(root) / "System32" / name
    if not candidate.is_file():
        raise ProtectedRuntimeError(f"the system tool {name!r} is not present in System32")
    return str(candidate)


def _robocopy(source: Path, destination: Path) -> None:
    completed = subprocess.run(
        [
            _system32_tool("robocopy.exe"),
            str(source),
            str(destination),
            "/E",
            "/COPY:DAT",
            "/DCOPY:DAT",
            "/R:0",
            "/W:0",
            "/NFL",
            "/NDL",
            "/NJH",
            "/NJS",
            "/NP",
            "/MT:32",
            "/XD",
            "__pycache__",
        ],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if completed.returncode >= 8:
        raise ProtectedRuntimeError(
            f"robocopy to {destination.name!r} failed: {completed.stdout[-500:]} "
            f"{completed.stderr[-500:]}"
        )


def _copy_tree(source: Path, destination: Path) -> None:
    try:
        shutil.copytree(
            source,
            destination,
            symlinks=False,
            ignore=shutil.ignore_patterns("__pycache__"),
        )
    except OSError as error:
        raise ProtectedRuntimeError(f"copying {source.name!r} failed: {error}") from error


def _prune_pycache(root: Path) -> None:
    for current, directories, _files in os.walk(root, topdown=True):
        for name in list(directories):
            if name == "__pycache__":
                shutil.rmtree(Path(current) / name, ignore_errors=True)
                directories.remove(name)


def _remove_known_base_site_packages(site_packages: Path) -> tuple[str, ...]:
    """Remove the base interpreter's own pip bootstrap from the snapshot.

    The approved worker closure is the venv's site-packages, not the base
    interpreter's installer. Keeping pip would make the observed distribution closure
    differ from the reviewed one.
    """
    removed: list[str] = []
    for pattern in ("pip", "pip-*.dist-info", "setuptools", "setuptools-*.dist-info", "README.txt"):
        for path in site_packages.glob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
            removed.append(path.name)
    return tuple(sorted(removed))


def _scan_for_model(root: Path) -> int:
    """Refuse a snapshot that still contains the packaged reference XML bytes."""
    checked = 0
    for current, directories, files in os.walk(root, topdown=True):
        directories[:] = [name for name in directories if name != "__pycache__"]
        for name in files:
            path = Path(current) / name
            try:
                info = path.lstat()
            except OSError:
                continue
            if not path.is_file() or info.st_size > 64 * 1024:
                continue
            if info.st_nlink != 1:
                continue
            checked += 1
            try:
                hasher = hashlib.sha256()
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        hasher.update(chunk)
            except OSError:
                continue
            if hasher.hexdigest() == reference.MODEL_SHA256:
                raise ProtectedRuntimeError(
                    "the runtime snapshot still contains the packaged reference XML"
                )
    return checked


def prepare_protected_runtime(
    *,
    worker_python: Path,
    root: Path,
    platform_tag: str,
    registry_root: Path | None = None,
    profile: PinnedReferenceProfile | None = None,
) -> ProtectedRuntime:
    """Create and measure the protected runtime snapshot under ``root``.

    ``registry_root`` is the supervisor-owned single-use marker directory. It defaults to
    a fresh system temporary directory and must remain outside the sandbox-visible tree.
    ``profile`` is the trusted pinned-reference profile; when supplied, the measured
    bootstrap and platform must match it before any process is launched.
    """
    environment = _run_environment_probe(worker_python)
    if registry_root is None:
        registry_root = Path(tempfile.mkdtemp(prefix="dynamisbench-protected-registry-"))
    registry_root.mkdir(parents=True, exist_ok=True)
    root.mkdir(parents=True, exist_ok=True)
    runtime_root = root
    if platform_tag == "windows-x86-64":
        if os.name != "nt":
            raise ProtectedRuntimeError("a Windows runtime snapshot requires Windows")
        base_copy = runtime_root / "python"
        source_copy = runtime_root / "src"
        runtime_root.mkdir(parents=True, exist_ok=True)
        _robocopy(environment.base_prefix, base_copy)
        _robocopy(environment.site_packages, base_copy / "Lib" / "site-packages")
        _robocopy(environment.source_root, source_copy)
        removed = _remove_known_base_site_packages(base_copy / "Lib" / "site-packages")
        _prune_pycache(base_copy)
        _prune_pycache(source_copy)
        model_path = source_copy / "dynamisbench" / "adapters" / "mujoco" / _MODEL_ASSET
        model_path.unlink(missing_ok=True)
        launch_interpreter = base_copy / "python.exe"
        base_for_worker = base_copy
        site_for_worker = base_copy / "Lib" / "site-packages"
        source_for_worker = source_copy
        source_identity = measure_runtime_identity(
            executable=environment.base_prefix / "python.exe",
            base_prefix=environment.base_prefix,
            site_packages=environment.site_packages,
            source_root=environment.source_root,
            model_asset_relative=_MODEL_ASSET,
            allow_hardlinks=True,
            allow_symlinks=True,
        )
        snapshot_identity = measure_runtime_identity(
            executable=launch_interpreter,
            base_prefix=base_for_worker,
            site_packages=site_for_worker,
            source_root=source_for_worker,
            model_asset_relative=_MODEL_ASSET,
        )
    elif platform_tag == "linux-x86-64":
        if environment.base_prefix in {Path("/"), Path("/usr"), Path("/usr/local")}:
            raise ProtectedRuntimeError(
                "the Linux probe requires a dedicated Python base, not a system prefix; "
                "granting /usr or /usr/local would make every system tool executable"
            )
        if environment.resolved_executable.parent == Path("/usr/bin"):
            raise ProtectedRuntimeError(
                "the Linux probe requires a dedicated interpreter, not a /usr/bin executable"
            )
        site_copy = runtime_root / "site-packages"
        source_copy = runtime_root / "src"
        runtime_root.mkdir(parents=True, exist_ok=True)
        _copy_tree(environment.site_packages, site_copy)
        _copy_tree(environment.source_root, source_copy)
        _prune_pycache(site_copy)
        _prune_pycache(source_copy)
        model_path = source_copy / "dynamisbench" / "adapters" / "mujoco" / _MODEL_ASSET
        model_path.unlink(missing_ok=True)
        # Launch the resolved base interpreter, not the venv launcher. -I -S then makes
        # pyvenv.cfg incapable of selecting system site-packages or another prefix; the
        # selected venv's config is still measured and pinned below.
        launch_interpreter = environment.resolved_executable
        resolved_interpreter = environment.resolved_executable
        base_for_worker = environment.base_prefix
        site_for_worker = site_copy
        source_for_worker = source_copy
        source_identity = measure_runtime_identity(
            executable=resolved_interpreter,
            base_prefix=environment.base_prefix,
            site_packages=environment.site_packages,
            source_root=environment.source_root,
            model_asset_relative=_MODEL_ASSET,
            allow_hardlinks=True,
            allow_symlinks=True,
        )
        snapshot_identity = measure_runtime_identity(
            executable=resolved_interpreter,
            base_prefix=base_for_worker,
            site_packages=site_for_worker,
            source_root=source_for_worker,
            model_asset_relative=_MODEL_ASSET,
        )
        removed = ()
    else:
        raise ProtectedRuntimeError(f"unsupported probe platform {platform_tag!r}")

    if not launch_interpreter.is_file():
        raise ProtectedRuntimeError("the snapshot interpreter is absent")
    checked = _scan_for_model(runtime_root)
    if source_identity.digest != snapshot_identity.digest:
        differing = [
            label
            for label, left, right in (
                ("base", source_identity.base, snapshot_identity.base),
                (
                    "site-packages",
                    source_identity.site_packages_closure,
                    snapshot_identity.site_packages_closure,
                ),
                ("source", source_identity.source, snapshot_identity.source),
            )
            if left.digest != right.digest
        ]
        raise ProtectedRuntimeError(
            "the runtime snapshot does not reproduce the measured installed bytes: "
            + ", ".join(differing)
        )

    bootstrap_path = source_for_worker / _BOOTSTRAP_RELATIVE
    if not bootstrap_path.is_file():
        raise ProtectedRuntimeError("the measured source snapshot has no protected bootstrap")
    _, bootstrap_digest = sha256_file(bootstrap_path, max_bytes=_MAX_CONFIG_BYTES)
    venv_config_path, venv_config_sha256 = _venv_config(environment)
    if profile is not None:
        if profile.platform != platform_tag:
            raise ProtectedRuntimeError("the protected profile is for a different platform")
        if profile.bootstrap_sha256 != bootstrap_digest:
            raise ProtectedRuntimeError(
                "the measured protected bootstrap is not the profile-pinned bytes"
            )
    protected_digest = protected_runtime_digest(snapshot_identity, venv_config_sha256)
    return ProtectedRuntime(
        root=root,
        bootstrap_path=bootstrap_path,
        interpreter=launch_interpreter,
        base_prefix=base_for_worker,
        site_packages=site_for_worker,
        source_root=source_for_worker,
        environment=environment,
        source=source_identity,
        snapshot=snapshot_identity,
        bootstrap_digest=bootstrap_digest,
        venv_config_path=venv_config_path,
        venv_config_sha256=venv_config_sha256,
        protected_digest=protected_digest,
        model_asset_scan_files=checked,
        removed_base_site_packages=removed,
        registry_root=registry_root,
    )


def build_protected_sandbox_config(
    *,
    profile: PinnedReferenceProfile,
    runtime: ProtectedRuntime,
    inputs: Path,
    scratch: Path,
    binding_sha256: str,
    probe_targets: Path,
    read_execute: tuple[str, ...],
    read_only: tuple[str, ...],
    read_write: tuple[str, ...],
) -> dict[str, object]:
    """Build the exact supervisor-pinned sandbox policy for one protected attempt.

    The bootstrap verifies these bytes against the digest passed on its command line
    before reading any value. The Landlock/seccomp module paths are fixed under the
    measured source root; the bootstrap does not accept a caller-selected module.
    """
    mechanism = "windows-appcontainer" if profile.platform == "windows-x86-64" else "linux-landlock"
    source_root = runtime.source_root
    return {
        "schema": _SANDBOX_SCHEMA,
        "mechanism": mechanism,
        "profile_sha256": profile.digest(),
        "runtime_closure_sha256": runtime.protected_digest,
        "inputs": str(inputs),
        "scratch": str(scratch),
        "source_root": str(source_root),
        "site_packages": str(runtime.site_packages),
        "base_prefix": str(runtime.base_prefix),
        "installed_site_packages": str(runtime.environment.site_packages),
        "installed_source_root": str(runtime.environment.source_root),
        "keep_paths": [str(runtime.base_prefix)],
        "landlock_module": str(source_root / "dynamisbench/execution/landlock.py"),
        "seccomp_module": str(source_root / "dynamisbench/execution/seccomp.py"),
        "read_execute": list(read_execute),
        "read_only": list(read_only),
        "read_write": list(read_write),
        "memory_limit_bytes": profile.max_memory_bytes,
        "cpu_time_seconds": profile.max_cpu_seconds,
        "max_file_bytes": profile.max_scratch_bytes,
        "max_open_files": 256,
        "max_scratch_bytes": profile.max_scratch_bytes,
        "max_scratch_entries": profile.max_scratch_entries,
        "binding_sha256": binding_sha256,
        "reference_trajectory_sha256": profile.reference_trajectory_sha256,
        "probe_targets": str(probe_targets),
        "venv_config_path": (
            None if runtime.venv_config_path is None else str(runtime.venv_config_path)
        ),
        "venv_config_sha256": runtime.venv_config_sha256,
        "mode": "materialized-mujoco",
    }


def write_protected_sandbox_config(path: Path, config: dict[str, object]) -> str:
    """Write canonical config bytes create-exclusive and return their SHA-256."""
    data = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(data) > _MAX_CONFIG_BYTES:
        raise ProtectedRuntimeError("the protected sandbox config exceeds its bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise ProtectedRuntimeError("the protected sandbox config already exists") from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return hashlib.sha256(data).hexdigest()
