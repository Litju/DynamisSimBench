"""Probe-only runtime snapshot and bootstrap writer for RES-555 Gate B2.

The supervisor measures the installed runtime, derives the exact bytes the worker will
execute, removes every packaged copy of the reference XML from that snapshot, and then
re-measures the snapshot. The worker measures the same roots again inside the sandbox.
A source/snapshot/worker digest disagreement refuses the attempt before physics.

Windows uses a full byte-copy of the base installation plus the approved worker
site-packages inside the AppContainer's private folder. Linux uses the installed base
interpreter and a copied site-packages/source snapshot so Landlock can deny the installed
site-packages and original source. Both snapshots delete ``__pycache__`` and the packaged
reference XML; the only model bytes are the verified input-view bytes.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import dynamisbench
from dynamisbench.adapters.mujoco import reference
from dynamisbench.adapters.mujoco._b2_probe_common import (
    RuntimeIdentity,
    measure_runtime_identity,
    sha256_file,
)

__all__ = ["ProtectedRuntime", "ProtectedRuntimeError", "RuntimeEnvironment"]

_MODEL_ASSET = "assets/reference_pendulum.xml"
_BOOTSTRAP: Final = '''"""Generated, fixed probe bootstrap.

No caller-supplied code executes here; the file is measured before launch.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path


def _ready(scratch: Path, mechanism: str, abi: int, profile: str, digest: str) -> None:
    payload = {
        "schema": "dynamisbench.res555.sandbox-ready/1",
        "mechanism": mechanism,
        "abi": abi,
        "profile_sha256": profile,
        "runtime_closure_sha256": digest,
        "environment_sanitized": True,
        "environment_keys": sorted(os.environ),
    }
    (scratch / "sandbox-ready.json").write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\\n",
        encoding="utf-8",
    )


def main() -> int:
    config = json.loads((Path.cwd() / "sandbox.json").read_text(encoding="utf-8"))
    scratch = Path(config["scratch"])
    system_root = os.environ.get("SYSTEMROOT") or os.environ.get("SystemRoot") or "C:/Windows"
    for name in list(os.environ):
        normalised = name.upper()
        if normalised in {
            "SYSTEMROOT",
            "WINDIR",
            "PROCESSOR_ARCHITECTURE",
            "PROCESSOR_ARCHITEW6432",
            "PROCESSOR_IDENTIFIER",
        }:
            continue
        if normalised == "PATH":
            os.environ[name] = str(Path(system_root) / "System32")
            continue
        if normalised in {"TEMP", "TMP", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ"}:
            continue
        del os.environ[name]
    os.environ["TEMP"] = str(scratch)
    os.environ["TMP"] = str(scratch)
    os.environ["HOME"] = str(scratch)
    os.environ["TZ"] = "UTC"
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["PYTHONIOENCODING"] = "utf-8"
    os.environ["PYTHONNOUSERSITE"] = "1"
    os.environ["PYTHONUTF8"] = "1"
    os.environ["DYNAMISBENCH_RES555_B2_PROBE"] = "1"
    if config["mechanism"] == "linux-landlock":
        spec = importlib.util.spec_from_file_location(
            "_b2_landlock_probe", config["landlock_module"]
        )
        if spec is None or spec.loader is None:
            raise SystemExit("the probe Landlock module could not be loaded")
        landlock = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(landlock)
        landlock.apply_limits(
            memory_bytes=int(config["memory_limit_bytes"]),
            cpu_seconds=int(config["cpu_time_seconds"]),
            file_bytes=int(config["max_file_bytes"]),
            open_files=int(config["max_open_files"]),
        )
        abi = landlock.apply(
            read_execute=[Path(item) for item in config["read_execute"]],
            read_only=[Path(item) for item in config["read_only"]],
            read_write=[Path(item) for item in config["read_write"]],
        )
        _ready(
            scratch,
            "linux-landlock",
            int(abi),
            config["profile_sha256"],
            config["runtime_closure_sha256"],
        )
    else:
        _ready(
            scratch,
            "windows-appcontainer",
            0,
            config["profile_sha256"],
            config["runtime_closure_sha256"],
        )

    allowed = [config["source_root"], config["site_packages"]]
    installed = (
        config.get("installed_site_packages", ""),
        config.get("installed_source_root", ""),
    )
    retained: list[str] = []
    for entry in sys.path:
        if not entry:
            continue
        try:
            resolved = Path(entry).resolve()
        except OSError:
            continue
        text = str(resolved)
        if any(text == item or text.startswith(item + os.sep) for item in allowed):
            retained.append(text)
            continue
        if any(
            text == item or text.startswith(item + os.sep)
            for item in installed
            if item
        ):
            continue
        if any(text == item or text.startswith(item + os.sep) for item in config["keep_paths"]):
            retained.append(text)
    sys.path[:] = [config["source_root"], config["site_packages"], *dict.fromkeys(retained)]

    from dynamisbench.adapters.mujoco._b2_probe_worker import main as worker_main

    return worker_main()


raise SystemExit(main())
'''


class ProtectedRuntimeError(RuntimeError):
    """The probe runtime snapshot could not be established or verified."""


@dataclass(frozen=True, slots=True)
class RuntimeEnvironment:
    """The installed environment facts the probe needs, measured from the interpreter."""

    executable: Path
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
    model_asset_scan_files: int
    removed_base_site_packages: tuple[str, ...]

    @property
    def matches(self) -> bool:
        return self.source.digest == self.snapshot.digest

    def bootstrap_sha256(self) -> str:
        _, digest = sha256_file(self.bootstrap_path)
        return digest

    def rescan_for_model(self) -> int:
        return _scan_for_model(self.root)


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
    executable = Path(value["executable"]).resolve()
    base_prefix = Path(value["base_prefix"]).resolve()
    candidates = [Path(item).resolve() for item in value["site_packages"]]
    site_packages = next((item for item in candidates if item.is_dir()), None)
    if site_packages is None:
        raise ProtectedRuntimeError("the worker environment has no site-packages directory")
    source_root = Path(dynamisbench.__file__).resolve().parent.parent
    for label, path in (
        ("executable", executable),
        ("base_prefix", base_prefix),
        ("site_packages", site_packages),
        ("source_root", source_root),
    ):
        if not path.exists():
            raise ProtectedRuntimeError(f"the worker environment {label} is absent")
    return RuntimeEnvironment(
        executable=executable,
        base_prefix=base_prefix,
        site_packages=site_packages,
        source_root=source_root,
    )


def _robocopy(source: Path, destination: Path) -> None:
    completed = subprocess.run(
        [
            "robocopy",
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


def prepare_runtime(
    *,
    worker_python: Path,
    root: Path,
    platform_tag: str,
) -> ProtectedRuntime:
    """Create and measure the probe runtime snapshot under ``root``."""
    environment = _run_environment_probe(worker_python)
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
        )
        snapshot_identity = measure_runtime_identity(
            executable=launch_interpreter,
            base_prefix=base_for_worker,
            site_packages=site_for_worker,
            source_root=source_for_worker,
            model_asset_relative=_MODEL_ASSET,
        )
    elif platform_tag == "linux-x86-64":
        site_copy = runtime_root / "site-packages"
        source_copy = runtime_root / "src"
        runtime_root.mkdir(parents=True, exist_ok=True)
        _copy_tree(environment.site_packages, site_copy)
        _copy_tree(environment.source_root, source_copy)
        _prune_pycache(site_copy)
        _prune_pycache(source_copy)
        model_path = source_copy / "dynamisbench" / "adapters" / "mujoco" / _MODEL_ASSET
        model_path.unlink(missing_ok=True)
        launch_interpreter = environment.executable
        resolved_interpreter = launch_interpreter.resolve()
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

    bootstrap_path = runtime_root / "bootstrap.py"
    bootstrap_path.write_text(_BOOTSTRAP, encoding="utf-8")
    _, bootstrap_digest = sha256_file(bootstrap_path)
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
        model_asset_scan_files=checked,
        removed_base_site_packages=removed,
    )
