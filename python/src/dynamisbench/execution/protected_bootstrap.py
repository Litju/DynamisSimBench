"""The protected production bootstrap for the pinned reference route.

This file is executed by the snapshot interpreter with ``-S`` as::

    python -S protected_bootstrap.py <sandbox-config-sha256> <bootstrap-sha256>

It is deliberately a source file inside the measured package tree, not a generated file in a
mutable runtime root. The supervisor hashes it, includes it in the protected profile, and
passes its expected SHA-256 on the command line. The bootstrap refuses a changed config or a
changed itself before it applies any sandbox. The runtime source closure still covers every
byte the worker imports; the profile and runtime digests identify the exact launch.

It imports only the standard library, applies the resource limits and the Linux sandbox,
writes the readiness echo, fixes ``sys.path``, and then imports the production worker. A
failure before the worker is a bounded stderr line and exit 2; no request is answered.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Final

SCHEMA: Final = "dynamisbench.protected.sandbox/1"
MAX_CONFIG_BYTES: Final = 256 * 1024
MAX_BOOTSTRAP_BYTES: Final = 256 * 1024


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path, *, limit: int) -> str:
    info = path.lstat()
    if not path.is_file() or info.st_size > limit or info.st_nlink != 1:
        raise ValueError("the protected file is not one bounded regular single-link file")
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _fail(message: str) -> int:
    sys.stderr.write("dynamisbench protected bootstrap: " + message[:400] + "\n")
    sys.stderr.flush()
    return 2


def _read_config(expected_sha256: str) -> dict[str, Any]:
    path = Path.cwd() / "sandbox.json"
    raw = path.read_bytes()
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("the protected sandbox config exceeds its bound")
    if _sha256_bytes(raw) != expected_sha256:
        raise ValueError("the protected sandbox config is not the supervisor-pinned bytes")
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ValueError("the protected sandbox config has an unknown schema")
    required = {
        "mechanism",
        "profile_sha256",
        "runtime_closure_sha256",
        "inputs",
        "scratch",
        "source_root",
        "site_packages",
        "base_prefix",
        "landlock_module",
        "seccomp_module",
        "read_execute",
        "read_only",
        "read_write",
        "memory_limit_bytes",
        "cpu_time_seconds",
        "max_file_bytes",
        "max_open_files",
    }
    missing = sorted(required - set(value))
    if missing:
        raise ValueError("the protected sandbox config lacks " + ", ".join(missing))
    return value


def _sanitize_environment(scratch: Path) -> list[str]:
    """Keep only the fixed launch allowlist and set the worker's own values.

    The supervisor also passes a minimal environment; this second reduction keeps the worker
    correct if it is launched by a different trusted caller. Nothing here relies on the
    inherited environment being benign.
    """
    keep = {
        "SYSTEMROOT",
        "WINDIR",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_ARCHITEW6432",
        "PROCESSOR_IDENTIFIER",
        "MUJOCO_GL",
        "TEMP",
        "TMP",
        "HOME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "TZ",
    }
    for name in list(os.environ):
        if name.upper() in keep:
            continue
        if name.upper() == "PATH":
            continue
        del os.environ[name]
    if os.name == "nt":
        system_root = os.environ.get("SYSTEMROOT") or os.environ.get("SystemRoot") or "C:/Windows"
        os.environ["PATH"] = str(Path(system_root) / "System32")
    else:
        os.environ["PATH"] = "/usr/bin:/bin"
    os.environ["TEMP"] = str(scratch)
    os.environ["TMP"] = str(scratch)
    os.environ["HOME"] = str(scratch)
    os.environ["TZ"] = "UTC"
    os.environ["MUJOCO_GL"] = "disable"
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["PYTHONIOENCODING"] = "utf-8"
    os.environ["PYTHONNOUSERSITE"] = "1"
    os.environ["PYTHONUTF8"] = "1"
    return sorted(os.environ)


def _fixed_module(source_root: Path, relative: str) -> Any:
    path = (source_root / relative).resolve()
    if not path.is_relative_to(source_root.resolve()) or not path.is_file():
        raise ValueError("a protected sandbox module is outside the measured source root")
    spec = importlib.util.spec_from_file_location("_protected_" + path.stem, path)
    if spec is None or spec.loader is None:
        raise ValueError("a protected sandbox module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _apply_limits_and_sandbox(config: dict[str, Any]) -> tuple[int, dict[str, object]]:
    source_root = Path(config["source_root"]).resolve()
    if config["mechanism"] != "linux-landlock":
        return 0, {}
    landlock = _fixed_module(source_root, "dynamisbench/execution/landlock.py")
    seccomp = _fixed_module(source_root, "dynamisbench/execution/seccomp.py")
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
    seccomp.apply_network_policy()
    return int(abi), seccomp.seccomp_status()


def _write_ready(
    scratch: Path,
    *,
    config: dict[str, Any],
    abi: int,
    seccomp: dict[str, object],
    environment_keys: list[str],
    config_sha256: str,
    bootstrap_sha256: str,
) -> None:
    payload = {
        "schema": "dynamisbench.protected.sandbox-ready/1",
        "mechanism": config["mechanism"],
        "abi": abi,
        "profile_sha256": config["profile_sha256"],
        "runtime_closure_sha256": config["runtime_closure_sha256"],
        "config_sha256": config_sha256,
        "bootstrap_sha256": bootstrap_sha256,
        "environment_sanitized": True,
        "environment_keys": environment_keys,
        "seccomp": seccomp,
    }
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    (scratch / "sandbox-ready.json").write_bytes(data)


def _prepare_sys_path(config: dict[str, Any]) -> None:
    source_root = str(Path(config["source_root"]).resolve())
    site_packages = str(Path(config["site_packages"]).resolve())
    allowed = {source_root, site_packages}
    installed = {
        str(Path(item).resolve())
        for item in (config.get("installed_site_packages"), config.get("installed_source_root"))
        if item
    }
    keep = {str(Path(item).resolve()) for item in config.get("keep_paths", [])}
    retained: list[str] = []
    for entry in sys.path:
        if not entry:
            continue
        try:
            text = str(Path(entry).resolve())
        except OSError:
            continue
        if text in allowed or any(text == item or text.startswith(item + os.sep) for item in keep):
            retained.append(text)
            continue
        if any(text == item or text.startswith(item + os.sep) for item in installed):
            continue
    sys.path[:] = [source_root, site_packages, *dict.fromkeys(retained)]


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv if argv is None else argv
    if not getattr(sys.flags, "no_site", 0) or not getattr(sys.flags, "isolated", 0):
        return _fail("the protected bootstrap requires an isolated -I -S interpreter")
    if len(arguments) != 3:
        return _fail("the protected bootstrap requires the config and bootstrap digests")
    config_sha256, bootstrap_sha256 = arguments[1], arguments[2]
    try:
        actual_bootstrap = _sha256_file(Path(__file__).resolve(), limit=MAX_BOOTSTRAP_BYTES)
        if actual_bootstrap != bootstrap_sha256:
            raise ValueError("the protected bootstrap is not the supervisor-pinned bytes")
        config = _read_config(config_sha256)
        scratch = Path(config["scratch"])
        environment_keys = _sanitize_environment(scratch)
        os.environ["DYNAMISBENCH_PROTECTED_CONFIG_SHA256"] = config_sha256
        os.environ["DYNAMISBENCH_PROTECTED_BOOTSTRAP_SHA256"] = bootstrap_sha256
        os.environ["DYNAMISBENCH_PROTECTED_PROFILE_SHA256"] = str(config["profile_sha256"])
        abi, seccomp = _apply_limits_and_sandbox(config)
        _write_ready(
            scratch,
            config=config,
            abi=abi,
            seccomp=seccomp,
            environment_keys=environment_keys,
            config_sha256=config_sha256,
            bootstrap_sha256=bootstrap_sha256,
        )
        _prepare_sys_path(config)
        from dynamisbench.adapters.mujoco.protected_worker import main as worker_main

        return worker_main()
    except BaseException as error:  # noqa: BLE001 - never claim a response before the worker
        return _fail(f"{type(error).__name__}: {error}")


if __name__ == "__main__":
    raise SystemExit(main())
