"""Supervisor-owned cgroup v2 containment for the protected Linux worker.

This is the host primitive for the protected execution route, not a route. It exists because
a POSIX session/process group is not an ownership primitive: a worker that calls ``setsid()``
leaves the group, and a descendant whose direct parent exits is no longer reachable through
the parent pid. A cgroup v2 subtree is owned by the supervisor rather than by the worker's
session, so every task that descends from the attached worker remains in the subtree until
the supervisor kills or removes it.

The host must delegate a writable cgroup v2 root to the supervisor. That is a real
provisioning requirement, not a fallback: :func:`delegated_root` refuses a read-only or
non-delegated hierarchy, and the launcher refuses to start rather than pretending the weaker
process-group primitive is equivalent. The delegated root must be a leaf domain cgroup (no
processes of its own), because cgroup v2 does not allow enabling a controller on a cgroup
that has internal processes.

The attempt is attached before the scientific interpreter executes. A tiny trusted launcher
writes its own pid (``0``) to the attempt's ``cgroup.procs`` and then ``execve``s the worker.
The worker therefore starts inside the subtree; there is no window in which unsupervised
worker code runs before attachment. ``cgroup.kill`` terminates the whole subtree, including
a child that called ``setsid()`` or outlived its direct parent, and ``cgroup.events``
(``populated 0``) is the emptiness oracle rather than a scan of the visible process table.

This is not a filesystem, network or memory sandbox by itself. The caller still applies the
Landlock allowlist and the seccomp policy, and the cgroup memory/pids limits are additional
bounds on the same attempt.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = [
    "CgroupError",
    "CgroupLimits",
    "CgroupObservation",
    "CgroupUnavailableError",
    "CgroupV2",
    "attach_code",
    "cgroup2_mount_for",
    "cgroup_available",
    "delegated_root",
    "verify_supervisor_placement",
]

_POLL_SECONDS: Final = 0.02
_DEFAULT_KILL_GRACE_SECONDS: Final = 5.0
_DEFAULT_CONTROLLERS: Final = ("pids", "memory", "cpu")
_REQUIRED_CONTROLLERS: Final = frozenset({"pids", "memory"})
_CGROUP2_FSTYPE: Final = "cgroup2"
_ATTACH_CODE: Final = (
    "import os,sys\n"
    "fd=os.open(sys.argv[1],os.O_WRONLY)\n"
    "try:\n"
    " os.write(fd,b'0')\n"
    "finally:\n"
    " os.close(fd)\n"
    "os.execv(sys.argv[2],sys.argv[2:])\n"
)


class CgroupError(RuntimeError):
    """The cgroup subtree could not be established or verified."""


class CgroupUnavailableError(CgroupError):
    """The host does not provide the delegated cgroup v2 mechanism this probe requires."""


@dataclass(frozen=True, slots=True)
class CgroupLimits:
    """The kernel bounds written into one attempt subtree.

    ``pids_max`` counts tasks, not processes: every thread in the worker's address space is
    one pid in the cgroup pids controller. The value must therefore be qualified against the
    real NumPy/OpenBLAS/MuJoCo thread requirements, not copied from a process-only limit.
    """

    pids_max: int
    memory_max_bytes: int
    swap_max_bytes: int = 0
    cpu_max: str | None = None

    def __post_init__(self) -> None:
        if self.pids_max <= 0:
            raise ValueError("a cgroup pids limit must be positive")
        if self.memory_max_bytes <= 0:
            raise ValueError("a cgroup memory limit must be positive")
        if self.swap_max_bytes < 0:
            raise ValueError("a cgroup swap limit must not be negative")


@dataclass(frozen=True, slots=True)
class CgroupObservation:
    """The kernel-authored facts observed from outside the worker."""

    path: str
    pids_current: int
    pids_peak: int
    pids_max: int
    pids_events_max: int
    memory_peak_bytes: int
    memory_events: dict[str, int]
    cpu_usage_usec: int
    populated: bool
    thread_count: int

    def as_json(self) -> dict[str, object]:
        return {
            "path": self.path,
            "pids_current": self.pids_current,
            "pids_peak": self.pids_peak,
            "pids_max": self.pids_max,
            "pids_events_max": self.pids_events_max,
            "memory_peak_bytes": self.memory_peak_bytes,
            "memory_events": dict(sorted(self.memory_events.items())),
            "cpu_usage_usec": self.cpu_usage_usec,
            "populated": self.populated,
            "thread_count": self.thread_count,
        }


def attach_code() -> str:
    """Return the fixed launcher source that moves itself into the subtree before exec.

    The code is a constant, not a file the worker or a caller can edit. ``os.open`` with
    ``O_WRONLY`` on ``cgroup.procs`` and writing ``0`` moves the calling task; the descriptor
    is closed before ``execve`` so the worker does not inherit a handle to the cgroup.
    """
    return _ATTACH_CODE


def _mountinfo() -> list[tuple[Path, Path, str]]:
    """Return ``(mount_root, mount_point, fstype)`` for every mount in this namespace."""
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise CgroupUnavailableError("the cgroup mount table is not readable") from error
    mounts: list[tuple[Path, Path, str]] = []
    for line in lines:
        try:
            before, after = line.split(" - ", 1)
            fields = before.split()
            fstype = after.split()[0]
            mount_root = Path(fields[3])
            mount_point = Path(fields[4])
        except (IndexError, ValueError):
            continue
        mounts.append((mount_root, mount_point, fstype))
    return mounts


def cgroup2_mount_for(path: Path) -> Path | None:
    """Return the cgroup2 mount point containing ``path``, or ``None``.

    The check is a mount-table fact rather than a filename convention. A directory under
    ``/sys/fs/cgroup`` that is not actually part of the cgroup2 hierarchy is refused.
    """
    target = path.resolve()
    candidates = [
        (mount_point, mount_root)
        for mount_root, mount_point, fstype in _mountinfo()
        if fstype == _CGROUP2_FSTYPE and target.is_relative_to(mount_point.resolve())
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda item: len(item[0].parts))[0]


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise CgroupError(f"the cgroup file {path.name!r} is not readable") from error


def _read_int(path: Path) -> int:
    value = _read(path)
    try:
        return int(value)
    except ValueError as error:
        raise CgroupError(f"the cgroup file {path.name!r} is not an integer") from error


def _read_key_values(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in _read(path).splitlines():
        name, _, raw = line.partition(" ")
        try:
            values[name] = int(raw)
        except ValueError:
            continue
    return values


def _write(path: Path, value: str) -> None:
    try:
        path.write_text(value + "\n", encoding="ascii")
    except OSError as error:
        raise CgroupError(f"the cgroup file {path.name!r} could not be written") from error


def _controllers(root: Path) -> frozenset[str]:
    return frozenset(_read(root / "cgroup.controllers").split())


def _subtree_control(root: Path) -> frozenset[str]:
    return frozenset(_read(root / "cgroup.subtree_control").split())


def _enable_controllers(root: Path) -> frozenset[str]:
    """Make the attempt's controllers available beneath the delegated root.

    cgroup v2 exposes a controller to children only when the parent's
    ``cgroup.subtree_control`` names it, and a controller may not be enabled on a cgroup
    that still has processes. The delegated root is expected to be a leaf. The function is
    idempotent and refuses when the required controller cannot be enabled.
    """
    available = _controllers(root)
    missing = _REQUIRED_CONTROLLERS - available
    if missing:
        raise CgroupUnavailableError(
            "the delegated cgroup root does not expose the required "
            + ", ".join(sorted(missing))
            + " controller"
        )
    enabled = _subtree_control(root)
    desired = [name for name in _DEFAULT_CONTROLLERS if name in available and name not in enabled]
    if desired:
        try:
            _write(root / "cgroup.subtree_control", " ".join(f"+{name}" for name in desired))
        except CgroupError as error:
            raise CgroupUnavailableError(
                "the delegated cgroup root cannot enable its controllers; it must be a "
                "leaf cgroup delegated to this supervisor with no internal processes"
            ) from error
    if not _REQUIRED_CONTROLLERS <= _subtree_control(root):
        raise CgroupUnavailableError(
            "the delegated cgroup root did not expose the required pids controller"
        )
    return _subtree_control(root)


def _is_delegated(path: Path) -> bool:
    try:
        if not path.is_absolute() or not path.is_dir() or path.is_symlink():
            return False
        if cgroup2_mount_for(path) is None:
            return False
        if not (path / "cgroup.procs").is_file() or not (path / "cgroup.kill").is_file():
            return False
        if not (path / "pids.peak").is_file():
            return False
        if _read(path / "cgroup.type") != "domain":
            return False
        if not _REQUIRED_CONTROLLERS <= _controllers(path):
            return False
        if not os.access(path, os.W_OK | os.X_OK):
            return False
        return os.access(path / "cgroup.procs", os.W_OK)
    except (CgroupError, OSError):
        return False


def _self_cgroup_path() -> Path | None:
    try:
        lines = Path("/proc/self/cgroup").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        if line.startswith("0::"):
            value = line[3:].strip()
            return Path(value) if value else Path("/")
    return None


def _mount_root_for(mount_point: Path) -> Path | None:
    for mount_root, candidate, fstype in _mountinfo():
        if fstype == _CGROUP2_FSTYPE and candidate.resolve() == mount_point.resolve():
            return mount_root
    return None


def verify_supervisor_placement(root: Path) -> None:
    """Require the supervisor to own a child of the delegated root, not the root itself.

    cgroup v2 does not allow enabling controllers on a cgroup that has internal processes.
    A delegated root therefore stays empty and the supervisor runs in one of its children;
    attempts are siblings of that supervisor child. This is the placement a systemd
    ``Delegate=yes`` service gets (the service manager places the payload in a child), and
    it is also what makes an attempt subtree killable without killing the supervisor.

    A supervisor that is outside the delegated root cannot migrate a child into it on a
    normal unprivileged host, so refusing here turns an obscure EACCES into a clear
    provisioning refusal.
    """
    mount_point = cgroup2_mount_for(root)
    if mount_point is None:
        raise CgroupUnavailableError("the cgroup root is not on a cgroup2 mount")
    mount_root = _mount_root_for(mount_point)
    current = _self_cgroup_path()
    if mount_root is None or current is None:
        raise CgroupUnavailableError("the supervisor's own cgroup is not readable")
    root_full = mount_root / root.resolve().relative_to(mount_point.resolve())
    current_full = mount_root / current.relative_to("/")
    if current_full == root_full or not current_full.is_relative_to(root_full):
        raise CgroupUnavailableError(
            "the supervisor must run in a child cgroup of the delegated root "
            f"{str(root)!r}; this process is in {str(current_full)!r}. Provision the "
            "service with Delegate=yes or launch the supervisor inside "
            f"{str(root / 'supervisor')!r}."
        )


def delegated_root(explicit: Path | None = None) -> Path:
    """Return the writable delegated cgroup v2 root, or refuse.

    Resolution order is explicit argument, ``DYNAMISBENCH_CGROUP_ROOT``, then the documented
    provisioned path ``/sys/fs/cgroup/dynamisbench``. An explicit value that is not a valid
    delegation is a refusal; it is not silently ignored in favour of a later candidate.
    """
    if explicit is not None:
        if not _is_delegated(explicit):
            raise CgroupUnavailableError(
                f"the requested cgroup root {str(explicit)!r} is not a writable, domain, "
                "pids-capable cgroup v2 delegation"
            )
        return explicit
    configured = os.environ.get("DYNAMISBENCH_CGROUP_ROOT")
    if configured:
        candidate = Path(configured)
        if not _is_delegated(candidate):
            raise CgroupUnavailableError(
                f"DYNAMISBENCH_CGROUP_ROOT={configured!r} is not a writable, domain, "
                "pids-capable cgroup v2 delegation"
            )
        return candidate
    provisioned = Path("/sys/fs/cgroup/dynamisbench")
    if _is_delegated(provisioned):
        return provisioned
    raise CgroupUnavailableError(
        "no delegated cgroup v2 root is available; provision a writable leaf cgroup such "
        "as /sys/fs/cgroup/dynamisbench and set DYNAMISBENCH_CGROUP_ROOT, or keep the "
        "worker in probe-only mode"
    )


def cgroup_available(explicit: Path | None = None) -> bool:
    """Whether a valid delegated root and supervisor placement can be established.

    The controller flags are enabled as part of the check. That is idempotent and is the only
    way to know that this delegated root can actually expose ``pids.max`` to an attempt.
    """
    try:
        root = delegated_root(explicit)
        _enable_controllers(root)
        verify_supervisor_placement(root)
    except (CgroupError, OSError):
        return False
    return True


class CgroupV2:
    """One supervisor-owned cgroup v2 attempt subtree."""

    __slots__ = ("_closed", "_limits", "path", "root")

    def __init__(self, root: Path, path: Path, limits: CgroupLimits) -> None:
        self.root = root
        self.path = path
        self._limits = limits
        self._closed = False

    @classmethod
    def create(
        cls,
        *,
        root: Path | None = None,
        name: str | None = None,
        limits: CgroupLimits,
    ) -> CgroupV2:
        """Create a fresh attempt subtree and write its bounds, or clean up and refuse."""
        delegated = delegated_root(root)
        _enable_controllers(delegated)
        verify_supervisor_placement(delegated)
        attempt_name = name or f"attempt-{uuid.uuid4().hex[:16]}"
        if "/" in attempt_name or attempt_name in {"", ".", ".."}:
            raise CgroupUnavailableError("a cgroup attempt name must be one path component")
        path = delegated / attempt_name
        try:
            path.mkdir(mode=0o755)
        except FileExistsError as error:
            raise CgroupUnavailableError("the cgroup attempt already exists") from error
        except OSError as error:
            raise CgroupUnavailableError(
                "the delegated cgroup root refused a new attempt subtree"
            ) from error
        instance = cls(delegated, path, limits)
        try:
            instance._configure()
        except BaseException:
            instance._cleanup_failed_setup()
            raise
        return instance

    def _configure(self) -> None:
        for name, value in (
            ("pids.max", str(self._limits.pids_max)),
            ("memory.max", str(self._limits.memory_max_bytes)),
            ("memory.swap.max", str(self._limits.swap_max_bytes)),
            ("memory.oom.group", "1"),
        ):
            target = self.path / name
            if not target.exists():
                raise CgroupUnavailableError(
                    f"the delegated cgroup does not expose the required {name!r} control"
                )
            _write(target, value)
        if self._limits.cpu_max is not None:
            cpu_max = self.path / "cpu.max"
            if cpu_max.exists():
                _write(cpu_max, self._limits.cpu_max)
        if _read(self.path / "pids.max") != str(self._limits.pids_max):
            raise CgroupError("the cgroup did not retain the requested pids limit")
        if _read(self.path / "memory.max") != str(self._limits.memory_max_bytes):
            raise CgroupError("the cgroup did not retain the requested memory limit")
        if _read(self.path / "memory.swap.max") != str(self._limits.swap_max_bytes):
            raise CgroupError("the cgroup did not retain the requested swap limit")

    def _cleanup_failed_setup(self) -> None:
        try:
            self.kill()
        except CgroupError:
            pass
        self.wait_empty(_DEFAULT_KILL_GRACE_SECONDS)
        self.remove()

    def launcher_command(
        self,
        *,
        launcher_python: Path,
        worker_program: Path,
        worker_arguments: Sequence[str],
    ) -> list[str]:
        """Return the fixed command that attaches itself and then execs the worker.

        ``launcher_python`` is the supervisor's own interpreter, not the scientific worker's.
        It runs only stdlib code from ``-c``; the cgroup path is an argument and the worker
        program is exec'd with the exact vector the caller supplied. No shell is involved.
        """
        if self._closed:
            raise CgroupError("the cgroup attempt has already been closed")
        return [
            str(launcher_python),
            "-I",
            "-S",
            "-c",
            _ATTACH_CODE,
            str(self.path / "cgroup.procs"),
            str(worker_program),
            *worker_arguments,
        ]

    def procs(self) -> tuple[int, ...]:
        raw = _read(self.path / "cgroup.procs")
        if not raw:
            return ()
        return tuple(sorted(int(line) for line in raw.splitlines() if line.strip()))

    def threads(self) -> int:
        raw = _read(self.path / "cgroup.threads")
        return sum(1 for line in raw.splitlines() if line.strip())

    def pids_current(self) -> int:
        return _read_int(self.path / "pids.current")

    def events(self) -> dict[str, int]:
        return _read_key_values(self.path / "cgroup.events")

    def observe(self) -> CgroupObservation:
        pids_events = (
            _read_key_values(self.path / "pids.events")
            if (self.path / "pids.events").exists()
            else {}
        )
        memory_events = (
            _read_key_values(self.path / "memory.events")
            if (self.path / "memory.events").exists()
            else {}
        )
        cpu_stat = (
            _read_key_values(self.path / "cpu.stat") if (self.path / "cpu.stat").exists() else {}
        )
        return CgroupObservation(
            path=str(self.path),
            pids_current=self.pids_current(),
            pids_peak=_read_int(self.path / "pids.peak"),
            pids_max=_read_int(self.path / "pids.max"),
            pids_events_max=pids_events.get("max", 0),
            memory_peak_bytes=(
                _read_int(self.path / "memory.peak") if (self.path / "memory.peak").exists() else 0
            ),
            memory_events=memory_events,
            cpu_usage_usec=cpu_stat.get("usage_usec", 0),
            populated=bool(self.events().get("populated", 0)),
            thread_count=self.threads(),
        )

    def verify_attached(self, pid: int, timeout: float = 5.0) -> bool:
        """Wait until ``pid`` is a member of this subtree, or return ``False``."""
        deadline = time.monotonic() + timeout
        while True:
            try:
                if pid in self.procs():
                    return True
            except CgroupError:
                return False
            if time.monotonic() >= deadline:
                return False
            time.sleep(_POLL_SECONDS)

    def kill(self) -> bool:
        """Kill every task in the subtree; return whether the write was accepted."""
        if self._closed:
            return False
        try:
            _write(self.path / "cgroup.kill", "1")
        except CgroupError:
            return False
        return True

    def wait_empty(self, timeout: float = _DEFAULT_KILL_GRACE_SECONDS) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            try:
                populated = self.events().get("populated", 1)
                procs = self.procs()
            except CgroupError:
                return False
            if populated == 0 and not procs:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(_POLL_SECONDS)

    def remove(self) -> bool:
        """Remove an empty attempt subtree, reporting whether the directory is gone."""
        if self._closed:
            return not self.path.exists()
        try:
            self.path.rmdir()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return True

    def close(self, *, timeout: float = _DEFAULT_KILL_GRACE_SECONDS) -> bool:
        """Kill, drain and remove the subtree; never leave it silently owned."""
        if self._closed:
            return not self.path.exists()
        killed = self.kill()
        empty = self.wait_empty(timeout)
        removed = self.remove()
        self._closed = True
        return bool(killed and empty and removed)

    def __enter__(self) -> CgroupV2:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
