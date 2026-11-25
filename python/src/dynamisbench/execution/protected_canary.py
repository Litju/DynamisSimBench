"""Localhost canaries for the protected worker, with a post-exit drain.

The probe canary reads its counters immediately after the worker exits. That is a race: a
single listener thread may be in the UDP or Unix accept step when the last TCP connection
arrives, so a zero count at that instant is not proof of zero delivery. The production
canary keeps the same positive-control requirement and adds :meth:`drain`, which waits for
at least two complete listener cycles after the worker is gone before the supervisor reads
the counters. The profile still narrows the Windows claim to the measured paths; this class
does not turn a canary into a universal network sandbox.
"""

from __future__ import annotations

import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import Final

__all__ = ["ProtectedNetworkCanary"]

_DEFAULT_TIMEOUT: Final = 0.2


class ProtectedNetworkCanary:
    """One TCP, UDP and (where available) Unix listener for one protected attempt."""

    def __init__(self) -> None:
        self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp.bind(("127.0.0.1", 0))
        self._tcp.listen(1)
        self._tcp.settimeout(_DEFAULT_TIMEOUT)
        self.port = int(self._tcp.getsockname()[1])

        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind(("127.0.0.1", 0))
        self._udp.settimeout(_DEFAULT_TIMEOUT)
        self.udp_port = int(self._udp.getsockname()[1])

        self._unix_path: Path | None = None
        self._unix: socket.socket | None = None
        unix_family = getattr(socket, "AF_UNIX", None)
        if unix_family is not None:
            self._unix_path = Path(tempfile.mkdtemp(prefix="dynamisbench-canary-")) / "worker.sock"
            listener = socket.socket(unix_family, socket.SOCK_STREAM)
            listener.bind(str(self._unix_path))
            listener.listen(1)
            listener.settimeout(_DEFAULT_TIMEOUT)
            self._unix = listener

        self.accepted = 0
        self.udp_received = 0
        self.unix_accepted = 0
        self._cycles = 0
        self._lock = threading.Lock()
        self._cycle_changed = threading.Condition(self._lock)
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
        """Prove each active listener receives before a worker count is interpreted."""
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
            probe.sendto(b"DYNAMISBENCH-CANARY-CONTROL", ("127.0.0.1", self.udp_port))
        finally:
            probe.close()
        results["udp"] = self._wait_for("udp_received", 1)
        self._reset("udp_received")

        unix_family = getattr(socket, "AF_UNIX", None)
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
            with self._cycle_changed:
                self._cycles += 1
                self._cycle_changed.notify_all()

    def drain(self, timeout: float = 2.0) -> None:
        """Wait for at least two listener cycles so a last-instant event is observed.

        The listener performs a 0.2 s accept/recv/accept sequence. Two completed cycles
        after the worker is reaped cover every channel before the supervisor reads the
        counters. This is a settle, not a promise that every destination or socket family
        is covered.
        """
        with self._cycle_changed:
            target = self._cycles + 2
            self._cycle_changed.wait_for(
                lambda: self._cycles >= target or self._stop.is_set(), timeout=timeout
            )

    def close(self) -> None:
        self._stop.set()
        with self._cycle_changed:
            self._cycle_changed.notify_all()
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
