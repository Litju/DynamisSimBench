"""RES-555 Gate B2: Linux seccomp network-policy qualifications."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from dynamisbench.execution._b2_seccomp import (
    BLOCKED_NETWORK_SYSCALLS,
    BLOCKED_PROCESS_SYSCALLS,
    build_network_filter,
    seccomp_available,
)

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="seccomp is Linux-only"
)


def test_the_filter_blocks_every_socket_path_and_the_io_uring_bypass() -> None:
    program = build_network_filter()
    assert program[0].code == 0x20  # BPF_LD | BPF_W | BPF_ABS, arch
    assert len(program) >= 3 + 2 * len(BLOCKED_NETWORK_SYSCALLS)
    assert 41 in BLOCKED_NETWORK_SYSCALLS  # socket
    assert 53 in BLOCKED_NETWORK_SYSCALLS  # socketpair
    assert 425 in BLOCKED_NETWORK_SYSCALLS  # io_uring_setup
    assert 101 in BLOCKED_PROCESS_SYSCALLS  # ptrace
    assert 62 in BLOCKED_PROCESS_SYSCALLS  # kill


def test_the_installed_policy_denies_every_socket_family_and_keeps_fork_and_threads() -> None:
    if not seccomp_available():
        pytest.skip("this kernel does not expose seccomp filter mode")
    script = r"""
import ctypes, json, os, signal, socket, sys, threading
from dynamisbench.execution._b2_seccomp import apply_network_policy, seccomp_status
apply_network_policy()
result = {"status": seccomp_status()}
for name, factory in (
    ("tcp", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM)),
    ("udp", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM)),
    ("unix", lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)),
    ("pair", lambda: socket.socketpair()),
):
    try:
        factory()
    except PermissionError:
        result[name] = "denied"
    except BaseException as error:
        result[name] = type(error).__name__
    else:
        result[name] = "allowed"
libc = ctypes.CDLL(None, use_errno=True)
result["clone3"] = libc.syscall(435, 0, 0)
result["clone3_errno"] = ctypes.get_errno()
try:
    os.kill(os.getpid(), signal.SIGTERM)
except PermissionError:
    result["kill"] = "denied"
else:
    result["kill"] = "allowed"
pid = os.fork()
if pid == 0:
    os._exit(0)
os.waitpid(pid, 0)
result["fork"] = "allowed"
values = []
thread = threading.Thread(target=lambda: values.append(1))
thread.start()
thread.join()
result["thread"] = values
print(json.dumps(result, sort_keys=True))
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["status"]["Seccomp"] == "2"
    assert int(result["status"]["Seccomp_filters"]) >= 1
    for name in ("tcp", "udp", "unix", "pair", "kill"):
        assert result[name] == "denied", (name, result)
    assert result["clone3"] == -1
    assert result["clone3_errno"] == 38  # ENOSYS, so glibc falls back to clone(2)
    assert result["fork"] == "allowed"
    assert result["thread"] == [1]
