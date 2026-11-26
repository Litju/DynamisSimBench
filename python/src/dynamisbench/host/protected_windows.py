"""Windows AppContainer launch boundary for the protected execution route.

This module is the host primitive, not a route. It creates a per-attempt AppContainer
profile, launches a suspended worker inside it, assigns the worker to a bounded Job Object,
and verifies the AppContainer token from outside the worker. It never decides *whether* a
protected attempt is authorized: :mod:`dynamisbench.execution.protected_launch` owns that,
and nothing here may substitute an unprotected launch.

The AppContainer token is a lowbox/restricted token with the package SID and no internet
capability. File access is the intersection of the normal and restricted checks; this is not
an absence-of-user-SID claim.
The attempt's runtime, input view and scratch receive explicit DACLs: read/execute for the
runtime and input, and read/write for scratch. The original workspace and the interactive
user profile are not granted to the package SID.

**Production principal.** The owner adopted a non-elevated supervisor for production
(RES-555 owner record, D3 Windows). The isolation facts measured on an elevated token — low
integrity, package SID, zero capabilities — are still recorded, but an elevated principal is
not the accepted production configuration. :func:`require_non_elevated_supervisor` is the
gate: it refuses rather than silently treating an elevated token as qualified. It is called
by the protected launcher and can be overridden only by an explicit residual acceptance that
re-qualifies that principal.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
from collections.abc import Mapping
from ctypes import wintypes
from pathlib import Path
from typing import Any, Final

try:
    import msvcrt as _msvcrt
except ImportError:  # pragma: no cover - exercised by the Linux collection gate
    _msvcrt = None

__all__ = [
    "AppContainerError",
    "AppContainerProcess",
    "AppContainerProfile",
    "PrincipalError",
    "current_user_sid",
    "grant_tree",
    "is_available",
    "require_non_elevated_supervisor",
    "restore_user_control",
    "supervisor_principal",
]

_PSID = ctypes.c_void_p
_HRESULT = ctypes.c_long
_INVALID_HANDLE_VALUE: Final = ctypes.c_void_p(-1).value
_WAIT_OBJECT_0: Final = 0x00000000
_WAIT_TIMEOUT: Final = 0x00000102
_STILL_ACTIVE: Final = 259
_PROCESS_QUERY_LIMITED_INFORMATION: Final = 0x1000
_TOKEN_QUERY: Final = 0x0008
_TOKEN_USER: Final = 1
_TOKEN_PRIVILEGES: Final = 3
_TOKEN_ELEVATION: Final = 20
_TOKEN_ELEVATION_TYPE: Final = 18
_TOKEN_HAS_RESTRICTIONS: Final = 21
_TOKEN_INTEGRITY_LEVEL: Final = 25
_TOKEN_IS_APPCONTAINER: Final = 29
_TOKEN_CAPABILITIES: Final = 30
_TOKEN_APPCONTAINER_SID: Final = 31
_TOKEN_IS_RESTRICTED: Final = 40
_SE_PRIVILEGE_ENABLED: Final = 0x00000002
_PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: Final = 0x00020009
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST: Final = 0x00020002
_EXTENDED_STARTUPINFO_PRESENT: Final = 0x00080000
_CREATE_SUSPENDED: Final = 0x00000004
_CREATE_NO_WINDOW: Final = 0x08000000
_CREATE_UNICODE_ENVIRONMENT: Final = 0x00000400
_HANDLE_FLAG_INHERIT: Final = 0x00000001
_SECURITY_MANDATORY_LOW_RID: Final = 0x00001000

_JOB_OBJECT_LIMIT_PROCESS_TIME: Final = 0x00000002
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS: Final = 0x00000008
_JOB_OBJECT_LIMIT_PROCESS_MEMORY: Final = 0x00000100
_JOB_OBJECT_LIMIT_JOB_MEMORY: Final = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Final = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: Final = 9
_JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION: Final = 1


class AppContainerError(RuntimeError):
    """The AppContainer profile or process could not be established."""


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


class _StartupInfoW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _StartupInfoExW(ctypes.Structure):
    _fields_ = [("StartupInfo", _StartupInfoW), ("lpAttributeList", ctypes.c_void_p)]


class _SecurityCapabilities(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", _PSID),
        ("Capabilities", ctypes.c_void_p),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _BasicAccountingInformation(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_int64),
        ("TotalKernelTime", ctypes.c_int64),
        ("ThisPeriodTotalUserTime", ctypes.c_int64),
        ("ThisPeriodTotalKernelTime", ctypes.c_int64),
        ("TotalPageFaultCount", ctypes.c_uint32),
        ("TotalProcesses", ctypes.c_uint32),
        ("ActiveProcesses", ctypes.c_uint32),
        ("TotalTerminatedProcesses", ctypes.c_uint32),
    ]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", _PSID), ("Attributes", wintypes.DWORD)]


class _TokenMandatoryLabel(ctypes.Structure):
    _fields_ = [("Label", _SidAndAttributes)]


class _Luid(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class _LuidAndAttributes(ctypes.Structure):
    _fields_ = [("Luid", _Luid), ("Attributes", wintypes.DWORD)]


class _TokenPrivileges(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", _LuidAndAttributes * 1),
    ]


class _TokenCapabilities(ctypes.Structure):
    _fields_ = [
        ("CapabilityCount", wintypes.DWORD),
        ("Capabilities", _SidAndAttributes * 1),
    ]


class _TokenAppContainerInformation(ctypes.Structure):
    _fields_ = [("TokenAppContainer", _PSID)]


def _win32() -> Any:
    if os.name != "nt":
        raise AppContainerError("AppContainer is only available on Windows")
    return ctypes


def _kernel32() -> Any:
    return _win32().WinDLL("kernel32", use_last_error=True)


def _advapi32() -> Any:
    return _win32().WinDLL("advapi32", use_last_error=True)


def _userenv() -> Any:
    return _win32().WinDLL("userenv", use_last_error=True)


def _last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    return int(getter()) if getter is not None else 0


def _system32_tool(name: str) -> str:
    """Resolve a privileged helper from the kernel's system directory, not the environment.

    `%SYSTEMROOT%` is caller-controlled; resolving `icacls.exe` from it would let a caller
    choose a program that runs with the supervisor's privileges.
    """
    buffer = ctypes.create_unicode_buffer(261)
    length = _kernel32().GetSystemDirectoryW(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        raise AppContainerError("the Windows system directory could not be resolved")
    candidate = Path(buffer.value) / name
    if not candidate.is_file():
        raise AppContainerError(f"the system tool {name!r} is not present in the system directory")
    return str(candidate)


def _check_bool(ok: Any, what: str) -> None:
    if not ok:
        error = _last_error()
        formatter = getattr(ctypes, "FormatError", None)
        detail = f" {formatter(error)}" if formatter is not None else ""
        raise AppContainerError(f"{what} failed: {error}{detail}")


def _open_osfhandle(handle: int, flags: int) -> int:
    opener = getattr(_msvcrt, "open_osfhandle", None)
    if opener is None:
        raise AppContainerError("msvcrt.open_osfhandle is unavailable")
    return int(opener(handle, flags))


def _check_hr(hr: int, what: str) -> None:
    if hr != 0:
        raise AppContainerError(f"{what} failed with HRESULT 0x{hr & 0xFFFFFFFF:08X}")


def _configure_advapi() -> None:
    api = _advapi32()
    api.FreeSid.argtypes = [_PSID]
    api.FreeSid.restype = _PSID
    api.ConvertSidToStringSidW.argtypes = [_PSID, ctypes.POINTER(wintypes.LPWSTR)]
    api.ConvertSidToStringSidW.restype = wintypes.BOOL
    api.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    api.OpenProcessToken.restype = wintypes.BOOL
    api.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    api.GetTokenInformation.restype = wintypes.BOOL
    api.GetSidSubAuthorityCount.argtypes = [_PSID]
    api.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    api.GetSidSubAuthority.argtypes = [_PSID, wintypes.DWORD]
    api.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    api.LookupPrivilegeNameW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(_Luid),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    api.LookupPrivilegeNameW.restype = wintypes.BOOL


def _configure_kernel32() -> None:
    api = _kernel32()
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    api.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    api.TerminateProcess.restype = wintypes.BOOL
    api.LocalFree.argtypes = [ctypes.c_void_p]
    api.LocalFree.restype = ctypes.c_void_p
    api.GetCurrentProcess.argtypes = []
    api.GetCurrentProcess.restype = wintypes.HANDLE
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.ResumeThread.argtypes = [wintypes.HANDLE]
    api.ResumeThread.restype = wintypes.DWORD
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.WaitForSingleObject.restype = wintypes.DWORD
    api.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    api.GetExitCodeProcess.restype = wintypes.BOOL
    api.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(_SecurityAttributes),
        wintypes.DWORD,
    ]
    api.CreatePipe.restype = wintypes.BOOL
    api.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    api.SetHandleInformation.restype = wintypes.BOOL
    api.InitializeProcThreadAttributeList.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    api.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    api.UpdateProcThreadAttribute.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    api.UpdateProcThreadAttribute.restype = wintypes.BOOL
    api.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    api.DeleteProcThreadAttributeList.restype = None
    api.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.POINTER(_ProcessInformation),
    ]
    api.CreateProcessW.restype = wintypes.BOOL
    api.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    api.GetSystemDirectoryW.restype = wintypes.UINT
    api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    api.CreateJobObjectW.restype = ctypes.c_void_p
    api.SetInformationJobObject.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    api.SetInformationJobObject.restype = wintypes.BOOL
    api.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    api.AssignProcessToJobObject.restype = wintypes.BOOL
    api.TerminateJobObject.argtypes = [ctypes.c_void_p, wintypes.UINT]
    api.TerminateJobObject.restype = wintypes.BOOL
    api.QueryInformationJobObject.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    api.QueryInformationJobObject.restype = wintypes.BOOL


if os.name == "nt":
    _configure_kernel32()
    _configure_advapi()


def _handle_value(handle: Any) -> int:
    value = handle.value if hasattr(handle, "value") else handle
    if value is None:
        raise AppContainerError("a required process handle is null")
    return int(value)


def _sid_to_string(sid: Any) -> str:
    if sid is None:
        raise AppContainerError("a SID is null")
    if isinstance(sid, int):
        sid = ctypes.c_void_p(sid)
    text = wintypes.LPWSTR()
    _check_bool(
        _advapi32().ConvertSidToStringSidW(sid, ctypes.byref(text)), "ConvertSidToStringSidW"
    )
    try:
        return str(text.value)
    finally:
        _kernel32().LocalFree(text)


def current_user_sid() -> str:
    """Return the interactive user SID, used only to retain supervisor cleanup rights."""
    token = wintypes.HANDLE()
    _check_bool(
        _advapi32().OpenProcessToken(ctypes.c_void_p(-1), _TOKEN_QUERY, ctypes.byref(token)),
        "OpenProcessToken(current)",
    )
    try:
        size = wintypes.DWORD(0)
        _advapi32().GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        _check_bool(
            _advapi32().GetTokenInformation(
                token, _TOKEN_USER, buffer, size.value, ctypes.byref(size)
            ),
            "GetTokenInformation(TokenUser)",
        )
        user = ctypes.cast(buffer, ctypes.POINTER(_SidAndAttributes)).contents
        return _sid_to_string(user.Sid)
    finally:
        _kernel32().CloseHandle(token)


class PrincipalError(RuntimeError):
    """The supervisor's own Windows token is not the accepted production principal."""


def _current_process_token() -> Any:
    token = wintypes.HANDLE()
    _check_bool(
        _advapi32().OpenProcessToken(ctypes.c_void_p(-1), _TOKEN_QUERY, ctypes.byref(token)),
        "OpenProcessToken(current supervisor)",
    )
    return token


def supervisor_principal() -> dict[str, object]:
    """Measure the supervisor's own token: elevation, integrity, capabilities, privileges.

    These are the facts that decide whether the qualified non-elevated production principal
    is in force. They are measured from the supervisor's own token, not inferred from the
    environment, and they are recorded in the protected consumption record.
    """
    if os.name != "nt":
        raise AppContainerError("the supervisor principal is a Windows-only observation")
    token = _current_process_token()
    try:
        elevation = wintypes.DWORD(0)
        size = wintypes.DWORD(0)
        _check_bool(
            _advapi32().GetTokenInformation(
                token,
                _TOKEN_ELEVATION,
                ctypes.byref(elevation),
                ctypes.sizeof(elevation),
                ctypes.byref(size),
            ),
            "GetTokenInformation(TokenElevation)",
        )
        elevation_type = wintypes.DWORD(0)
        _check_bool(
            _advapi32().GetTokenInformation(
                token,
                _TOKEN_ELEVATION_TYPE,
                ctypes.byref(elevation_type),
                ctypes.sizeof(elevation_type),
                ctypes.byref(size),
            ),
            "GetTokenInformation(TokenElevationType)",
        )
        return {
            "elevated": bool(elevation.value),
            "elevation_type": int(elevation_type.value),
            "integrity_level": _token_integrity_level(token),
            "capability_count": len(_token_capabilities(token)),
            "privileges": _token_privileges(token),
        }
    finally:
        _kernel32().CloseHandle(token)


def require_non_elevated_supervisor(*, accept_elevated_residual: bool = False) -> dict[str, object]:
    """Return the supervisor principal, or refuse an elevated one.

    The owner adopted ``require_non_elevated_windows`` for production: the hosted CI token is
    elevated and its mechanism facts are evidence, not an accepted production principal. An
    operator can only proceed past this gate by passing
    ``accept_elevated_residual=True`` *and* recording that residual acceptance in the owner
    record, which is an explicit decision rather than a code path.
    """
    principal = supervisor_principal()
    if bool(principal["elevated"]) and not accept_elevated_residual:
        raise PrincipalError(
            "the supervisor token is elevated; the accepted production principal is "
            "non-elevated. Re-qualify an elevated principal or run the supervisor under a "
            "non-elevated account"
        )
    return principal


class AppContainerProfile:
    """One named AppContainer profile and its private filesystem folder."""

    __slots__ = ("name", "sid", "sid_string", "folder")

    def __init__(self, name: str, sid: Any, sid_string: str, folder: Path) -> None:
        self.name = name
        self.sid = sid
        self.sid_string = sid_string
        self.folder = folder

    @classmethod
    def create(cls, name: str) -> AppContainerProfile:
        if os.name != "nt":
            raise AppContainerError("AppContainer profiles are only available on Windows")
        api = _userenv()
        api.CreateAppContainerProfile.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            _PSID,
            wintypes.DWORD,
            ctypes.POINTER(_PSID),
        ]
        api.CreateAppContainerProfile.restype = _HRESULT
        api.GetAppContainerFolderPath.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        api.GetAppContainerFolderPath.restype = _HRESULT
        api.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
        api.DeleteAppContainerProfile.restype = _HRESULT
        sid = _PSID()
        _check_hr(
            int(
                api.CreateAppContainerProfile(
                    name, name, "DynamisBench protected execution", None, 0, ctypes.byref(sid)
                )
            ),
            "CreateAppContainerProfile",
        )
        try:
            sid_string = _sid_to_string(sid)
            folder_pointer = ctypes.c_void_p()
            _check_hr(
                int(api.GetAppContainerFolderPath(sid_string, ctypes.byref(folder_pointer))),
                "GetAppContainerFolderPath",
            )
            try:
                folder = Path(ctypes.wstring_at(folder_pointer))
            finally:
                _kernel32().LocalFree(folder_pointer)
            folder.mkdir(parents=True, exist_ok=True)
            return cls(name, sid, sid_string, folder)
        except BaseException:
            api.DeleteAppContainerProfile(name)
            _advapi32().FreeSid(sid)
            raise

    def delete(self) -> None:
        api = _userenv()
        api.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
        api.DeleteAppContainerProfile.restype = _HRESULT
        api.DeleteAppContainerProfile(self.name)
        if self.sid is not None:
            _advapi32().FreeSid(self.sid)
            self.sid = None


def grant_tree(
    path: Path,
    sid_string: str,
    access: str,
    *,
    user_access: str = "(OI)(CI)(F)",
) -> None:
    """Replace one tree's DACL with the package SID, the user and the system principals.

    ``access`` is the worker's rights expression (for example ``(OI)(CI)(RX)``).
    ``user_access`` is the interactive supervisor user's expression. Runtime and input
    trees use ``(OI)(CI)(RX,DE,DC)``: the worker token cannot write their contents, and the
    user can delete them for cleanup. The user owns the tree and can still change its DACL,
    so this is not a same-user immutability claim; the pre/post closures are the detection.
    The package SID never receives write access to a read-only view. SYSTEM retains full
    control; the Administrators group is deliberately not granted, so an elevated runner's
    group membership is not a worker write path. The scratch tree gives the user full
    control because the supervisor must read the receipt.
    """
    if not path.is_dir():
        raise AppContainerError("an AppContainer grant target is not a directory")
    user = current_user_sid()
    command = [
        _system32_tool("icacls.exe"),
        str(path),
        "/inheritance:r",
        # An AppContainer profile's AC folder carries a package-SID "(CR)(F)" ACE that
        # /grant:r does not replace. Remove every existing grant ACE for the package SID
        # first, then add exactly the requested rights.
        "/remove:g",
        f"*{sid_string}",
        "/grant:r",
        f"*{sid_string}:{access}",
        "/grant:r",
        f"*{user}:{user_access}",
        "/grant:r",
        "*S-1-5-18:(OI)(CI)(F)",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    if completed.returncode != 0:
        raise AppContainerError(
            f"icacls could not grant the protected DACL at {path.name!r}: "
            f"{completed.stderr.strip()[:200]}"
        )


def restore_user_control(path: Path) -> None:
    """Re-grant the interactive user full control after an attempt has ended.

    The runtime snapshot is session-scoped. During an attempt the user has only
    ``RX,DE,DC`` so the worker's measured bytes cannot be rewritten under it. After the
    attempt, the next attempt's pre-launch closure re-measurement is the detection point,
    and the user needs write access to stage a deliberately substituted runtime in a test
    or a controlled repair. This helper changes only the user's ACE; the package-SID ACE
    and the system principals remain.
    """
    if not path.is_dir():
        raise AppContainerError("an AppContainer restore target is not a directory")
    user = current_user_sid()
    completed = subprocess.run(
        [
            _system32_tool("icacls.exe"),
            str(path),
            "/grant:r",
            f"*{user}:(OI)(CI)(F)",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        raise AppContainerError(
            f"icacls could not restore user control at {path.name!r}: "
            f"{completed.stderr.strip()[:200]}"
        )


def is_available() -> bool:
    """Whether this host can create an AppContainer profile, without creating one."""
    if os.name != "nt":
        return False
    try:
        api = _userenv()
        api.DeriveAppContainerSidFromAppContainerName.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(_PSID),
        ]
        api.DeriveAppContainerSidFromAppContainerName.restype = _HRESULT
        sid = _PSID()
        hr = int(
            api.DeriveAppContainerSidFromAppContainerName(
                "DynamisBench.Protected.Availability", ctypes.byref(sid)
            )
        )
        if sid:
            _advapi32().FreeSid(sid)
        return hr == 0
    except Exception:  # noqa: BLE001 - availability is an observation, not an assertion
        return False


class _AttemptJob:
    """A bounded Windows Job Object owned by the supervisor."""

    __slots__ = ("handle",)

    def __init__(self, *, memory_bytes: int, cpu_seconds: int, max_processes: int) -> None:
        api = _kernel32()
        handle = api.CreateJobObjectW(None, None)
        if not handle:
            raise AppContainerError(f"CreateJobObjectW failed: {_last_error()}")
        self.handle = int(handle)
        limits = _ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = (
            _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | _JOB_OBJECT_LIMIT_PROCESS_TIME
            | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | _JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | _JOB_OBJECT_LIMIT_JOB_MEMORY
        )
        limits.BasicLimitInformation.PerProcessUserTimeLimit = cpu_seconds * 10_000_000
        limits.BasicLimitInformation.ActiveProcessLimit = max_processes
        limits.ProcessMemoryLimit = memory_bytes
        limits.JobMemoryLimit = memory_bytes
        if not api.SetInformationJobObject(
            ctypes.c_void_p(self.handle),
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            error = _last_error()
            self.close()
            raise AppContainerError(f"SetInformationJobObject failed: {error}")

    def assign(self, process_handle: int) -> None:
        if not _kernel32().AssignProcessToJobObject(
            ctypes.c_void_p(self.handle), ctypes.c_void_p(process_handle)
        ):
            raise AppContainerError(f"AssignProcessToJobObject failed: {_last_error()}")

    def accounting(self) -> dict[str, int]:
        value = _BasicAccountingInformation()
        if not _kernel32().QueryInformationJobObject(
            ctypes.c_void_p(self.handle),
            _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
            ctypes.byref(value),
            ctypes.sizeof(value),
            None,
        ):
            raise AppContainerError(f"QueryInformationJobObject failed: {_last_error()}")
        return {
            "active_processes": int(value.ActiveProcesses),
            "total_processes": int(value.TotalProcesses),
            "total_user_time_100ns": int(value.TotalUserTime),
            "total_kernel_time_100ns": int(value.TotalKernelTime),
        }

    def terminate(self) -> None:
        if self.handle:
            _kernel32().TerminateJobObject(ctypes.c_void_p(self.handle), 1)

    def close(self) -> None:
        handle, self.handle = self.handle, 0
        if handle:
            _kernel32().CloseHandle(ctypes.c_void_p(handle))


def _token_information(token: Any, info_class: int, what: str) -> Any:
    """Return a buffer holding one variable-length token information record."""
    size = wintypes.DWORD(0)
    # The size probe returns FALSE with ERROR_INSUFFICIENT_BUFFER; only the size matters.
    _advapi32().GetTokenInformation(token, info_class, None, 0, ctypes.byref(size))
    if size.value == 0:
        raise AppContainerError(f"{what} returned no token information")
    buffer = ctypes.create_string_buffer(size.value)
    _check_bool(
        _advapi32().GetTokenInformation(token, info_class, buffer, size.value, ctypes.byref(size)),
        what,
    )
    return buffer


def _token_capabilities(token: Any) -> list[str]:
    buffer = _token_information(
        token, _TOKEN_CAPABILITIES, "GetTokenInformation(TokenCapabilities)"
    )
    count = int(ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value)
    if count == 0:
        return []
    offset = _TokenCapabilities.Capabilities.offset
    array_type = _SidAndAttributes * count
    values = ctypes.cast(ctypes.addressof(buffer) + offset, ctypes.POINTER(array_type)).contents
    return [_sid_to_string(item.Sid) for item in values]


def _token_privileges(token: Any) -> list[dict[str, object]]:
    buffer = _token_information(token, _TOKEN_PRIVILEGES, "GetTokenInformation(TokenPrivileges)")
    count = int(ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value)
    if count == 0:
        return []
    offset = _TokenPrivileges.Privileges.offset
    array_type = _LuidAndAttributes * count
    values = ctypes.cast(ctypes.addressof(buffer) + offset, ctypes.POINTER(array_type)).contents
    privileges: list[dict[str, object]] = []
    for item in values:
        name = ctypes.create_unicode_buffer(256)
        length = wintypes.DWORD(len(name))
        _check_bool(
            _advapi32().LookupPrivilegeNameW(
                None, ctypes.byref(item.Luid), name, ctypes.byref(length)
            ),
            "LookupPrivilegeNameW",
        )
        privileges.append(
            {
                "name": name.value,
                "enabled": bool(int(item.Attributes) & _SE_PRIVILEGE_ENABLED),
            }
        )
    return privileges


def _token_integrity_level(token: Any) -> str:
    buffer = _token_information(
        token, _TOKEN_INTEGRITY_LEVEL, "GetTokenInformation(TokenIntegrityLevel)"
    )
    label = ctypes.cast(buffer, ctypes.POINTER(_TokenMandatoryLabel)).contents
    if not label.Label.Sid:
        return ""
    return _sid_to_string(label.Label.Sid)


def _token_observation(pid: int, expected_sid: str) -> dict[str, object]:
    """Read the worker token from outside; this is supervisor evidence, not self-report."""
    api = _kernel32()
    advapi = _advapi32()
    process = api.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not process:
        raise AppContainerError(f"OpenProcess failed: {_last_error()}")
    token = wintypes.HANDLE()
    try:
        _check_bool(
            advapi.OpenProcessToken(process, _TOKEN_QUERY, ctypes.byref(token)),
            "OpenProcessToken(worker)",
        )
        is_container = wintypes.DWORD(0)
        size = wintypes.DWORD(0)
        _check_bool(
            advapi.GetTokenInformation(
                token,
                _TOKEN_IS_APPCONTAINER,
                ctypes.byref(is_container),
                ctypes.sizeof(is_container),
                ctypes.byref(size),
            ),
            "GetTokenInformation(TokenIsAppContainer)",
        )
        container_sid = ""
        container_info = _TokenAppContainerInformation()
        if is_container.value:
            size = wintypes.DWORD(0)
            advapi.GetTokenInformation(
                token,
                _TOKEN_APPCONTAINER_SID,
                None,
                0,
                ctypes.byref(size),
            )
            if size.value:
                buffer = ctypes.create_string_buffer(size.value)
                _check_bool(
                    advapi.GetTokenInformation(
                        token,
                        _TOKEN_APPCONTAINER_SID,
                        buffer,
                        size.value,
                        ctypes.byref(size),
                    ),
                    "GetTokenInformation(TokenAppContainerSid)",
                )
                container_info = ctypes.cast(
                    buffer, ctypes.POINTER(_TokenAppContainerInformation)
                ).contents
                if container_info.TokenAppContainer:
                    container_sid = _sid_to_string(container_info.TokenAppContainer)
        elevation = wintypes.DWORD(0)
        _check_bool(
            advapi.GetTokenInformation(
                token,
                _TOKEN_ELEVATION,
                ctypes.byref(elevation),
                ctypes.sizeof(elevation),
                ctypes.byref(size),
            ),
            "GetTokenInformation(TokenElevation)",
        )
        elevation_type = wintypes.DWORD(0)
        _check_bool(
            advapi.GetTokenInformation(
                token,
                _TOKEN_ELEVATION_TYPE,
                ctypes.byref(elevation_type),
                ctypes.sizeof(elevation_type),
                ctypes.byref(size),
            ),
            "GetTokenInformation(TokenElevationType)",
        )
        has_restrictions = wintypes.DWORD(0)
        _check_bool(
            advapi.GetTokenInformation(
                token,
                _TOKEN_HAS_RESTRICTIONS,
                ctypes.byref(has_restrictions),
                ctypes.sizeof(has_restrictions),
                ctypes.byref(size),
            ),
            "GetTokenInformation(TokenHasRestrictions)",
        )
        restricted = wintypes.DWORD(0)
        _check_bool(
            advapi.GetTokenInformation(
                token,
                _TOKEN_IS_RESTRICTED,
                ctypes.byref(restricted),
                ctypes.sizeof(restricted),
                ctypes.byref(size),
            ),
            "GetTokenInformation(TokenIsRestricted)",
        )
        capabilities = _token_capabilities(token)
        privileges = _token_privileges(token)
        return {
            "is_appcontainer": bool(is_container.value),
            "appcontainer_sid": container_sid,
            "expected_sid": expected_sid,
            "sid_matches": container_sid == expected_sid,
            "capability_count": len(capabilities),
            "capabilities": capabilities,
            "privilege_count": len(privileges),
            "privileges": privileges,
            "integrity_level": _token_integrity_level(token),
            "elevated": bool(elevation.value),
            "elevation_type": int(elevation_type.value),
            "has_restrictions": bool(has_restrictions.value),
            "restricted_token": bool(restricted.value),
        }
    finally:
        if token:
            api.CloseHandle(token)
        api.CloseHandle(process)


def _environment_block(environment: Mapping[str, str]) -> ctypes.Array[ctypes.c_wchar]:
    entries = [f"{name}={value}" for name, value in sorted(environment.items())]
    return ctypes.create_unicode_buffer("\0".join(entries) + "\0\0")


class AppContainerProcess:
    """One suspended AppContainer worker, owned by a bounded Job Object."""

    __slots__ = (
        "_closed",
        "_job",
        "_process",
        "_thread",
        "pid",
        "returncode",
        "stderr",
        "stdin",
        "stdout",
        "token_observation",
    )

    def __init__(self) -> None:
        raise AppContainerError("AppContainerProcess is created only by launch()")

    @classmethod
    def launch(
        cls,
        *,
        profile: AppContainerProfile,
        application: Path,
        arguments: tuple[str, ...],
        working_directory: Path,
        environment: Mapping[str, str] | None,
        memory_bytes: int,
        cpu_seconds: int,
        max_processes: int,
    ) -> AppContainerProcess:
        api = _kernel32()
        job = _AttemptJob(
            memory_bytes=memory_bytes, cpu_seconds=cpu_seconds, max_processes=max_processes
        )
        process_handles: list[Any] = []
        thread_handle: Any = None
        attribute_buffer: Any = None
        attribute_initialized = False
        pipes: list[Any] = []
        wrapped_handles: set[int] = set()
        process_info = _ProcessInformation()
        try:
            security = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, True)
            stdin_read, stdin_write = wintypes.HANDLE(), wintypes.HANDLE()
            stdout_read, stdout_write = wintypes.HANDLE(), wintypes.HANDLE()
            stderr_read, stderr_write = wintypes.HANDLE(), wintypes.HANDLE()
            for read_handle, write_handle in (
                (stdin_read, stdin_write),
                (stdout_read, stdout_write),
                (stderr_read, stderr_write),
            ):
                _check_bool(
                    api.CreatePipe(
                        ctypes.byref(read_handle),
                        ctypes.byref(write_handle),
                        ctypes.byref(security),
                        0,
                    ),
                    "CreatePipe",
                )
                pipes.append((read_handle, write_handle))
            for parent in (stdin_write, stdout_read, stderr_read):
                _check_bool(
                    api.SetHandleInformation(parent, _HANDLE_FLAG_INHERIT, 0),
                    "SetHandleInformation",
                )

            size = ctypes.c_size_t(0)
            api.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
            attribute_buffer = ctypes.create_string_buffer(size.value)
            attribute_list = ctypes.cast(attribute_buffer, ctypes.c_void_p)
            _check_bool(
                api.InitializeProcThreadAttributeList(attribute_list, 2, 0, ctypes.byref(size)),
                "InitializeProcThreadAttributeList",
            )
            attribute_initialized = True
            capabilities = _SecurityCapabilities(profile.sid, None, 0, 0)
            _check_bool(
                api.UpdateProcThreadAttribute(
                    attribute_list,
                    0,
                    _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    ctypes.byref(capabilities),
                    ctypes.sizeof(capabilities),
                    None,
                    None,
                ),
                "UpdateProcThreadAttribute(SECURITY_CAPABILITIES)",
            )
            # Do not inherit every inheritable handle the supervisor happens to hold. The
            # child receives exactly its three stdio pipe ends; a socket, event or file the
            # supervisor owns is not a worker transport by accident.
            stdio_handles = (stdin_read, stdout_write, stderr_write)
            handle_array = (wintypes.HANDLE * len(stdio_handles))(*stdio_handles)
            _check_bool(
                api.UpdateProcThreadAttribute(
                    attribute_list,
                    0,
                    _PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    ctypes.byref(handle_array),
                    ctypes.sizeof(handle_array),
                    None,
                    None,
                ),
                "UpdateProcThreadAttribute(HANDLE_LIST)",
            )
            startup = _StartupInfoExW()
            startup.StartupInfo.cb = ctypes.sizeof(_StartupInfoExW)
            startup.StartupInfo.dwFlags = 0x00000100 | 0x00000008  # USESTDHANDLES | USESHOWWINDOW
            startup.StartupInfo.wShowWindow = 0
            startup.StartupInfo.hStdInput = stdin_read
            startup.StartupInfo.hStdOutput = stdout_write
            startup.StartupInfo.hStdError = stderr_write
            startup.lpAttributeList = attribute_list

            command_line = ctypes.create_unicode_buffer(
                subprocess.list2cmdline([str(application), *arguments])
            )
            if environment is None:
                environment_pointer = None
                environment_flags = 0
            else:
                environment_block = _environment_block(environment)
                environment_pointer = ctypes.cast(environment_block, ctypes.c_void_p)
                environment_flags = _CREATE_UNICODE_ENVIRONMENT
            _check_bool(
                api.CreateProcessW(
                    str(application),
                    command_line,
                    None,
                    None,
                    True,
                    _EXTENDED_STARTUPINFO_PRESENT
                    | _CREATE_SUSPENDED
                    | _CREATE_NO_WINDOW
                    | environment_flags,
                    environment_pointer,
                    str(working_directory),
                    ctypes.byref(startup),
                    ctypes.byref(process_info),
                ),
                "CreateProcessW(AppContainer)",
            )
            process_handles.append(process_info.hProcess)
            thread_handle = process_info.hThread
            # Child ends are no longer needed in the parent.
            api.CloseHandle(stdin_read)
            api.CloseHandle(stdout_write)
            api.CloseHandle(stderr_write)

            job.assign(_handle_value(process_info.hProcess))
            observation = _token_observation(int(process_info.dwProcessId), profile.sid_string)
            resumed = api.ResumeThread(process_info.hThread)
            if int(resumed) == 0xFFFFFFFF:
                raise AppContainerError(
                    f"ResumeThread failed for the suspended AppContainer worker: {_last_error()}"
                )

            instance = object.__new__(cls)
            instance._job = job
            instance._process = _handle_value(process_info.hProcess)
            instance._thread = _handle_value(process_info.hThread)
            instance._closed = False
            instance.pid = int(process_info.dwProcessId)
            instance.returncode = None
            instance.token_observation = observation
            instance.stdin = os.fdopen(
                _open_osfhandle(_handle_value(stdin_write), os.O_WRONLY),
                "wb",
                buffering=0,
            )
            wrapped_handles.add(_handle_value(stdin_write))
            instance.stdout = os.fdopen(
                _open_osfhandle(_handle_value(stdout_read), os.O_RDONLY),
                "rb",
                buffering=0,
            )
            wrapped_handles.add(_handle_value(stdout_read))
            instance.stderr = os.fdopen(
                _open_osfhandle(_handle_value(stderr_read), os.O_RDONLY),
                "rb",
                buffering=0,
            )
            wrapped_handles.add(_handle_value(stderr_read))
            return instance
        except BaseException:
            if process_info.hProcess:
                api.TerminateProcess(process_info.hProcess, 1)
            for handle in process_handles:
                api.CloseHandle(handle)
            if thread_handle:
                api.CloseHandle(thread_handle)
            for read_handle, write_handle in pipes:
                for handle in (read_handle, write_handle):
                    if _handle_value(handle) not in wrapped_handles:
                        api.CloseHandle(handle)
            job.terminate()
            job.close()
            raise
        finally:
            if attribute_initialized and attribute_buffer is not None:
                api.DeleteProcThreadAttributeList(ctypes.cast(attribute_buffer, ctypes.c_void_p))

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        code = wintypes.DWORD(0)
        if not _kernel32().GetExitCodeProcess(ctypes.c_void_p(self._process), ctypes.byref(code)):
            raise AppContainerError(f"GetExitCodeProcess failed: {_last_error()}")
        if code.value == _STILL_ACTIVE:
            return None
        self.returncode = int(code.value)
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is not None:
            return self.returncode
        milliseconds = 0xFFFFFFFF if timeout is None else max(0, int(timeout * 1000))
        result = _kernel32().WaitForSingleObject(ctypes.c_void_p(self._process), milliseconds)
        if result == _WAIT_TIMEOUT:
            self.poll()
            if self.returncode is None:
                raise TimeoutError("the AppContainer worker is still running")
            return self.returncode
        if int(result) != _WAIT_OBJECT_0:
            raise AppContainerError(f"WaitForSingleObject failed: {_last_error()}")
        code = wintypes.DWORD(0)
        _check_bool(
            _kernel32().GetExitCodeProcess(ctypes.c_void_p(self._process), ctypes.byref(code)),
            "GetExitCodeProcess",
        )
        self.returncode = int(code.value)
        return self.returncode

    def kill(self) -> None:
        self._job.terminate()

    def job_accounting(self) -> dict[str, int]:
        return self._job.accounting()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for stream in (self.stdin, self.stdout, self.stderr):
            try:
                stream.close()
            except OSError:
                pass
        self._job.terminate()
        self._job.close()
        _kernel32().CloseHandle(ctypes.c_void_p(self._process))
        _kernel32().CloseHandle(ctypes.c_void_p(self._thread))
