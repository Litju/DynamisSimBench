"""NTFS handle operations for the offline worker-input verifier."""

from __future__ import annotations

import ctypes
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final, cast

from dynamisbench.materialization import MaterializationError, MaterializationRefusalCode

# All candidate objects are opened relative to a held directory, without any
# Win32 path conversion or traversal through a reparse point.
_FILE_ATTRIBUTE_DIRECTORY: Final = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x400
_FILE_READ_DATA: Final = 0x1
_FILE_READ_ATTRIBUTES: Final = 0x80
_SYNCHRONIZE: Final = 0x100000
_READ_ACCESS: Final = _FILE_READ_DATA | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
_FILE_SHARE_READ: Final = 0x1
_OBJ_DONT_REPARSE: Final = 0x1000
_FILE_OPEN: Final = 0x1
_FILE_DIRECTORY_FILE: Final = 0x1
_FILE_NON_DIRECTORY_FILE: Final = 0x40
_FILE_SYNCHRONOUS_IO_NONALERT: Final = 0x20
_FILE_OPEN_REPARSE_POINT: Final = 0x200000
_FILE_FLAG_BACKUP_SEMANTICS: Final = 0x02000000
_OPEN_EXISTING: Final = 3
_FILE_TYPE_DISK: Final = 1
_DRIVE_FIXED: Final = 3
_FILE_STREAM_INFO: Final = 7
_FILE_ID_BOTH_DIRECTORY_INFO: Final = 10
_FILE_ID_BOTH_DIRECTORY_RESTART_INFO: Final = 11
_ERROR_NO_MORE_FILES: Final = 18
_ERROR_HANDLE_EOF: Final = 38
_INVALID_HANDLE: Final = ctypes.c_void_p(-1).value
_DWORD = ctypes.c_uint32
_HANDLE = ctypes.c_void_p


class _UnicodeString(ctypes.Structure):
    _fields_ = (
        ("length", ctypes.c_uint16),
        ("maximum_length", ctypes.c_uint16),
        ("buffer", ctypes.c_wchar_p),
    )


class _ObjectAttributes(ctypes.Structure):
    _fields_ = (
        ("length", _DWORD),
        ("root", _HANDLE),
        ("name", ctypes.POINTER(_UnicodeString)),
        ("attributes", _DWORD),
        ("security_descriptor", _HANDLE),
        ("security_qos", _HANDLE),
    )


class _IoStatus(ctypes.Structure):
    _fields_ = (("status", _HANDLE), ("information", ctypes.c_size_t))


class _FileInfo(ctypes.Structure):
    # Win32 FILETIME is two DWORDs aligned to four bytes, including in this struct.
    _fields_ = (
        ("attributes", _DWORD),
        ("times", _DWORD * 6),
        ("volume", _DWORD),
        ("size_high", _DWORD),
        ("size_low", _DWORD),
        ("links", _DWORD),
        ("index_high", _DWORD),
        ("index_low", _DWORD),
    )


def _api(dll: Any, name: str, result: Any, *arguments: Any) -> Any:
    function = getattr(dll, name)
    function.restype = result
    function.argtypes = arguments
    return function


_c = cast(Any, ctypes)
_kernel = _c.WinDLL("kernel32", use_last_error=True)
_ntdll = _c.WinDLL("ntdll")
_create_file = _api(
    _kernel,
    "CreateFileW",
    _HANDLE,
    ctypes.c_wchar_p,
    _DWORD,
    _DWORD,
    _HANDLE,
    _DWORD,
    _DWORD,
    _HANDLE,
)
_create_relative = _api(
    _ntdll,
    "NtCreateFile",
    ctypes.c_int32,
    ctypes.POINTER(_HANDLE),
    _DWORD,
    ctypes.POINTER(_ObjectAttributes),
    ctypes.POINTER(_IoStatus),
    _HANDLE,
    _DWORD,
    _DWORD,
    _DWORD,
    _DWORD,
    _HANDLE,
    _DWORD,
)
_status_error = _api(_ntdll, "RtlNtStatusToDosError", _DWORD, ctypes.c_int32)
_close_handle = _api(_kernel, "CloseHandle", ctypes.c_int, _HANDLE)
_drive_type = _api(_kernel, "GetDriveTypeW", _DWORD, ctypes.c_wchar_p)
_disk_type = _api(_kernel, "GetFileType", _DWORD, _HANDLE)
_get_info = _api(
    _kernel, "GetFileInformationByHandle", ctypes.c_int, _HANDLE, ctypes.POINTER(_FileInfo)
)
_query = _api(
    _kernel, "GetFileInformationByHandleEx", ctypes.c_int, _HANDLE, ctypes.c_int, _HANDLE, _DWORD
)
_get_volume = _api(
    _kernel,
    "GetVolumeInformationByHandleW",
    ctypes.c_int,
    _HANDLE,
    ctypes.c_wchar_p,
    _DWORD,
    _HANDLE,
    _HANDLE,
    _HANDLE,
    ctypes.c_wchar_p,
    _DWORD,
)
_read_file = _api(
    _kernel, "ReadFile", ctypes.c_int, _HANDLE, _HANDLE, _DWORD, ctypes.POINTER(_DWORD), _HANDLE
)


def close(handle: int) -> None:
    if not _close_handle(handle):
        raise _c.WinError(_c.get_last_error())


def _info(handle: int) -> _FileInfo:
    data = _FileInfo()
    if _disk_type(handle) != _FILE_TYPE_DISK or not _get_info(handle, ctypes.byref(data)):
        raise OSError("file identity is unavailable")
    return data


def _relative(parent: int, name: str, *, directory: bool, share: int) -> int:
    encoded_length = len(name.encode("utf-16-le"))
    string = _UnicodeString(encoded_length, encoded_length + 2, name)
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes),
        parent,
        ctypes.pointer(string),
        _OBJ_DONT_REPARSE,
        None,
        None,
    )
    io_status = _IoStatus()
    out = _HANDLE()
    type_flag = _FILE_DIRECTORY_FILE if directory else _FILE_NON_DIRECTORY_FILE
    status = _create_relative(
        ctypes.byref(out),
        _READ_ACCESS,
        ctypes.byref(attributes),
        ctypes.byref(io_status),
        None,
        0,
        share,
        _FILE_OPEN,
        _FILE_SYNCHRONOUS_IO_NONALERT | _FILE_OPEN_REPARSE_POINT | type_flag,
        None,
        0,
    )
    if status < 0 or out.value is None:
        raise _c.WinError(_status_error(status))
    return out.value


def _require_plain(info: _FileInfo, *, directory: bool) -> None:
    if (
        info.attributes & _FILE_ATTRIBUTE_REPARSE_POINT
        or bool(info.attributes & _FILE_ATTRIBUTE_DIRECTORY) != directory
        or (not directory and info.links != 1)
    ):
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_LINK_REFUSED,
            "the input view contains a link or non-regular object",
        )


def open_root(path: Path) -> int:
    if len(path.drive) != 2 or not path.drive[0].isascii() or not path.drive[0].isalpha():
        raise OSError("input view must use a local drive root")
    if _drive_type(path.anchor) != _DRIVE_FIXED:
        raise OSError("input view requires a fixed local drive")
    share_all = 7
    handle = _create_file(
        path.anchor,
        _READ_ACCESS,
        share_all,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    if handle in (None, _INVALID_HANDLE):
        raise _c.WinError(_c.get_last_error())
    try:
        fs = ctypes.create_unicode_buffer(16)
        if not _get_volume(handle, None, 0, None, None, None, fs, len(fs)) or fs.value != "NTFS":
            raise OSError("input view requires NTFS")
        volume = _info(handle).volume
        for component in path.parts[1:]:
            child = _relative(handle, component, directory=True, share=share_all)
            close(handle)
            handle = child
            info = _info(handle)
            _require_plain(info, directory=True)
            if info.volume != volume:
                raise OSError("input view root crossed a volume")
        _check_streams(handle, directory=True)
        return handle
    except BaseException:
        close(handle)
        raise


def _check_streams(handle: int, *, directory: bool) -> None:
    buffer = ctypes.create_string_buffer(4096)
    if not _query(handle, _FILE_STREAM_INFO, buffer, ctypes.sizeof(buffer)):
        if directory and _c.get_last_error() == _ERROR_HANDLE_EOF:
            return
        raise _c.WinError(_c.get_last_error())
    # FILE_STREAM_INFO: next offset, UTF-16 byte count, size, allocation, name.
    next_offset, name_bytes = struct.unpack_from("<II", buffer)
    if (
        directory
        or next_offset != 0
        or name_bytes != 14
        or buffer.raw[24:38].decode("utf-16-le") != "::$DATA"
    ):
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_PATH_REFUSED,
            "the input view contains an alternate data stream",
        )


def open_child(parent: int, name: str, *, directory: bool, inode: int) -> int:
    handle = _relative(parent, name, directory=directory, share=_FILE_SHARE_READ)
    try:
        info = _info(handle)
        _require_plain(info, directory=directory)
        if (info.index_high << 32 | info.index_low) != inode or info.volume != _info(parent).volume:
            raise MaterializationError(
                MaterializationRefusalCode.INPUT_PATH_REFUSED,
                "the input view entry changed identity or crossed a volume",
            )
        _check_streams(handle, directory=directory)
        return handle
    except BaseException:
        close(handle)
        raise


def entries(directory: int) -> Iterator[tuple[str, int]]:
    buffer = ctypes.create_string_buffer(4096)
    kind = _FILE_ID_BOTH_DIRECTORY_RESTART_INFO
    while _query(directory, kind, buffer, ctypes.sizeof(buffer)):
        kind = _FILE_ID_BOTH_DIRECTORY_INFO
        raw = buffer.raw
        offset = 0
        while True:
            next_offset = struct.unpack_from("<I", raw, offset)[0]
            name_bytes = struct.unpack_from("<I", raw, offset + 60)[0]
            end = offset + 104 + name_bytes
            if name_bytes > 510 or name_bytes % 2 or end > len(raw):
                raise OSError("invalid directory entry name")
            name = raw[offset + 104 : end].decode("utf-16-le", errors="surrogatepass")
            inode = struct.unpack_from("<Q", raw, offset + 96)[0]
            if name not in (".", ".."):
                yield name, inode
            if not next_offset:
                break
            if offset + next_offset < end or offset + next_offset + 104 > len(raw):
                raise OSError("invalid directory entry offset")
            offset += next_offset
    if _c.get_last_error() != _ERROR_NO_MORE_FILES:
        raise _c.WinError(_c.get_last_error())


def read(handle: int, max_bytes: int) -> bytes:
    info = _info(handle)
    size = info.size_high << 32 | info.size_low
    if size > max_bytes:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_LIMIT_EXCEEDED,
            "an input view file exceeds its read bound",
        )
    buffer = ctypes.create_string_buffer(size + 1)
    read_count = _DWORD()
    if not _read_file(handle, buffer, size + 1, ctypes.byref(read_count), None):
        raise _c.WinError(_c.get_last_error())
    if read_count.value != size:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_SOURCE_CHANGED,
            "the pinned input file changed while reading",
        )
    return buffer.raw[: read_count.value]
