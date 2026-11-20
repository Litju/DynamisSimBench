"""Read bounded, data-only results under the opened source root."""

from __future__ import annotations

import io
import math
import os
import re
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from dynamisbench.domain.spec.quantities import CanonicalUnit
from dynamisbench.identity import asset_sha256
from dynamisbench.workspace.authority import PathScopeError
from dynamisbench.workspace.paths import validate_logical_reference
from dynamisbench.workspace.workspace import Workspace

RESULT_DIRECTORY = "external-results"
MAX_BYTES = 1024 * 1024
MAX_ENTRIES = 256
MAX_RESULTS = 32
MAX_COLUMNS = 16
MAX_ROWS = 20_000
MAX_VALUES = 100_000
MAX_TOKEN = 64

FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,95}\.csv", re.IGNORECASE | re.ASCII)
HEADER = re.compile(
    rb"([A-Za-z][A-Za-z0-9_]{0,47})\[((?:[A-Za-z]+(?:\^-?[1-9])?(?:[*/][A-Za-z]+(?:\^-?[1-9])?)*)|1)\]"
)
NUMBER = re.compile(rb"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
NONFINITE = {
    b"NaN": float("nan"),
    b"Inf": float("inf"),
    b"+Inf": float("inf"),
    b"-Inf": -float("inf"),
}


class Refusal(StrEnum):
    UNAVAILABLE = "The result source is unavailable or is not a regular, single-link file."
    CHANGED = "The result changed. Refresh the results list to inspect the new source."
    LIMIT = "The source exceeds the external-results limits."
    SCHEMA = "Use a header beginning with time[s], followed by unique name[SI-unit] columns."
    DATA = (
        "Each row must match the header and contain decimal numbers, explicit NaN/Inf, "
        "or blank signal cells. Time must be finite."
    )


class ResultRefusedError(ValueError):
    def __init__(self, reason: Refusal) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ResultSource:
    name: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class ResultColumn:
    name: str
    unit: str
    canonical_unit: str


@dataclass(frozen=True, slots=True)
class ResultSamples:
    columns: tuple[ResultColumn, ...]
    values: tuple[list[float | None], ...]


def _plain(entry: os.stat_result, *, directory: bool) -> bool:
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    return (
        expected(entry.st_mode)
        and not bool(getattr(entry, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        and (directory or entry.st_nlink == 1)
    )


def _identity(entry: os.stat_result) -> tuple[int, int]:
    return entry.st_dev, entry.st_ino


def _directory_identity(directory: Path) -> tuple[tuple[int, int], ...]:
    chain = []
    for component in (*reversed(directory.parents), directory):
        info = component.lstat()
        if not _plain(info, directory=True):
            raise ResultRefusedError(Refusal.UNAVAILABLE)
        chain.append(_identity(info))
    return tuple(chain)


def _stamp(entry: os.stat_result) -> tuple[int, ...]:
    return (*_identity(entry), entry.st_size, entry.st_mtime_ns)


def _read_source(directory: Path, name: str) -> bytes:
    if not FILENAME.fullmatch(name):
        raise ResultRefusedError(Refusal.UNAVAILABLE)
    try:
        validate_logical_reference(name)
    except PathScopeError:
        raise ResultRefusedError(Refusal.UNAVAILABLE) from None
    path = directory / name
    try:
        chain = _directory_identity(directory)
        before = path.lstat()
        if not _plain(before, directory=False):
            raise ResultRefusedError(Refusal.UNAVAILABLE)
        if before.st_size > MAX_BYTES:
            raise ResultRefusedError(Refusal.LIMIT)
        flags = os.O_RDONLY
        for flag in ("O_BINARY", "O_NOFOLLOW", "O_NONBLOCK"):
            flags |= getattr(os, flag, 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not _plain(opened, directory=False)
                or _stamp(opened) != _stamp(before)
                or _directory_identity(directory) != chain
                or not _plain(current := path.lstat(), directory=False)
                or _stamp(current) != _stamp(opened)
            ):
                raise ResultRefusedError(Refusal.CHANGED)
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                raw = handle.read(MAX_BYTES + 1)
            after = path.lstat()
            if (
                len(raw) != opened.st_size
                or _stamp(os.fstat(descriptor)) != _stamp(opened)
                or not _plain(after, directory=False)
                or _stamp(after) != _stamp(opened)
                or after.st_ctime_ns != before.st_ctime_ns
                or _directory_identity(directory) != chain
            ):
                raise ResultRefusedError(Refusal.CHANGED)
            return raw
        finally:
            os.close(descriptor)
    except OSError:
        raise ResultRefusedError(Refusal.UNAVAILABLE) from None


def discover_results(
    workspace: Workspace,
) -> tuple[dict[str, ResultSource], dict[str, Refusal]]:
    directory = workspace.source_root / RESULT_DIRECTORY
    names: list[str] = []
    try:
        # Check the parent separately so a deleted workspace is different from an absent inbox.
        _directory_identity(workspace.source_root)
        try:
            chain = _directory_identity(directory)
        except FileNotFoundError:
            return {}, {}
        with os.scandir(directory) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_ENTRIES:
                    raise ResultRefusedError(Refusal.LIMIT)
                if FILENAME.fullmatch(entry.name):
                    names.append(entry.name)
                    if len(names) > MAX_RESULTS:
                        raise ResultRefusedError(Refusal.LIMIT)
        if _directory_identity(directory) != chain:
            raise ResultRefusedError(Refusal.CHANGED)
    except OSError:
        raise ResultRefusedError(Refusal.UNAVAILABLE) from None

    sources: dict[str, ResultSource] = {}
    refused: dict[str, Refusal] = {}
    for name in sorted(names):
        try:
            raw = _read_source(directory, name)
        except ResultRefusedError as error:
            refused[name] = error.reason
        else:
            sources[name] = ResultSource(name, asset_sha256(raw).hex, len(raw))
    return sources, refused


def read_result(workspace: Workspace, source: ResultSource) -> ResultSamples:
    raw = _read_source(workspace.source_root / RESULT_DIRECTORY, source.name)
    if len(raw) != source.size_bytes or asset_sha256(raw).hex != source.sha256:
        raise ResultRefusedError(Refusal.CHANGED)
    return parse_samples(raw)


def _columns(header: bytes) -> tuple[ResultColumn, ...]:
    fields = header.removeprefix(b"\xef\xbb\xbf").rstrip(b"\r\n").split(b",")
    if not 2 <= len(fields) <= MAX_COLUMNS or fields[0] != b"time[s]":
        raise ResultRefusedError(Refusal.SCHEMA)
    columns = []
    names: set[str] = set()
    for field in fields:
        match = HEADER.fullmatch(field)
        if match is None or len(match[2]) > MAX_TOKEN:
            raise ResultRefusedError(Refusal.SCHEMA)
        name, unit = (part.decode("ascii") for part in match.groups())
        if name.casefold() in names:
            raise ResultRefusedError(Refusal.SCHEMA)
        names.add(name.casefold())
        try:
            canonical = CanonicalUnit(expression=unit).expression
        except ValueError:
            raise ResultRefusedError(Refusal.SCHEMA) from None
        columns.append(ResultColumn(name, unit, canonical))
    return tuple(columns)


def _number(cell: bytes) -> float:
    if len(cell) > MAX_TOKEN or not NUMBER.fullmatch(cell):
        raise ResultRefusedError(Refusal.DATA)
    value = float(cell)
    if not math.isfinite(value):
        raise ResultRefusedError(Refusal.DATA)
    return value


def parse_samples(raw: bytes) -> ResultSamples:
    if len(raw) > MAX_BYTES:
        raise ResultRefusedError(Refusal.LIMIT)
    lines = io.BytesIO(raw)
    header_limit = MAX_COLUMNS * (48 + MAX_TOKEN + 3) + 5
    header = lines.readline(header_limit + 1)
    if len(header) > header_limit:
        raise ResultRefusedError(Refusal.LIMIT)
    columns = _columns(header)
    values: tuple[list[float | None], ...] = tuple([] for _ in columns)
    row_limit = len(columns) * (MAX_TOKEN + 1) + 1
    max_rows = min(MAX_ROWS, MAX_VALUES // len(columns))
    while line := lines.readline(row_limit + 1):
        if len(values[0]) >= max_rows or len(line) > row_limit:
            raise ResultRefusedError(Refusal.LIMIT)
        cells = line.rstrip(b"\r\n").split(b",")
        if len(cells) != len(columns):
            raise ResultRefusedError(Refusal.DATA)
        values[0].append(_number(cells[0]))
        for column, cell in zip(values[1:], cells[1:], strict=True):
            if not cell:
                column.append(None)
            elif cell in NONFINITE:
                column.append(NONFINITE[cell])
            else:
                column.append(_number(cell))
    if not values[0]:
        raise ResultRefusedError(Refusal.DATA)
    return ResultSamples(columns, values)
