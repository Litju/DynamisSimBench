"""Verify a prepared worker-input view without executing a worker.

The expected binding and request must come from trusted preparation. A result
records the bytes that passed these checkpoints, even on mutable storage.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Final

from dynamisbench.domain.spec.base import DomainModel
from dynamisbench.domain.spec.benchmark import BenchmarkRelease
from dynamisbench.domain.spec.environment import EnvironmentDefinition
from dynamisbench.domain.spec.realizations import RealizationDefinition
from dynamisbench.domain.spec.scenarios import ScenarioDefinition
from dynamisbench.domain.spec.sut import SUTDefinition, SUTInterfaceKind
from dynamisbench.execution.contracts import WorkerRequest
from dynamisbench.execution.input_binding import (
    MAX_BINDING_BYTES,
    WorkerInputBinding,
    _input_refs,
    verify_worker_input_binding,
)
from dynamisbench.identity import canonical_semantic_bytes
from dynamisbench.materialization import (
    DefinitionInput,
    DefinitionKind,
    MaterializationError,
    MaterializationRefusalCode,
    parse_input_manifest,
)

_MAX_INPUT_BYTES: Final = 1024 * 1024


@dataclass(frozen=True, slots=True)
class VerifiedInputFile:
    """The identity measured from an offline read."""

    path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedWorkerInputs:
    """A1 observations for one bound verification, with no execution authority."""

    binding_sha256: str
    input_manifest_sha256: str
    files: tuple[VerifiedInputFile, ...]


def _platform_reader():
    if sys.platform == "win32":
        from dynamisbench.execution import _input_view_windows as reader
    elif sys.platform == "linux":
        from dynamisbench.execution import _input_view_linux as reader
    else:
        raise OSError("an anchored reader is unavailable for this platform")
    return reader


class _View:
    def __init__(self, handles: ExitStack, root: Path) -> None:
        self.reader = _platform_reader()
        self.handles = handles
        self.root = self.reader.open_root(root)
        handles.callback(self.reader.close, self.root)
        self.directories: dict[int, dict[str, int]] = {}
        self.opened: dict[tuple[int, str], bool] = {}

    def _scan(self, directory: int, names: set[str]) -> dict[str, int]:
        found: dict[str, int] = {}
        for name, inode in self.reader.entries(directory):
            if name not in names or name in found:
                raise MaterializationError(
                    MaterializationRefusalCode.INPUT_SET_UNEXPECTED,
                    "the input view contains an unexpected entry or spelling",
                )
            found[name] = inode
        if found.keys() != names:
            raise MaterializationError(
                MaterializationRefusalCode.INPUT_SET_INCOMPLETE,
                "the input view is missing a required entry",
            )
        return found

    def expect(self, directory: int, names: set[str]) -> None:
        self.directories[directory] = self._scan(directory, names)

    def open(self, parent: int, name: str, *, directory: bool) -> int:
        inode = self.directories[parent][name]
        handle = self.reader.open_child(parent, name, directory=directory, inode=inode)
        self.handles.callback(self.reader.close, handle)
        self.opened[parent, name] = directory
        return handle

    def read(self, parent: int, name: str, limit: int) -> bytes:
        return self.reader.read(self.open(parent, name, directory=False), limit)

    def recheck_membership(self) -> None:
        for directory, original in self.directories.items():
            if self._scan(directory, set(original)) != original:
                raise MaterializationError(
                    MaterializationRefusalCode.INPUT_SOURCE_CHANGED,
                    "the input view entry identities changed during verification",
                )
        # A matching directory entry can hide a new hardlink or same-inode
        # mount. Reapply the handle checks while the original objects are pinned.
        for (parent, name), directory in self.opened.items():
            handle = self.reader.open_child(
                parent, name, directory=directory, inode=self.directories[parent][name]
            )
            self.reader.close(handle)


def _verify_object(
    data: bytes, *, path: str, size_bytes: int, expected_digest: str
) -> VerifiedInputFile:
    observed = sha256(data).hexdigest()
    if len(data) != size_bytes or observed != expected_digest:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_OBJECT_CORRUPT,
            "an input file's bytes do not match the manifest",
        )
    return VerifiedInputFile(path, len(data), observed)


def _verify_definition[T: DomainModel](
    view: _View,
    directory: int,
    record: DefinitionInput,
    model: type[T],
    *,
    identity: Callable[[T], tuple[str, str]],
    observations: list[VerifiedInputFile],
) -> T:
    filename = f"{record.kind.value}.json"
    data = view.read(directory, filename, _MAX_INPUT_BYTES)
    observation = _verify_object(
        data,
        path=f"definitions/{filename}",
        size_bytes=record.size_bytes,
        expected_digest=record.semantic_digest.hex,
    )
    value = model.model_validate_json(data)
    if canonical_semantic_bytes(value) != data or identity(value) != (
        record.identifier,
        record.version,
    ):
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_DEFINITION_MISMATCH,
            "an input definition did not match its canonical bytes or resolved identity",
        )
    observations.append(observation)
    return value


def _verify_definitions(
    view: _View,
    directory: int,
    refs: dict[DefinitionKind, DefinitionInput],
    observations: list[VerifiedInputFile],
) -> RealizationDefinition:
    view.expect(directory, {f"{kind.value}.json" for kind in DefinitionKind})
    benchmark = _verify_definition(
        view,
        directory,
        refs[DefinitionKind.BENCHMARK],
        BenchmarkRelease,
        identity=lambda value: (str(value.benchmark_id), value.version),
        observations=observations,
    )
    scenario = _verify_definition(
        view,
        directory,
        refs[DefinitionKind.SCENARIO],
        ScenarioDefinition,
        identity=lambda value: (str(value.scenario_id), value.version),
        observations=observations,
    )
    realization = _verify_definition(
        view,
        directory,
        refs[DefinitionKind.REALIZATION],
        RealizationDefinition,
        identity=lambda value: (str(value.realization_id), value.version),
        observations=observations,
    )
    sut = _verify_definition(
        view,
        directory,
        refs[DefinitionKind.SYSTEM_UNDER_TEST],
        SUTDefinition,
        identity=lambda value: (str(value.sut_id), value.version),
        observations=observations,
    )
    _verify_definition(
        view,
        directory,
        refs[DefinitionKind.ENVIRONMENT],
        EnvironmentDefinition,
        identity=lambda value: (str(value.environment_id), value.version),
        observations=observations,
    )
    if sut.interface.kind != SUTInterfaceKind.IN_PROCESS:
        raise MaterializationError(
            MaterializationRefusalCode.SUT_EXECUTABLE_CLOSURE_UNSUPPORTED,
            "offline verification requires an in-process SUT",
        )
    if (
        realization.benchmark.identifier != benchmark.benchmark_id
        or realization.benchmark.version != benchmark.version
        or not any(item == scenario for item in benchmark.scenarios)
    ):
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_DEFINITION_MISMATCH,
            "the benchmark, embedded scenario and realization disagree",
        )
    return realization


def verify_worker_input_view(
    root: Path, *, expected: WorkerInputBinding, request: WorkerRequest
) -> VerifiedWorkerInputs:
    """Verify an independently built input view against a trusted attempt.

    The small offline profile accepts up to one asset with a 1 MiB limit for
    each manifest, definition and asset. The root can be relocated. No source,
    CAS or package asset is read by this verifier.
    """
    if not root.is_absolute() or len(root.parts) < 2 or ".." in root.parts:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_PATH_REFUSED,
            "an absolute input view path without parent traversal is required",
        )
    try:
        with ExitStack() as handles:
            view = _View(handles, root)
            view.expect(view.root, {"binding.json", "manifest.json", "definitions", "assets"})
            binding = view.read(view.root, "binding.json", MAX_BINDING_BYTES)
            verify_worker_input_binding(binding, expected=expected, request=request)
            raw_manifest = view.read(view.root, "manifest.json", _MAX_INPUT_BYTES)
            manifest_digest = sha256(raw_manifest).hexdigest()
            if manifest_digest != expected.input_manifest_sha256:
                raise MaterializationError(
                    MaterializationRefusalCode.INPUT_MANIFEST_MISMATCH,
                    "the input manifest bytes do not match the trusted binding",
                )
            manifest = parse_input_manifest(raw_manifest)
            if manifest.execution_refs != _input_refs(request):
                raise MaterializationError(
                    MaterializationRefusalCode.INPUT_MANIFEST_MISMATCH,
                    "the input manifest references do not match the trusted request",
                )
            if len(manifest.assets) > 1:
                raise MaterializationError(
                    MaterializationRefusalCode.INPUT_LIMIT_EXCEEDED,
                    "the first offline profile supports at most one asset",
                )
            observations: list[VerifiedInputFile] = []
            definitions = view.open(view.root, "definitions", directory=True)
            realization = _verify_definitions(
                view, definitions, {item.kind: item for item in manifest.definitions}, observations
            )
            if {(a.asset_id, a.path, a.sha256) for a in realization.assets} != {
                (a.asset_id, a.logical_path, a.declared_sha256) for a in manifest.assets
            }:
                raise MaterializationError(
                    MaterializationRefusalCode.INPUT_MANIFEST_MISMATCH,
                    "the manifest assets do not match the realization declarations",
                )
            directory = view.open(view.root, "assets", directory=True)
            if not manifest.assets:
                view.expect(directory, set())
            else:
                (asset,) = manifest.assets
                *parents, filename = asset.logical_path.split("/")
                for name in parents:
                    view.expect(directory, {name})
                    directory = view.open(directory, name, directory=True)
                view.expect(directory, {filename})
                observations.append(
                    _verify_object(
                        view.read(directory, filename, _MAX_INPUT_BYTES),
                        path=f"assets/{asset.logical_path}",
                        size_bytes=asset.size_bytes,
                        expected_digest=asset.observed_sha256,
                    )
                )
            view.recheck_membership()
    except OSError as error:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_PATH_REFUSED,
            "the input view could not be verified through stable filesystem handles",
        ) from error
    except ValueError as error:
        raise MaterializationError(
            MaterializationRefusalCode.INPUT_DEFINITION_MISMATCH,
            "an input view record could not be canonically validated",
        ) from error

    return VerifiedWorkerInputs(
        sha256(binding).hexdigest(),
        manifest_digest,
        tuple(sorted(observations, key=lambda observation: observation.path)),
    )
