"""Qualification of the supervisor-side input preparation boundary."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from dynamisbench.domain.spec.sut import SUTInterface, SUTInterfaceKind
from dynamisbench.evidence.bundle import RunId, parse_run_id
from dynamisbench.execution import (
    PreflightRefusedError,
    PreparedExecutionInputs,
    RefusalCode,
    WorkerEnvironmentManifest,
    canonical_preflight_bytes,
    canonical_worker_request_bytes,
    preflight_run,
    prepare_execution_inputs,
)
from dynamisbench.execution.input_binding import (
    WorkerInputBinding,
    build_worker_input_binding,
    verify_worker_input_binding,
)
from dynamisbench.execution.input_verification import _platform_reader, verify_worker_input_view
from dynamisbench.identity import canonical_semantic_bytes, semantic_sha256
from dynamisbench.materialization import (
    MAX_ASSETS,
    AssetInput,
    InputManifestDigest,
    MaterializationError,
    MaterializationRefusalCode,
    MaterializationStore,
)
from dynamisbench.workspace import PersistenceClass, initialize_workspace
from tests.domain import factories as domain
from tests.execution.input_view_support import write_input_view
from tests.execution.support import (
    ExecutionFixture,
    asset_realization,
    build_fixture,
    worker_manifest,
    write_source_asset,
)

MODEL_PATH = "models/reference/decay.json"
MODEL_BYTES = b'{"initial_value":8,"multiplier":0.5,"steps":3}\n'


@pytest.fixture
def model_fixture(tmp_path: Path) -> ExecutionFixture:
    """A data-only scalar recurrence model for the simulator-free control adapter."""
    workspace = initialize_workspace(tmp_path / "source", tmp_path / "evidence")
    digest = write_source_asset(workspace, MODEL_PATH, MODEL_BYTES)
    return build_fixture(
        tmp_path,
        workspace=workspace,
        realization=asset_realization(path=MODEL_PATH, sha256=digest),
        system_under_test=domain.sut_definition(
            interface=SUTInterface(kind=SUTInterfaceKind.IN_PROCESS)
        ),
    )


def _prepare(
    fixture: ExecutionFixture, selection: WorkerEnvironmentManifest, run_id: RunId | None = None
) -> PreparedExecutionInputs:
    return prepare_execution_inputs(
        fixture.run_id if run_id is None else run_id,
        fixture.run,
        benchmark=fixture.benchmark,
        scenario=fixture.benchmark.scenarios[0],
        realization=fixture.realization,
        system_under_test=fixture.system_under_test,
        environment=fixture.environment,
        manifest=selection,
        workspace=fixture.workspace,
    )


def _assert_no_run(fixture: ExecutionFixture) -> None:
    for location in (PersistenceClass.STAGING, PersistenceClass.SEALED_EVIDENCE):
        assert not fixture.workspace.resolve(location, fixture.run_id).exists()


def test_incompatible_worker_is_refused_before_materialization(
    execution_fixture: ExecutionFixture, tmp_path: Path
) -> None:
    selection = worker_manifest(execution_fixture, program=str(tmp_path / "absent-worker"))
    with pytest.raises(PreflightRefusedError) as raised:
        _prepare(execution_fixture, selection)
    assert RefusalCode.WORKER_PROGRAM_UNRESOLVED in {r.code for r in raised.value.report.refusals}
    _assert_no_run(execution_fixture)


def test_substituted_environment_is_refused(execution_fixture: ExecutionFixture) -> None:
    selection = worker_manifest(execution_fixture)
    changed = execution_fixture.environment.model_copy(update={"description": "Different bytes"})
    with pytest.raises(PreflightRefusedError) as raised:
        _prepare(replace(execution_fixture, environment=changed), selection)
    codes = {item.code for item in raised.value.report.refusals}
    assert RefusalCode.ENVIRONMENT_IDENTITY_MISMATCH in codes
    _assert_no_run(execution_fixture)


def test_preparation_refuses_subprocess_sut(execution_fixture: ExecutionFixture) -> None:
    with pytest.raises(MaterializationError) as raised:
        _prepare(execution_fixture, worker_manifest(execution_fixture))
    assert raised.value.code is MaterializationRefusalCode.SUT_EXECUTABLE_CLOSURE_UNSUPPORTED
    _assert_no_run(execution_fixture)


def test_exact_inputs_are_reproducible_and_verifiable_after_source_edit(
    model_fixture: ExecutionFixture,
) -> None:
    selection = worker_manifest(model_fixture)
    first = _prepare(model_fixture, selection)
    assert _prepare(model_fixture, selection) == first
    legacy = preflight_run(
        model_fixture.run_id,
        model_fixture.run,
        realization=model_fixture.realization,
        environment=model_fixture.environment,
        manifest=selection,
        workspace=model_fixture.workspace,
    )
    assert first.report == legacy.report
    assert first.worker_environment_digest == semantic_sha256(selection)
    assert first.report.execution_fingerprint == model_fixture.run.fingerprint

    # Read and hash the persisted manifest independently of the prepare result.
    original_digest = hashlib.sha256(MODEL_BYTES).hexdigest()
    store = MaterializationStore(model_fixture.workspace)
    digest = first.inputs.manifest_digest
    assert hashlib.sha256(store.manifest_path(digest.hex).read_bytes()).hexdigest() == digest.hex
    assert write_source_asset(model_fixture.workspace, MODEL_PATH, b"revision 2") != original_digest
    restored = store.read_manifest(digest)
    assert restored == first.inputs.manifest
    assert restored.execution_refs.realization == model_fixture.run.spec.realization
    asset: AssetInput
    (asset,) = restored.assets
    assert asset.logical_path == MODEL_PATH
    assert asset.observed_sha256 == original_digest
    assert store.object_path(original_digest).read_bytes() == MODEL_BYTES
    _assert_no_run(model_fixture)


@pytest.mark.parametrize("source", [None, b"", b"revision 2"])
def test_original_plan_refuses_missing_or_edited_model(
    model_fixture: ExecutionFixture, source: bytes | None
) -> None:
    path = model_fixture.workspace.source_root / MODEL_PATH
    if source is None:
        path.unlink()
    else:
        path.write_bytes(source)
    with pytest.raises(MaterializationError) as raised:
        _prepare(model_fixture, worker_manifest(model_fixture))
    assert raised.value.code is (
        MaterializationRefusalCode.INPUT_SET_INCOMPLETE
        if source is None
        else MaterializationRefusalCode.INPUT_SOURCE_CHANGED
    )
    _assert_no_run(model_fixture)


def test_changed_benchmark_with_same_version_is_refused(model_fixture: ExecutionFixture) -> None:
    changed = model_fixture.benchmark.model_copy(update={"description": "Different benchmark"})
    with pytest.raises(MaterializationError) as raised:
        _prepare(replace(model_fixture, benchmark=changed), worker_manifest(model_fixture))
    assert raised.value.code is MaterializationRefusalCode.INPUT_DEFINITION_MISMATCH
    _assert_no_run(model_fixture)


def test_preparation_retains_materialization_asset_limit(model_fixture: ExecutionFixture) -> None:
    original = model_fixture.realization.assets[0]
    assets = tuple(
        original.model_copy(update={"asset_id": f"model-{i}", "path": f"models/model-{i}.json"})
        for i in range(MAX_ASSETS + 1)
    )
    fixture = build_fixture(
        model_fixture.workspace.source_root,
        workspace=model_fixture.workspace,
        realization=model_fixture.realization.model_copy(update={"assets": assets}),
        system_under_test=model_fixture.system_under_test,
    )
    with pytest.raises(MaterializationError) as raised:
        _prepare(fixture, worker_manifest(fixture))
    assert raised.value.code is MaterializationRefusalCode.INPUT_LIMIT_EXCEEDED
    _assert_no_run(fixture)


def test_binding_commits_to_canonical_preparation(model_fixture: ExecutionFixture) -> None:
    selection = worker_manifest(model_fixture)
    prepared = _prepare(model_fixture, selection)
    assert prepared.request is not None
    binding = build_worker_input_binding(
        prepared, selection, runtime_closure_sha256="a" * 64, isolation_profile_sha256="b" * 64
    )
    expected = {
        "schema": "dynamisbench.worker-input-binding/1",
        "run_id": str(model_fixture.run_id),
        "execution_fingerprint": model_fixture.run.fingerprint.hex,
        "request_sha256": hashlib.sha256(
            canonical_worker_request_bytes(prepared.request)
        ).hexdigest(),
        "preflight_sha256": hashlib.sha256(canonical_preflight_bytes(prepared.report)).hexdigest(),
        "input_manifest_sha256": prepared.inputs.manifest_digest.hex,
        "environment_sha256": model_fixture.run.spec.environment.semantic_digest.hex,
        "worker_selection_sha256": semantic_sha256(selection).hex,
        "adapter_implementation_sha256": selection.adapter.implementation_digest,
        "runtime_closure_sha256": "a" * 64,
        "isolation_profile_sha256": "b" * 64,
        "launch_nonce": binding.launch_nonce,
    }
    raw = canonical_semantic_bytes(expected)
    assert raw == canonical_semantic_bytes(binding)
    verify_worker_input_binding(raw, expected=binding, request=prepared.request)
    _assert_no_run(model_fixture)


@pytest.mark.parametrize("change", ["run", "report", "request", "selection", "manifest"])
def test_binding_refuses_substituted_authority(
    model_fixture: ExecutionFixture, change: str
) -> None:
    selection = worker_manifest(model_fixture)
    prepared = _prepare(model_fixture, selection)
    other = _prepare(model_fixture, selection, parse_run_id("other-run"))
    if change == "run":
        prepared = replace(prepared, request=other.request)
    if change == "report":
        prepared = replace(prepared, report=other.report)
    if change == "request":
        prepared = replace(prepared, request=None)
    if change == "selection":
        selection = worker_manifest(model_fixture, program=str(model_fixture.workspace.source_root))
    if change == "manifest":
        prepared = replace(
            prepared,
            inputs=replace(prepared.inputs, manifest_digest=InputManifestDigest(hex="f" * 64)),
        )
    with pytest.raises(MaterializationError, match="input_manifest_mismatch"):
        build_worker_input_binding(
            prepared, selection, runtime_closure_sha256="a" * 64, isolation_profile_sha256="b" * 64
        )


def test_binding_refuses_noncanonical_and_previous_attempt(model_fixture: ExecutionFixture) -> None:
    selection = worker_manifest(model_fixture)
    prepared = _prepare(model_fixture, selection)
    assert prepared.request is not None
    first = build_worker_input_binding(
        prepared, selection, runtime_closure_sha256="a" * 64, isolation_profile_sha256="b" * 64
    )
    second = build_worker_input_binding(
        prepared, selection, runtime_closure_sha256="a" * 64, isolation_profile_sha256="b" * 64
    )
    assert first.launch_nonce != second.launch_nonce
    raw = canonical_semantic_bytes(first)
    for data, expected in ((raw + b"\n", first), (raw, second)):
        with pytest.raises(MaterializationError, match="input_manifest_mismatch"):
            verify_worker_input_binding(data, expected=expected, request=prepared.request)


@pytest.fixture
def candidate_view(
    tmp_path: Path, model_fixture: ExecutionFixture
) -> tuple[Path, PreparedExecutionInputs, WorkerInputBinding]:
    selection = worker_manifest(model_fixture)
    preparation = _prepare(model_fixture, selection)
    binding = build_worker_input_binding(
        preparation, selection, runtime_closure_sha256="a" * 64, isolation_profile_sha256="b" * 64
    )
    root = write_input_view(tmp_path / "inputs", model_fixture.workspace, preparation, binding)
    return root, preparation, binding


def test_offline_view_survives_relocation_and_source_cache_deletion(
    candidate_view: tuple[Path, PreparedExecutionInputs, WorkerInputBinding],
    model_fixture: ExecutionFixture,
) -> None:
    root, prepared, binding = candidate_view
    assert prepared.request is not None
    first = verify_worker_input_view(root, expected=binding, request=prepared.request)
    store = MaterializationStore(model_fixture.workspace)
    (model_fixture.workspace.source_root / MODEL_PATH).unlink()
    for item in (*prepared.inputs.manifest.definitions, *prepared.inputs.manifest.assets):
        store.object_path(item.object.removeprefix("sha256/")).unlink(missing_ok=True)
    store.manifest_path(prepared.inputs.manifest_digest.hex).unlink()

    relocated = root.rename(root.with_name("relocated"))
    assert verify_worker_input_view(relocated, expected=binding, request=prepared.request) == first
    assert (
        first.binding_sha256
        == hashlib.sha256((relocated / "binding.json").read_bytes()).hexdigest()
    )
    assert first.input_manifest_sha256 == prepared.inputs.manifest_digest.hex
    assert len(first.files) == 6
    asset = first.files[0]
    assert asset.path == f"assets/{MODEL_PATH}"
    assert asset.size_bytes == len(MODEL_BYTES)
    assert asset.sha256 == hashlib.sha256(MODEL_BYTES).hexdigest()
    _assert_no_run(model_fixture)


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS root alias fixture")
@pytest.mark.parametrize("alias", ["case", "ancestor-case", "short"])
def test_offline_view_refuses_ntfs_root_alias(
    candidate_view: tuple[Path, PreparedExecutionInputs, WorkerInputBinding],
    alias: str,
) -> None:
    root, prepared, binding = candidate_view
    assert prepared.request is not None
    verify_worker_input_view(root, expected=binding, request=prepared.request)
    if alias == "case":
        alternate = root.with_name(root.name.swapcase())
    elif alias == "ancestor-case":
        alternate = root.parent.with_name(root.parent.name.swapcase()) / root.name
    else:
        import ctypes

        short_path = ctypes.WinDLL("kernel32", use_last_error=True).GetShortPathNameW
        buffer = ctypes.create_unicode_buffer(32768)
        length = short_path(str(root), buffer, len(buffer))
        assert 0 < length < len(buffer)
        alternate = Path(buffer.value)
        if str(alternate).casefold() == str(root).casefold():
            pytest.skip("NTFS did not create a short alias")
    assert alternate.samefile(root)
    with pytest.raises(MaterializationError, match="exact NTFS path"):
        verify_worker_input_view(alternate, expected=binding, request=prepared.request)


@pytest.mark.parametrize(
    ("relative", "mutation"),
    [
        (f"assets/{MODEL_PATH}", "replace"),
        (f"assets/{MODEL_PATH}", "truncate"),
        (f"assets/{MODEL_PATH}", "append"),
        (f"assets/{MODEL_PATH}", "remove"),
        ("definitions/benchmark.json", "replace"),
        ("manifest.json", "append"),
        ("binding.json", "append"),
        ("binding.json", "oversize"),
        ("manifest.json", "oversize"),
        ("definitions/benchmark.json", "oversize"),
        ("assets/unexpected", "extra"),
        ("definitions/Benchmark.json", "wrong-case"),
        ("definitions/bｅnchmark.json", "wrong-case"),
        ("definitions/benchmark.json", "hardlink"),
        ("definitions/benchmark.json", "symlink"),
        ("definitions/benchmark.json", "fifo"),
        ("definitions/benchmark.json", "stream"),
        ("definitions", "junction"),
    ],
)
def test_offline_view_refuses_altered_entries(
    candidate_view: tuple[Path, PreparedExecutionInputs, WorkerInputBinding],
    relative: str,
    mutation: str,
) -> None:
    root, prepared, binding = candidate_view
    assert prepared.request is not None
    path = root / relative
    if mutation == "replace":
        path.write_bytes(b"x" * path.stat().st_size)
    elif mutation == "truncate":
        path.write_bytes(b"")
    elif mutation == "append":
        with path.open("ab") as stream:
            stream.write(b"x")
    elif mutation == "remove":
        path.unlink()
    elif mutation == "oversize":
        bound = 4096 if relative == "binding.json" else 1024 * 1024
        path.write_bytes(b"x" * (bound + 1))
    elif mutation == "extra":
        path.mkdir()
    elif mutation == "wrong-case":
        transfer = path.with_name("transfer")
        path.with_name("benchmark.json").rename(transfer)
        transfer.rename(path)
        assert path.name in os.listdir(path.parent)
    elif mutation == "stream":
        if sys.platform != "win32":
            pytest.skip("NTFS alternate stream fixture")
        stream_name = str(path) + ":extra"
        with open(stream_name, "wb") as stream:
            stream.write(b"unexpected")
        with open(stream_name, "rb") as stream:
            assert stream.read() == b"unexpected"
    elif mutation == "junction":
        if sys.platform != "win32":
            pytest.skip("NTFS junction fixture")
        outside = path.rename(root.parent / "outside")
        subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/j", str(path), str(outside)],
            check=True,
            capture_output=True,
        )
        assert path.is_junction()
    else:
        outside = path.rename(root.parent / "outside")
        if mutation == "symlink":
            try:
                path.symlink_to(outside)
            except OSError as error:
                if getattr(error, "winerror", None) == 1314:
                    pytest.skip("Windows symlink privilege is unavailable")
                raise
            assert path.is_symlink()
        elif mutation == "fifo":
            if sys.platform != "linux":
                pytest.skip("FIFO fixture")
            os.mkfifo(path)
        else:
            os.link(outside, path)
            assert path.stat().st_nlink == 2

    with pytest.raises(MaterializationError):
        verify_worker_input_view(root, expected=binding, request=prepared.request)


@pytest.mark.parametrize("relative", [f"assets/{MODEL_PATH}", "definitions"])
def test_offline_view_refuses_same_bytes_swapped_after_enumeration(
    candidate_view: tuple[Path, PreparedExecutionInputs, WorkerInputBinding],
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
) -> None:
    root, prepared, binding = candidate_view
    assert prepared.request is not None
    target = root / relative
    reader = _platform_reader()
    open_original = reader.open_child
    replaced = False

    def swap(parent: int, name: str, *, directory: bool, inode: int) -> int:
        nonlocal replaced
        if not replaced and name == target.name:
            replaced = True
            previous = target.rename(root.parent / "previous")
            if directory:
                shutil.copytree(previous, target)
            else:
                shutil.copyfile(previous, target)
        return open_original(parent, name, directory=directory, inode=inode)

    monkeypatch.setattr(reader, "open_child", swap)
    with pytest.raises(MaterializationError, match="changed identity"):
        verify_worker_input_view(root, expected=binding, request=prepared.request)
    assert replaced


def test_offline_view_refuses_manifest_rehashed_with_substitute_asset(
    candidate_view: tuple[Path, PreparedExecutionInputs, WorkerInputBinding],
) -> None:
    root, prepared, binding = candidate_view
    assert prepared.request is not None
    manifest_path = root / "manifest.json"
    substitute = b"new model"
    digest = hashlib.sha256(substitute).hexdigest()
    data = json.loads(manifest_path.read_bytes())
    data["assets"][0].update(
        declared_sha256=digest,
        observed_sha256=digest,
        object=f"sha256/{digest}",
        size_bytes=len(substitute),
    )
    raw = canonical_semantic_bytes(data)
    manifest_path.write_bytes(raw)
    (root / "assets" / MODEL_PATH).write_bytes(substitute)
    with pytest.raises(MaterializationError, match="trusted binding"):
        verify_worker_input_view(root, expected=binding, request=prepared.request)

    forged = binding.model_copy(update={"input_manifest_sha256": hashlib.sha256(raw).hexdigest()})
    (root / "binding.json").write_bytes(canonical_semantic_bytes(forged))
    with pytest.raises(MaterializationError, match="realization declarations"):
        verify_worker_input_view(root, expected=forged, request=prepared.request)


@pytest.mark.parametrize("extra", [0, 1])
def test_offline_asset_size_boundary(
    tmp_path: Path, model_fixture: ExecutionFixture, extra: int
) -> None:
    model = MODEL_BYTES.ljust(1024 * 1024 + extra, b" ")
    digest = write_source_asset(model_fixture.workspace, MODEL_PATH, model)
    fixture = build_fixture(
        tmp_path,
        workspace=model_fixture.workspace,
        realization=asset_realization(path=MODEL_PATH, sha256=digest),
        system_under_test=model_fixture.system_under_test,
    )
    selection = worker_manifest(fixture)
    prepared = _prepare(fixture, selection)
    assert prepared.request is not None
    binding = build_worker_input_binding(
        prepared, selection, runtime_closure_sha256="a" * 64, isolation_profile_sha256="b" * 64
    )
    root = write_input_view(tmp_path / "inputs", fixture.workspace, prepared, binding)
    if extra:
        with pytest.raises(MaterializationError, match="input_limit_exceeded"):
            verify_worker_input_view(root, expected=binding, request=prepared.request)
    else:
        result = verify_worker_input_view(root, expected=binding, request=prepared.request)
        assert result.files[0].size_bytes == 1024 * 1024
