"""Build independent offline view fixtures from the published CAS objects."""

from pathlib import Path

from dynamisbench.execution import PreparedExecutionInputs
from dynamisbench.execution.input_binding import WorkerInputBinding
from dynamisbench.identity import canonical_semantic_bytes
from dynamisbench.materialization import MaterializationStore
from dynamisbench.workspace import Workspace


def write_input_view(
    root: Path, workspace: Workspace, prepared: PreparedExecutionInputs, binding: WorkerInputBinding
) -> Path:
    store = MaterializationStore(workspace)
    (root / "assets").mkdir(parents=True)
    (root / "definitions").mkdir()
    (root / "binding.json").write_bytes(canonical_semantic_bytes(binding))
    (root / "manifest.json").write_bytes(
        store.manifest_path(prepared.inputs.manifest_digest.hex).read_bytes()
    )
    for item in prepared.inputs.manifest.definitions:
        data = store.object_path(item.semantic_digest.hex).read_bytes()
        (root / "definitions" / f"{item.kind}.json").write_bytes(data)
    for item in prepared.inputs.manifest.assets:
        path = root / "assets" / item.logical_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(store.object_path(item.observed_sha256).read_bytes())
    return root
