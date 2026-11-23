"""Probe-only input-view writer for RES-555 Gate B2.

The production materializer publishes CAS objects. This writer composes the exact
read-only view the protected worker is allowed to consume, using the same canonical
binding and manifest bytes. It is test/probe infrastructure, not a production storage
adapter.
"""

from __future__ import annotations

from pathlib import Path

from dynamisbench.execution import PreparedExecutionInputs
from dynamisbench.execution.input_binding import WorkerInputBinding
from dynamisbench.identity import canonical_semantic_bytes
from dynamisbench.materialization import MaterializationStore
from dynamisbench.workspace import Workspace

__all__ = ["build_input_view"]


def build_input_view(
    root: Path,
    workspace: Workspace,
    prepared: PreparedExecutionInputs,
    binding: WorkerInputBinding,
) -> Path:
    """Write ``binding.json``, ``manifest.json``, definitions and assets beneath ``root``."""
    store = MaterializationStore(workspace)
    (root / "assets").mkdir(parents=True, exist_ok=False)
    (root / "definitions").mkdir()
    (root / "binding.json").write_bytes(canonical_semantic_bytes(binding))
    (root / "manifest.json").write_bytes(
        store.manifest_path(prepared.inputs.manifest_digest.hex).read_bytes()
    )
    for item in prepared.inputs.manifest.definitions:
        (root / "definitions" / f"{item.kind.value}.json").write_bytes(
            store.object_path(item.semantic_digest.hex).read_bytes()
        )
    for item in prepared.inputs.manifest.assets:
        path = root / "assets" / item.logical_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(store.object_path(item.observed_sha256).read_bytes())
    return root
