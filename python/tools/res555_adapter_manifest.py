"""Generate the RES-555 expanded adapter-manifest acceptance request.

The owner accepted the RES-550/B2 10-file adapter implementation identity on 2026-11-25.
The protected route then added an inside-sandbox production worker, the shared contracts it
imports and the bootstrap that applies the sandbox before the worker import. Those bytes are
measured by the runtime source closure, but they are not part of the accepted adapter
identity, so owner condition 8 remains open.

This tool computes the exact replacement identity - schema
``dynamisbench.mujoco.implementation-identity/2`` with a second
``production_entry_manifest`` - for both qualified platforms. It is a request generator,
not an authority: the protected route keeps the accepted 10-file digest until the owner
signs the new values and a separate commit updates the profile.

Run from ``python/``:

    uv run python tools/res555_adapter_manifest.py
    uv run python tools/res555_adapter_manifest.py --check

``--check`` compares the freshly computed document with the committed candidate JSON and
fails on any drift, including a changed source file or a changed accepted digest.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Final

import dynamisbench
from dynamisbench.adapters.mujoco import reference
from dynamisbench.adapters.mujoco.protected_contracts import (
    CANDIDATE_IDENTITY_SCHEMA,
    CANDIDATE_PRODUCTION_ENTRY_FILES,
    expanded_implementation_identity,
)
from dynamisbench.execution.protected_profile import ADAPTER_IMPLEMENTATION_DIGESTS

__all__ = ["build_document", "main"]

REQUEST_SCHEMA: Final = "dynamisbench.res555.adapter-manifest-candidate/1"
PLATFORMS: Final = ("windows-x86-64", "linux-x86-64")


def _source_root() -> Path:
    return Path(dynamisbench.__file__).resolve().parent.parent


def build_document(*, source_root: Path | None = None) -> dict[str, Any]:
    """Return the complete candidate request, with both platform digests."""
    root = (source_root or _source_root()).resolve()
    platforms: dict[str, Any] = {}
    for platform in PLATFORMS:
        digest, payload = expanded_implementation_identity(
            source_root=root,
            model_sha256=reference.MODEL_SHA256,
            engine_version=reference.ENGINE_VERSION,
            python_version=reference.PYTHON_VERSION,
            platform_tag=platform,
        )
        platforms[platform] = {
            "implementation_digest": digest,
            "payload": payload,
        }
    manifest = platforms[PLATFORMS[0]]["payload"]
    return {
        "schema": REQUEST_SCHEMA,
        "status": "owner-accepted-conditional-dual-binding",
        "accepted_identity": {
            "schema": reference.IMPLEMENTATION_IDENTITY_SCHEMA,
            "digests": dict(ADAPTER_IMPLEMENTATION_DIGESTS),
            "source_files": list(reference.ADAPTER_SOURCE_FILES),
            "source_file_count": len(reference.ADAPTER_SOURCE_FILES),
        },
        "candidate_identity": {
            "schema": CANDIDATE_IDENTITY_SCHEMA,
            "source_files": [entry["path"] for entry in manifest["source_manifest"]],
            "production_entry_files": list(CANDIDATE_PRODUCTION_ENTRY_FILES),
            "file_count": len(manifest["source_manifest"])
            + len(manifest["production_entry_manifest"]),
            "platforms": platforms,
        },
        "dependency_closure_digest": manifest["dependency_closure"]["digest"],
        "declaration": (
            "Owner conditionally accepted both 13-file schema-2 digests for the fixed "
            "MuJoCo reference on 2026-11-26. The protected supervisor verifies schema-2 "
            "in addition to the preserved protocol-v1 10-file worker identity. Human "
            "review and merge remain blocked."
        ),
    }


def _write(document: dict[str, Any], output: Path | None) -> None:
    encoded = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(encoded)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(encoded, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--check",
        type=Path,
        default=None,
        metavar="COMMITTED_JSON",
        help="fail when the committed candidate differs from the current source",
    )
    arguments = parser.parse_args(argv)
    document = build_document(source_root=arguments.source_root)
    if arguments.check is not None:
        committed = json.loads(arguments.check.read_text(encoding="utf-8"))
        if committed != document:
            sys.stderr.write(
                "the committed adapter-manifest candidate does not reproduce from the "
                "current source; regenerate it and obtain owner re-acceptance\n"
            )
            return 1
        return 0
    _write(document, arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
