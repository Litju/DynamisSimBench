"""Qualification against actual workspace files and the existing Arrow reader."""

from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dynamisbench.transport.arrow import ARROW_IPC_STREAM_CONTENT_TYPE, read_ipc_stream
from dynamisbench.workspace.external_results import MAX_BYTES, MAX_ROWS
from tests.api.workspace_routes import client, open_route, snapshot

GOOD = b"time[s],position[mm],velocity[m/s]\r\n0,2,NaN\r\n0.125,,Inf\r\n0.25,1,-Inf\r\n"


@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "source"
    evidence = tmp_path / "evidence"
    source.mkdir()
    evidence.mkdir()
    return source, evidence


def result_path(api: TestClient, source: Path, evidence: Path) -> str:
    workspace = open_route(api, source, evidence)
    return f"/api/v1/workspaces/{workspace['workspace_id']}/external-results"


def test_file_bound_result_round_trip(roots: tuple[Path, Path]) -> None:
    source, evidence = roots
    inbox = source / "external-results"
    inbox.mkdir()
    file = inbox / "actual.csv"
    file.write_bytes(GOOD)
    (source / "outside.csv").write_bytes(GOOD)
    before = snapshot(source)
    with client() as api:
        base = result_path(api, source, evidence)
        listing = api.get(base).json()["results"]
        assert len(listing) == 1
        result = listing[0]
        assert result["name"] == "actual.csv"
        assert result["refusal"] is None
        url = f"{base}/{result['result_id']}"
        response = api.get(url)
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        data = response.json()
        assert data["source_sha256"] == hashlib.sha256(GOOD).hexdigest()
        assert data["sample_count"] == 3
        assert data["columns"][1] == {"name": "position", "unit": "mm", "canonical_unit": "0.001*m"}
        assert str(source) not in response.text
        response = api.get(url + "/samples")
        assert response.headers["content-type"] == ARROW_IPC_STREAM_CONTENT_TYPE
        table = read_ipc_stream(response.content)
        assert [row["time"] for row in table.rows] == [0, 0.125, 0.25]
        assert [row["position"] for row in table.rows] == [2, None, 1]
        first_velocity = table.rows[0]["velocity"]
        assert isinstance(first_velocity, float) and math.isnan(first_velocity)
        assert table.rows[1]["velocity"] == math.inf
        assert table.rows[2]["velocity"] == -math.inf
        assert api.get(base).json()["results"] == listing
        assert snapshot(source) == before
        file.write_bytes(GOOD.replace(b"0,2,", b"0,3,"))
        assert api.get(url).status_code == 409
        assert api.get(url + "/samples").status_code == 409
        assert api.get(base).json()["results"][0]["result_id"] != result["result_id"]
        assert api.get(url).status_code == 404


@pytest.mark.parametrize(
    "raw",
    [
        b"timestamp[ms],value[1]\n0,3",
        b"time[s],time[s]\n0,1",
        b"time[s],Value[1],value[V]\n0,1,2",
        b"time[s],angle[degrees]\n0,1",
        b"time[s],value[1]\n0,1,2",
        b"time[s],value[1]\nNaN,1",
        b"time[s],value[1]\n0,1e999",
        b"time[s],value[1]\n0,\xff",
        b"time[s],value[1]\n",
        b"time[s],value[1]\n" + b"0,1\n" * (MAX_ROWS + 1),
    ],
    ids=[
        "time-unit",
        "duplicate",
        "case-fold",
        "unknown-unit",
        "width",
        "missing-time",
        "overflow",
        "encoding",
        "empty",
        "row-limit",
    ],
)
def test_invalid_csv_is_refused(roots: tuple[Path, Path], raw: bytes) -> None:
    source, evidence = roots
    inbox = source / "external-results"
    inbox.mkdir()
    (inbox / "input.csv").write_bytes(raw)
    with client() as api:
        base = result_path(api, source, evidence)
        result = api.get(base).json()["results"][0]
        response = api.get(f"{base}/{result['result_id']}")
        assert response.status_code == 422, (result, response.text)
        assert str(source) not in response.text


def test_oversize_and_links_and_cross_workspace_id(roots: tuple[Path, Path]) -> None:
    source, evidence = roots
    inbox = source / "external-results"
    with client() as api:
        base = result_path(api, source, evidence)
        assert api.get(base).json() == {"results": []}
        assert api.get(base + "/%2E%2E%2Foutside.csv").status_code == 404
        inbox.mkdir()
        (inbox / "oversize.csv").write_bytes(b"x" * (MAX_BYTES + 1))
        file = inbox / "valid.csv"
        file.write_bytes(GOOD)
        other = evidence / "outside.csv"
        other.write_bytes(GOOD)
        os.link(other, inbox / "hardlink.csv")
        candidates = {row["name"]: row for row in api.get(base).json()["results"]}
        for name in ["hardlink.csv", "oversize.csv"]:
            assert candidates[name]["result_id"] is None
            assert candidates[name]["refusal"]
        second = source.parent / "other"
        second.mkdir()
        wrong_workspace = result_path(api, second, evidence)
        url = "/" + candidates["valid.csv"]["result_id"]
        assert api.get(wrong_workspace + url).status_code == 404
        file.unlink()
        assert api.get(base + url).status_code == 404
