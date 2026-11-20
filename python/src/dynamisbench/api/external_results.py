"""Read-only external simulation results for an explicitly opened workspace."""

from typing import Literal

from fastapi import APIRouter, HTTPException, Response

from dynamisbench.api.errors import ErrorResponse, refusal_responses
from dynamisbench.api.models import ApiModel
from dynamisbench.api.workspace_registry import WorkspaceNotFoundError
from dynamisbench.api.workspaces import RegisteredWorkspace
from dynamisbench.transport.arrow import (
    ARROW_IPC_STREAM_CONTENT_TYPE,
    encode_nullable_float_columns,
)
from dynamisbench.workspace.external_results import (
    Refusal,
    ResultRefusedError,
    ResultSamples,
    ResultSource,
    read_result,
)

external_results_router = APIRouter()
_BASE = "/workspaces/{workspace_id}/external-results"
_REFUSALS = refusal_responses(
    {
        404: {"model": ErrorResponse, "description": "The workspace or result is unavailable."},
        409: {"model": ErrorResponse, "description": "The discovered source changed."},
        422: {"model": ErrorResponse, "description": "The result or folder was refused."},
    }
)


class ResultEntry(ApiModel):
    name: str
    result_id: str | None = None
    refusal: Refusal | None = None


class ResultsResponse(ApiModel):
    results: tuple[ResultEntry, ...]


class ResultField(ApiModel):
    name: str
    unit: str
    canonical_unit: str


class ResultResponse(ApiModel):
    result_id: str
    source_name: str
    source_sha256: str
    size_bytes: int
    schema_version: Literal["external-results/csv-v1"] = "external-results/csv-v1"
    sample_count: int
    columns: tuple[ResultField, ...]


def _refusal(error: ResultRefusedError) -> HTTPException:
    status = {Refusal.CHANGED: 409, Refusal.UNAVAILABLE: 404}.get(error.reason, 422)
    return HTTPException(status, detail=error.reason.value)


@external_results_router.get(_BASE, response_model=ResultsResponse, responses=_REFUSALS)
def list_results(
    workspace_id: str, registry: RegisteredWorkspace, response: Response
) -> ResultsResponse:
    response.headers["Cache-Control"] = "no-store"
    try:
        sources, refused = registry.discover_external_results(workspace_id)
    except WorkspaceNotFoundError:
        raise HTTPException(404, detail="Open the workspace to discover its results.") from None
    except ResultRefusedError as error:
        raise _refusal(error) from None
    entries = [ResultEntry(name=source.name, result_id=key) for key, source in sources.items()]
    entries.extend(ResultEntry(name=name, refusal=reason) for name, reason in refused.items())
    return ResultsResponse(results=tuple(sorted(entries, key=lambda entry: entry.name)))


def _read(
    registry: RegisteredWorkspace, workspace_id: str, result_id: str
) -> tuple[ResultSource, ResultSamples]:
    try:
        workspace, source = registry.external_result(workspace_id, result_id)
        return source, read_result(workspace, source)
    except WorkspaceNotFoundError:
        raise HTTPException(
            404, detail="Refresh the results list or reopen the workspace."
        ) from None
    except ResultRefusedError as error:
        raise _refusal(error) from None


@external_results_router.get(
    _BASE + "/{result_id}", response_model=ResultResponse, responses=_REFUSALS
)
def inspect_result(
    workspace_id: str, result_id: str, registry: RegisteredWorkspace, response: Response
) -> ResultResponse:
    response.headers["Cache-Control"] = "no-store"
    source, samples = _read(registry, workspace_id, result_id)
    return ResultResponse(
        result_id=result_id,
        source_name=source.name,
        source_sha256=source.sha256,
        size_bytes=source.size_bytes,
        sample_count=len(samples.values[0]),
        columns=tuple(
            ResultField(name=field.name, unit=field.unit, canonical_unit=field.canonical_unit)
            for field in samples.columns
        ),
    )


@external_results_router.get(
    _BASE + "/{result_id}/samples",
    response_class=Response,
    responses={
        **_REFUSALS,
        200: {
            "content": {
                ARROW_IPC_STREAM_CONTENT_TYPE: {"schema": {"type": "string", "format": "binary"}}
            }
        },
    },
)
def result_samples(workspace_id: str, result_id: str, registry: RegisteredWorkspace) -> Response:
    _, samples = _read(registry, workspace_id, result_id)
    return Response(
        encode_nullable_float_columns(
            tuple(
                (field.name, values)
                for field, values in zip(samples.columns, samples.values, strict=True)
            )
        ),
        media_type=ARROW_IPC_STREAM_CONTENT_TYPE,
        headers={"Cache-Control": "no-store"},
    )
