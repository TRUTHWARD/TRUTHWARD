# SPDX-License-Identifier: Apache-2.0
import json
from typing import Literal, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from agentic_qa.api.deps import any_capability_dependency, capability_dependency, get_current_user, get_db, get_request_id, get_trace_id
from agentic_qa.api.responses import success_response
from agentic_qa.schemas.models import (
    CreateModelRequest,
    ModelGovernanceActionRequest,
    ModelInvokeRequest,
    ModelInvokeResponse,
    ModelInvokeWithToolsRequest,
    UpdateModelRequest,
    VisualTargetResolveRequest,
)
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.model_service import ModelService


router = APIRouter(tags=["models"])

MODEL_GOVERNANCE_DIRECT_MUTATION_DISABLED = "MODEL_GOVERNANCE_DIRECT_MUTATION_DISABLED"


def _require_community_direct_model_mutation() -> None:
    if not ModelService.community_direct_mutation_enabled():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": MODEL_GOVERNANCE_DIRECT_MUTATION_DISABLED,
                "message": "Use POST /model-governance/actions so model mutations pass approval, guardrail, and audit.",
            },
        )


def _build_prompt(payload: ModelInvokeRequest | ModelInvokeWithToolsRequest) -> tuple[str, dict[str, object]]:
    message_lines = [f"{message.role}: {message.content}" for message in payload.messages]
    prompt_sections = [payload.systemPrompt or "", *message_lines]
    prompt = "\n".join(section for section in prompt_sections if section).strip() or payload.taskType
    request_payload = {
        "taskType": payload.taskType,
        "messages": [message.model_dump() for message in payload.messages],
        "temperature": payload.temperature,
        "maxTokens": payload.maxTokens,
        "requiresJson": payload.requiresJson,
        "metadata": payload.metadata,
    }
    if isinstance(payload, ModelInvokeWithToolsRequest):
        request_payload.update(
            {
                "tools": payload.tools,
                "toolChoice": payload.toolChoice,
                "allowedToolNames": payload.allowedToolNames,
                "toolCallLimit": payload.toolCallLimit,
            }
        )
    return prompt, request_payload


def _serialize_invoke_response(raw_response: dict[str, object], tool_calls: list[dict[str, object]] | None = None) -> ModelInvokeResponse:
    semantic_output = raw_response.get("output")
    output_json = semantic_output if isinstance(semantic_output, dict) else None
    output_text = json.dumps(output_json, ensure_ascii=False, sort_keys=True) if output_json is not None else ""
    mode: Literal["live", "stub"] = "live" if raw_response.get("mode") == "live" else "stub"
    raw_status = str(raw_response.get("status") or "failed")
    status_value = cast(
        Literal["completed", "degraded", "failed", "invalid"],
        raw_status if raw_status in {"completed", "degraded", "failed", "invalid"} else "failed",
    )
    invocation_id = raw_response.get("modelInvocationId")
    model_id = raw_response.get("modelId")
    raw_limitations = raw_response.get("limitations")
    usage = {
        "promptTokens": raw_response.get("promptTokens"),
        "completionTokens": raw_response.get("completionTokens"),
        "totalTokens": raw_response.get("totalTokens"),
    }
    return ModelInvokeResponse(
        modelInvocationId=UUID(str(invocation_id)) if invocation_id else None,
        modelId=UUID(str(model_id)) if model_id else None,
        provider=str(raw_response.get("provider") or "stub"),
        mode=mode,
        status=status_value,
        success=bool(raw_response.get("success", False)),
        outputText=output_text,
        outputJson=output_json,
        limitations=[str(item) for item in raw_limitations] if isinstance(raw_limitations, list) else [],
        fallbackUsed=bool(raw_response.get("fallbackUsed", False)),
        fallbackReason=str(raw_response["fallbackReason"]) if raw_response.get("fallbackReason") else None,
        finishReason="stop",
        usage=usage,
        latencyMs=int(raw_response.get("latencyMs") or 0),
        toolCalls=tool_calls or [],
    )


@router.post("/models")
def create_model(
    request: Request,
    payload: CreateModelRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("model.config.manage")),
) -> dict[str, object]:
    _require_community_direct_model_mutation()
    if payload.projectId is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="projectId is required")
    try:
        data = ModelService(db).create_model(
            payload,
            ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/model-governance/policy")
def model_governance_policy(
    request: Request,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    return success_response(request, ModelService(db).model_governance_policy())


@router.post("/model-governance/actions")
def request_model_governance_action(
    request: Request,
    payload: ModelGovernanceActionRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("model.governance.manage")),
) -> dict[str, object]:
    service = ModelService(db)
    try:
        data = service.request_model_governance_action(
            payload,
            ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
        )
    except ValueError as exc:
        status_code = status.HTTP_404_NOT_FOUND if "not found" in str(exc) else status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
    return success_response(request, data)


@router.post("/model/invoke")
def invoke_model(
    request: Request,
    payload: ModelInvokeRequest,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = ModelService(db)
    prompt, request_payload = _build_prompt(payload)
    raw_response = service.invoke_model(
        role=payload.modelSelector.role,
        prompt=prompt,
        payload=request_payload,
        provider=payload.modelSelector.provider,
        execution_id=payload.executionId,
        project_id=payload.projectId,
        environment_id=payload.environmentId,
        context=ServiceContext(user=user, request_id=get_request_id(request), trace_id=str(payload.traceId or UUID(str(get_trace_id(request))))),
    )
    return success_response(request, _serialize_invoke_response(raw_response).model_dump(mode="json"))


@router.post("/model/invoke-with-tools")
def invoke_model_with_tools(
    request: Request,
    payload: ModelInvokeWithToolsRequest,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = ModelService(db)
    prompt, request_payload = _build_prompt(payload)
    raw_response = service.invoke_model(
        role=payload.modelSelector.role,
        prompt=prompt,
        payload=request_payload,
        provider=payload.modelSelector.provider,
        execution_id=payload.executionId,
        project_id=payload.projectId,
        environment_id=payload.environmentId,
        context=ServiceContext(user=user, request_id=get_request_id(request), trace_id=str(payload.traceId or UUID(str(get_trace_id(request))))),
    )
    tool_calls = [
        {"name": tool_name, "mode": payload.toolChoice}
        for tool_name in payload.allowedToolNames[: payload.toolCallLimit]
    ]
    return success_response(
        request,
        _serialize_invoke_response(raw_response, tool_calls=tool_calls).model_dump(mode="json"),
    )


@router.post("/model/resolve-visual-target")
def resolve_visual_target(
    request: Request,
    payload: VisualTargetResolveRequest,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = ModelService(db)
    try:
        data = service.resolve_visual_target(
            payload,
            ServiceContext(
                user=user,
                request_id=get_request_id(request),
                trace_id=str(payload.traceId or UUID(str(get_trace_id(request)))),
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return success_response(request, data)


@router.get("/models")
def list_models(
    request: Request,
    provider: str | None = Query(default=None),
    role: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    project_id: UUID | None = Query(default=None, alias="projectId"),
    environment_id: UUID | None = Query(default=None, alias="environmentId"),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, object]:
    service = ModelService(db)
    data = service.list_models(
        page=page,
        page_size=page_size,
        provider=provider,
        role=role,
        project_id=project_id,
        environment_id=environment_id,
        context=ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
    )
    return success_response(request, data)


@router.get("/models/{model_id}")
def get_model(request: Request, model_id: UUID, db=Depends(get_db), user=Depends(get_current_user)) -> dict[str, object]:
    service = ModelService(db)
    try:
        data = service.get_model(
            model_id,
            ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.put("/models/{model_id}")
def update_model(
    request: Request,
    model_id: UUID,
    payload: UpdateModelRequest,
    db=Depends(get_db),
    user=Depends(capability_dependency("model.config.manage")),
) -> dict[str, object]:
    _require_community_direct_model_mutation()
    try:
        data = ModelService(db).update_model(
            model_id,
            payload,
            ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return success_response(request, data)


@router.delete("/models/{model_id}")
def delete_model(request: Request, model_id: UUID, db=Depends(get_db), user=Depends(capability_dependency("model.config.manage"))) -> dict[str, object]:
    _require_community_direct_model_mutation()
    try:
        data = ModelService(db).delete_model(
            model_id,
            ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return success_response(request, data)


@router.post("/models/{model_id}/health-check")
def health_check_model(request: Request, model_id: UUID, db=Depends(get_db), user=Depends(any_capability_dependency("model.config.manage", "model.governance.manage"))) -> dict[str, object]:
    service = ModelService(db)
    try:
        data = service.health_check(model_id, ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)


@router.post("/models/{model_id}/capability-scan")
def capability_scan_model(request: Request, model_id: UUID, db=Depends(get_db), user=Depends(any_capability_dependency("model.config.manage", "model.governance.manage"))) -> dict[str, object]:
    service = ModelService(db)
    try:
        data = service.capability_scan(model_id, ServiceContext(user=user, request_id=get_request_id(request), trace_id=get_trace_id(request)))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return success_response(request, data)
