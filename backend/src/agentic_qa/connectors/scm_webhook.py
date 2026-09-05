# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Mapping

from agentic_qa.schemas.scm_pr import WebhookEnvelope


MAX_WEBHOOK_BYTES = 2 * 1024 * 1024
WEBHOOK_CLOCK_SKEW_SECONDS = 300
SUPPORTED_ACTIONS = {
    "opened",
    "reopened",
    "synchronize",
    "sync",
    "update",
    "closed",
    "merged",
    "edited",
    "labeled",
    "unlabeled",
    "ready_for_review",
    "converted_to_draft",
}
GITLAB_ACTIONS = {
    "open": "opened",
    "reopen": "reopened",
    "close": "closed",
    "merge": "merged",
    "approved": "update",
    "approval": "update",
    "unapproved": "update",
}


class ScmWebhookProtocolError(ValueError):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(message)


def verify_signature(
    provider: str,
    headers: Mapping[str, str],
    raw_body: bytes,
    secret: str,
    *,
    now: datetime | None = None,
) -> datetime:
    """Verify protocol authentication only; authorization remains Service-owned."""
    if not secret:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_SECRET_UNAVAILABLE", "webhook secret is unavailable", 503)
    if len(raw_body) > MAX_WEBHOOK_BYTES:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_PAYLOAD_TOO_LARGE", "webhook payload is too large", 413)
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    timestamp_value = lowered.get("x-webhook-timestamp") or lowered.get("x-agentic-webhook-timestamp")
    signature_header = {
        "github": "x-hub-signature-256",
        "gitlab": "x-gitlab-signature-256",
        "mock-scm": "x-scm-signature-256",
    }.get(provider)
    if signature_header is None:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_PROVIDER_UNSUPPORTED", "SCM provider is unsupported", 400)
    supplied = lowered.get(signature_header, "")
    authenticated = False
    if supplied:
        if supplied.startswith("sha256="):
            supplied = supplied[7:]
        expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
        authenticated = len(supplied) == 64 and hmac.compare_digest(supplied.lower(), expected)
    elif provider == "gitlab":
        supplied_token = lowered.get("x-gitlab-token", "")
        authenticated = bool(supplied_token) and hmac.compare_digest(supplied_token, secret)
    if not authenticated:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_SIGNATURE_INVALID", "webhook signature is invalid", 401)

    # Native provider signatures authenticate the JSON body, not arbitrary
    # timestamp headers. Use the timestamp inside that authenticated body so a
    # captured request cannot be replayed by changing an unsigned header.
    if provider == "mock-scm" and timestamp_value:
        try:
            event_at = datetime.fromtimestamp(float(timestamp_value), tz=timezone.utc)
        except (ValueError, OverflowError) as exc:
            raise ScmWebhookProtocolError("SCM_WEBHOOK_TIMESTAMP_INVALID", "webhook timestamp is invalid", 401) from exc
    else:
        event_at = _provider_event_time(provider, raw_body)
    current = now or datetime.now(timezone.utc)
    if abs((current - event_at).total_seconds()) > WEBHOOK_CLOCK_SKEW_SECONDS:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_TIMESTAMP_EXPIRED", "webhook timestamp is outside the allowed window", 401)
    return event_at


def adapt_webhook(
    provider: str,
    headers: Mapping[str, str],
    raw_body: bytes,
    *,
    received_at: datetime,
    verified_event_at: datetime,
) -> WebhookEnvelope:
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_PAYLOAD_INVALID", "webhook payload must be UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ScmWebhookProtocolError("SCM_WEBHOOK_PAYLOAD_INVALID", "webhook payload must be an object")
    if provider == "github":
        native = _adapt_github(headers, payload)
    elif provider == "gitlab":
        native = _adapt_gitlab(headers, payload)
    elif provider == "mock-scm":
        native = _adapt_mock(headers, payload)
    else:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_PROVIDER_UNSUPPORTED", "SCM provider is unsupported")
    native["providerEventAt"] = native.get("providerEventAt") or verified_event_at
    native["provider"] = provider
    native["receivedAt"] = received_at
    native["payloadHash"] = f"sha256:{hashlib.sha256(raw_body).hexdigest()}"
    native["payloadSnapshot"] = payload
    return WebhookEnvelope.model_validate(native)


def _adapt_github(headers: Mapping[str, str], payload: dict[str, Any]) -> dict[str, Any]:
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    event = lowered.get("x-github-event", "")
    if event != "pull_request":
        raise ScmWebhookProtocolError("SCM_WEBHOOK_EVENT_UNSUPPORTED", "only GitHub pull_request events are supported", 422)
    delivery = lowered.get("x-github-delivery")
    pr = payload.get("pull_request") or {}
    repository = payload.get("repository") or {}
    installation = payload.get("installation") or {}
    return _build_native(
        delivery=delivery,
        event_type="pull_request",
        action=payload.get("action"),
        installation=installation.get("id") or payload.get("installation_id") or "github-app",
        repository_id=repository.get("id") or repository.get("node_id"),
        repository_name=repository.get("full_name"),
        repository_url=repository.get("html_url"),
        pr_number=payload.get("number") or pr.get("number"),
        provider_event_at=pr.get("updated_at"),
        payload=payload,
    )


def _adapt_gitlab(headers: Mapping[str, str], payload: dict[str, Any]) -> dict[str, Any]:
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    event = lowered.get("x-gitlab-event", "")
    if event not in {"Merge Request Hook", "merge_request"} or payload.get("object_kind") not in {None, "merge_request"}:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_EVENT_UNSUPPORTED", "only GitLab merge request events are supported", 422)
    attrs = payload.get("object_attributes") or {}
    project = payload.get("project") or {}
    return _build_native(
        delivery=(
            lowered.get("x-gitlab-event-uuid")
            or lowered.get("x-gitlab-webhook-uuid")
            or lowered.get("idempotency-key")
            or lowered.get("x-request-id")
        ),
        event_type="merge_request",
        action=GITLAB_ACTIONS.get(str(attrs.get("action") or attrs.get("state") or "update").lower(), attrs.get("action") or attrs.get("state") or "update"),
        installation=payload.get("installation_id") or project.get("namespace") or project.get("id") or "gitlab",
        repository_id=project.get("id"),
        repository_name=project.get("path_with_namespace") or project.get("web_url"),
        repository_url=project.get("web_url"),
        pr_number=attrs.get("iid") or attrs.get("id"),
        provider_event_at=attrs.get("updated_at") or attrs.get("created_at"),
        payload=payload,
    )


def _adapt_mock(headers: Mapping[str, str], payload: dict[str, Any]) -> dict[str, Any]:
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    repository = payload.get("repository") or {}
    pr = payload.get("pull_request") or payload.get("merge_request") or {}
    return _build_native(
        delivery=lowered.get("x-scm-delivery"),
        event_type=str(payload.get("event_type") or "pull_request"),
        action=payload.get("action"),
        installation=payload.get("installation_id") or "mock-installation",
        repository_id=repository.get("id"),
        repository_name=repository.get("full_name"),
        repository_url=repository.get("web_url"),
        pr_number=payload.get("number") or pr.get("number") or pr.get("iid"),
        provider_event_at=payload.get("updated_at"),
        payload=payload,
    )


def _build_native(**values: Any) -> dict[str, Any]:
    delivery = str(values.get("delivery") or "").strip()
    action = str(values.get("action") or "").strip().lower()
    event_type = str(values.get("event_type") or "")
    repository_id = str(values.get("repository_id") or "").strip()
    repository_name = str(values.get("repository_name") or "").strip()
    if not delivery:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_DELIVERY_ID_MISSING", "delivery ID is required", 422)
    if action not in SUPPORTED_ACTIONS:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_ACTION_UNSUPPORTED", "webhook action is unsupported", 422)
    if event_type not in {"pull_request", "merge_request"}:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_EVENT_UNSUPPORTED", "SCM event type is unsupported", 422)
    if not repository_id or not repository_name:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_REPOSITORY_MISSING", "repository identity is required", 422)
    raw_pr_number = values.get("pr_number")
    if raw_pr_number is None:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_PR_NUMBER_MISSING", "PR/MR number is required", 422)
    try:
        pr_number = int(raw_pr_number)
    except (TypeError, ValueError) as exc:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_PR_NUMBER_MISSING", "PR/MR number is required", 422) from exc
    provider_event_at = _parse_datetime(values.get("provider_event_at"))
    return {
        "schemaVersion": "phase8.scm-webhook-envelope.v1",
        "deliveryId": delivery,
        "eventType": event_type,
        "action": action,
        "installationRef": str(values.get("installation")),
        "repository": {
            "nativeId": repository_id,
            "fullName": repository_name,
            "webUrl": str(values.get("repository_url")) if values.get("repository_url") else None,
        },
        "pullRequestNumber": pr_number,
        "providerEventAt": provider_event_at,
    }


def _parse_datetime(value: Any) -> datetime:
    if value in {None, ""}:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_EVENT_TIME_MISSING", "provider event time is required", 422)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_EVENT_TIME_INVALID", "provider event time is invalid", 422) from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _provider_event_time(provider: str, raw_body: bytes) -> datetime:
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_TIMESTAMP_MISSING", "a verifiable event timestamp is required", 401) from exc
    if not isinstance(payload, dict):
        raise ScmWebhookProtocolError("SCM_WEBHOOK_TIMESTAMP_MISSING", "a verifiable event timestamp is required", 401)
    if provider == "github":
        raw_item = payload.get("pull_request")
        item = raw_item if isinstance(raw_item, dict) else {}
        value = item.get("updated_at")
    elif provider == "gitlab":
        raw_item = payload.get("object_attributes")
        item = raw_item if isinstance(raw_item, dict) else {}
        value = item.get("updated_at") or item.get("created_at")
    else:
        value = payload.get("updated_at")
    try:
        return _parse_datetime(value)
    except ScmWebhookProtocolError as exc:
        raise ScmWebhookProtocolError("SCM_WEBHOOK_TIMESTAMP_MISSING", "a verifiable event timestamp is required", 401) from exc


__all__ = [
    "MAX_WEBHOOK_BYTES",
    "ScmWebhookProtocolError",
    "adapt_webhook",
    "verify_signature",
]
