# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from agentic_qa.connectors.contracts import (
    ConnectorCapability,
    ConnectorOperationRequest,
    ConnectorOperationResult,
    ConnectorRuntimeContract,
)


MOCK_CONNECTOR_CONTRACT = ConnectorRuntimeContract(
    connector_name="mock-scm",
    protocol="mock",
    capabilities=[
        ConnectorCapability(name="fetch_pull_request", read_only=True, risk_level="low"),
        ConnectorCapability(name="fetch_diff", read_only=True, risk_level="low"),
        ConnectorCapability(name="fetch_checks", read_only=True, risk_level="low"),
        ConnectorCapability(name="write_check", read_only=False, risk_level="high"),
    ],
    credential_schemes=["vault", "credential"],
)


class MockScmConnector:
    contract = MOCK_CONNECTOR_CONTRACT

    def invoke(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        if request.operation == "write_check":
            status = str(request.payload.get("status") or "")
            if status == "stale":
                return ConnectorOperationResult(succeeded=False, errors=["mock-scm refuses stale CI writeback"])
            external_id = f"mock-check-{str(request.payload.get('idempotencyKey') or '')[-16:]}"
            return ConnectorOperationResult(
                succeeded=True,
                data={
                    "id": external_id,
                    "status": status,
                    "url": f"https://mock-scm.example.test/checks/{external_id}",
                },
                evidence_refs=[{"type": "connector", "ref": f"mock-scm://checks/{external_id}"}],
                connector_call_ref=f"mock-scm://checks/{external_id}",
            )
        return ConnectorOperationResult(
            succeeded=True,
            data={
                "operation": request.operation,
                "repository": request.payload.get("repository"),
                "pullNumber": request.payload.get("pullNumber"),
                "commitSha": request.payload.get("commitSha"),
                "readOnly": request.operation != "write_check",
            },
            evidence_refs=[
                {
                    "type": "connector",
                    "ref": f"mock-scm://{request.operation}",
                    "metadata": {"readOnly": True},
                }
            ],
            connector_call_ref=f"mock-scm://{request.operation}",
        )
