# SPDX-License-Identifier: Apache-2.0
"""Apache-2.0 reference ConnectorRuntime for the public conformance kit."""

from __future__ import annotations

from agentic_qa.connectors.contracts import (
    ConnectorCapability,
    ConnectorOperationRequest,
    ConnectorOperationResult,
    ConnectorRuntimeContract,
)


class ReferenceConnectorAdapter:
    contract = ConnectorRuntimeContract(
        connector_name="public-reference-connector",
        protocol="public-conformance.v1",
        capabilities=[ConnectorCapability(name="conformance.read", read_only=True)],
        credential_schemes=["credential_ref"],
    )

    def invoke(self, request: ConnectorOperationRequest) -> ConnectorOperationResult:
        if request.operation != "conformance.read":
            return ConnectorOperationResult(
                succeeded=False,
                errors=[f"unsupported operation: {request.operation}"],
            )
        item_id = str(request.payload.get("itemId") or "")
        return ConnectorOperationResult(
            succeeded=True,
            data={"itemId": item_id, "state": "available"},
            evidence_refs=[
                {
                    "type": "connector_read",
                    "ref": f"public-reference://items/{item_id}",
                    "metadata": {
                        "traceId": request.trace_id,
                        "skillInvocationId": request.skill_invocation_id,
                    },
                }
            ],
            connector_call_ref=f"public-reference://items/{item_id}",
        )


def create_connector() -> ReferenceConnectorAdapter:
    return ReferenceConnectorAdapter()
