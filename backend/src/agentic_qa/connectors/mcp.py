# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from agentic_qa.connectors.contracts import ConnectorCapability, ConnectorRuntimeContract


MCP_CONNECTOR_CONTRACT = ConnectorRuntimeContract(
    connector_name="mcp",
    protocol="mcp",
    capabilities=[
        ConnectorCapability(name="list_tools", read_only=True, risk_level="low"),
        ConnectorCapability(name="invoke_tool", read_only=False, risk_level="medium"),
    ],
    credential_schemes=["vault", "credential", "mcp-secret"],
)
