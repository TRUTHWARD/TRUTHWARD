# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from agentic_qa.connectors.contracts import ConnectorRuntime, ConnectorRuntimeContract


class ConnectorRuntimeRegistry:
    """In-process catalog for connector runtime contracts.

    The registry deliberately stores contracts and runtime adapters only. It has
    no database access and makes no business decisions.
    """

    def __init__(self) -> None:
        self._contracts: dict[str, ConnectorRuntimeContract] = {}
        self._runtimes: dict[str, ConnectorRuntime] = {}

    def register_contract(self, contract: ConnectorRuntimeContract) -> None:
        self._contracts[contract.connector_name] = contract

    def register_runtime(self, runtime: ConnectorRuntime) -> None:
        self._contracts[runtime.contract.connector_name] = runtime.contract
        self._runtimes[runtime.contract.connector_name] = runtime

    def get_contract(self, connector_name: str) -> ConnectorRuntimeContract | None:
        return self._contracts.get(connector_name)

    def list_contracts(self) -> list[ConnectorRuntimeContract]:
        return [self._contracts[name] for name in sorted(self._contracts)]

    def get_runtime(self, connector_name: str) -> ConnectorRuntime | None:
        return self._runtimes.get(connector_name)
