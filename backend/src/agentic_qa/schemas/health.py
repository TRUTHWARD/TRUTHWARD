# SPDX-License-Identifier: Apache-2.0
from pydantic import BaseModel


class SystemHealthResponse(BaseModel):
    status: str
    services: dict[str, str]
    details: dict[str, object] = {}


class RuntimeReadinessItem(BaseModel):
    id: str
    label: str
    status: str
    summary: str
    details: dict[str, object] = {}
    evidenceRefs: list[str] = []
    validationCommand: str | None = None
    secretSafe: bool = True


class RuntimeReadinessCategory(BaseModel):
    id: str
    title: str
    status: str
    items: list[RuntimeReadinessItem]


class ReadinessResponse(BaseModel):
    schemaVersion: str = "phase8.runtime-readiness.v1"
    generatedAt: str | None = None
    status: str
    ready: bool
    dependencies: dict[str, str]
    categories: list[RuntimeReadinessCategory] = []
    summary: dict[str, int] = {}
    secretSafe: bool = True
    writeActions: bool = False
