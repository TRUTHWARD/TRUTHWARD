# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Protocol

from agentic_qa.skills.integrations.ci_gate import CiGateEvidenceSkill
from agentic_qa.skills.integrations.contracts import IntegrationSkillInput, IntegrationSkillResult
from agentic_qa.skills.integrations.integration_intake import IntegrationIntakeSkill
from agentic_qa.skills.integrations.scm_pr_workflow import ScmPrWorkflowSkill


class IntegrationSkill(Protocol):
    skill_name: str

    def run(self, request: IntegrationSkillInput) -> IntegrationSkillResult:
        ...


class IntegrationSkillRegistry:
    def __init__(self, skills: list[IntegrationSkill] | None = None) -> None:
        self._skills: dict[str, IntegrationSkill] = {}
        for skill in skills or []:
            self.register(skill)

    def register(self, skill: IntegrationSkill) -> None:
        self._skills[skill.skill_name] = skill

    def get(self, skill_name: str) -> IntegrationSkill:
        try:
            return self._skills[skill_name]
        except KeyError as exc:
            raise ValueError(f"integration skill not registered: {skill_name}") from exc

    def list_skill_names(self) -> list[str]:
        return sorted(self._skills)

    def run(self, request: IntegrationSkillInput) -> IntegrationSkillResult:
        return self.get(request.skill).run(request)


def build_integration_skill_registry() -> IntegrationSkillRegistry:
    return IntegrationSkillRegistry(
        [
            IntegrationIntakeSkill(),
            ScmPrWorkflowSkill(),
            CiGateEvidenceSkill(),
        ]
    )
