# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from agentic_qa.guardrails.base import GuardrailContext, RuntimeGuardrail
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult


class SandboxExecutionGuard(RuntimeGuardrail):
    rule_id = "execution.untrusted_code_sandbox"

    def evaluate(self, context: GuardrailContext) -> GuardrailResult:
        payload = context.payload
        raw_profile = payload.get("sandboxProfile")
        profile = raw_profile if isinstance(raw_profile, dict) else {}
        command_surface = payload.get("commandSurface")
        failures: list[str] = []
        expected = {
            "engine": "docker",
            "networkMode": "none",
            "readOnlySource": True,
            "readOnlyRootFilesystem": True,
            "hostPathAccess": False,
            "dockerSocketAccess": False,
            "noNewPrivileges": True,
            "dropAllCapabilities": True,
            "cleanupRequired": True,
        }
        for key, value in expected.items():
            if profile.get(key) != value:
                failures.append(key)
        if profile.get("secretRefs") or profile.get("networkAllowlist"):
            failures.append("default-deny-secret-network")
        if command_surface not in {None, "platform_recipe_only"}:
            failures.append("arbitrary-command-surface")
        if failures:
            return GuardrailResult(
                rule_id=self.rule_id,
                decision=GuardrailDecision.BLOCK,
                reason="untrusted code execution did not satisfy the P21 sandbox baseline",
                evidence=sorted(set(failures)),
                metadata={"action": "admission.execute", "sandboxed": False},
            )
        return GuardrailResult(
            rule_id=self.rule_id,
            decision=GuardrailDecision.ALLOW,
            reason="untrusted code execution satisfies the default-deny P21 sandbox baseline",
            evidence=[
                "read-only source and root filesystem",
                "network disabled",
                "all Linux capabilities dropped",
                "Docker socket and host paths unavailable",
                "platform-owned recipes only",
            ],
            metadata={"action": "admission.execute", "sandboxed": True},
        )


__all__ = ["SandboxExecutionGuard"]
