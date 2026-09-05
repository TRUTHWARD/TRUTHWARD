/* SPDX-License-Identifier: Apache-2.0 */
export type ProductProfile = "full" | "oss";

export function normalizeProductProfile(value: string | undefined): ProductProfile {
  return value?.trim().toLowerCase() === "oss" ? "oss" : "full";
}

export const PRODUCT_PROFILE = normalizeProductProfile(import.meta.env.VITE_PRODUCT_PROFILE);
export const IS_OSS_PROFILE = PRODUCT_PROFILE === "oss";

// This is a UX projection of the backend-authoritative Community capability ceiling.
// A route being present here never grants access; every page and API still checks
// the effective capabilities returned by /auth/me.
export const OSS_SECTION_CAPABILITIES = {
  workspace: null,
  "workflow-runs": null,
  workflow: "test_plans.manage",
  "exploratory-sessions": "exploratory_sessions.read",
  tasks: "work_items.read",
  findings: null,
  "audit-logs": "audit.logs.read",
  "candidate-paths": "graph.candidate.read",
  "change-sets": "change.read",
  "impact-analysis": "impact.read",
  "selective-replay-plans": "replay.plan.read",
  observability: "audit.logs.read",
  "execution-dashboard": null,
  "skill-invocations": "skill_invocations.read",
  "capability-bindings": "capability_bindings.read",
  "project-settings": "project.settings.manage",
  "environment-settings": "environment.settings.manage",
  "model-config": "model.config.manage",
  "connector-settings": "connector_bindings.manage",
} as const satisfies Record<string, string | null>;

export function isSectionIncludedInProductProfile(
  sectionId: string,
  profile: ProductProfile = PRODUCT_PROFILE,
): boolean {
  return profile !== "oss" || Object.hasOwn(OSS_SECTION_CAPABILITIES, sectionId);
}

export function isSectionVisibleInProductProfile(
  sectionId: string,
  capabilities: readonly string[],
  profile: ProductProfile = PRODUCT_PROFILE,
): boolean {
  if (profile !== "oss") return true;
  if (!Object.hasOwn(OSS_SECTION_CAPABILITIES, sectionId)) return false;
  const capability = OSS_SECTION_CAPABILITIES[sectionId as keyof typeof OSS_SECTION_CAPABILITIES];
  return capability === null || capabilities.includes(capability);
}
