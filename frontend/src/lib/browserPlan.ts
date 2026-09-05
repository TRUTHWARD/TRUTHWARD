/* SPDX-License-Identifier: Apache-2.0 */
export type BrowserPlanDraft = {
  mode: "none" | "preserve" | "assert_visible" | "assert_text";
  targetUrl: string;
  role: string;
  name: string;
  selector: string;
  expectedText: string;
  match: "contains" | "exact";
};

export type DomainConfiguration = Record<string, Record<string, unknown>>;

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

export function readBrowserPlan(config: DomainConfiguration): BrowserPlanDraft {
  const functional = config.functional ?? {};
  const action = record(functional.semanticAction);
  const target = record(action.semanticTarget);
  const hints = record(action.targetHints);
  const assertion = record(action.assertionIntent);
  const mode = functional.actualExecution === true
    ? action.actionType === "assert_visible" || action.actionType === "assert_text" ? action.actionType : "preserve"
    : "none";
  return {
    mode,
    targetUrl: String(functional.targetUrl ?? ""),
    role: String(target.role ?? "button"),
    name: String(target.name ?? ""),
    selector: String(hints.selector ?? hints.css ?? ""),
    expectedText: String(assertion.expectedText ?? assertion.text ?? assertion.expected ?? ""),
    match: assertion.match === "exact" ? "exact" : "contains",
  };
}

export function browserPlanError(draft: BrowserPlanDraft): string | null {
  if (draft.mode === "none" || draft.mode === "preserve") return null;
  try {
    const url = new URL(draft.targetUrl);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) return "browserTargetUrlInvalid";
  } catch {
    return "browserTargetUrlInvalid";
  }
  if (!draft.selector.trim() && !draft.name.trim()) return "browserTargetRequired";
  if (draft.mode === "assert_text" && !draft.expectedText.trim()) return "browserExpectedTextRequired";
  return null;
}

export function buildBrowserPlan(config: DomainConfiguration, draft: BrowserPlanDraft, riskLevel: string): DomainConfiguration {
  const error = browserPlanError(draft);
  if (error) throw new Error(error);
  if (draft.mode === "preserve") return config;
  if (draft.mode === "none") {
    return config.functional ? { ...config, functional: { ...config.functional, actualExecution: false } } : config;
  }
  return {
    ...config,
    functional: {
      ...config.functional,
      actualExecution: true,
      targetUrl: draft.targetUrl.trim(),
      semanticAction: {
        schemaVersion: "phase7.v1",
        actionId: "browser-assertion",
        actionType: draft.mode,
        semanticTarget: { role: draft.role, name: draft.name.trim() },
        targetHints: draft.selector.trim() ? { selector: draft.selector.trim() } : {},
        locatorStrategy: { primary: "dom", fallback: ["accessibility"] },
        fallbackPolicy: { allowCoordinateClick: false },
        assertionIntent: draft.mode === "assert_text" ? { expectedText: draft.expectedText, match: draft.match } : {},
        riskLevel,
        policyRefs: [],
      },
    },
  };
}
