/* SPDX-License-Identifier: Apache-2.0 */
export type BrowserActionType = "navigate" | "fill" | "click" | "assert_visible" | "assert_text";
export type BrowserScenarioStatus = "draft" | "needs_input" | "confirmed" | "stale";

export type BrowserActionDraft = {
  actionId: string;
  actionType: BrowserActionType;
  url: string;
  role: string;
  name: string;
  selector: string;
  testId: string;
  expectedText: string;
  match: "contains" | "exact";
  valueRef: string;
  secretRef: string;
  sourceRefs: Array<Record<string, unknown>>;
  confidence: number;
  limitations: string[];
  origin: "generated" | "manual" | "legacy";
};

export type BrowserScenarioDraft = {
  scenarioId: string;
  name: string;
  goal: string;
  targetUrl: string;
  preconditions: string[];
  actions: BrowserActionDraft[];
  sourceRefs: Array<Record<string, unknown>>;
  confidence: number;
  limitations: string[];
  status: BrowserScenarioStatus;
  selected: boolean;
  origin: "generated" | "manual" | "legacy";
};

export type BrowserPlanDraft = {
  mode: "none" | "preserve" | "scenarios";
  schemaVersion: "community.executable-scenarios.v1";
  revision: number;
  sourceFingerprint: string;
  sourceChanged: boolean;
  acceptCurrentSource: boolean;
  changeSummary: Record<string, unknown>;
  scenarios: BrowserScenarioDraft[];
};

export type BrowserScenarioInsights = {
  schemaVersion?: string;
  environmentTargetUrl?: string | null;
  historicalLocatorHints?: Array<Record<string, unknown>>;
};

export type DomainConfiguration = Record<string, Record<string, unknown>>;

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function stringArray(value: unknown) {
  return Array.isArray(value) ? value.map(String).filter(Boolean) : [];
}

function referenceArray(value: unknown): Array<Record<string, unknown>> {
  return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item)) : [];
}

function actionType(value: unknown): BrowserActionType {
  return ["navigate", "fill", "click", "assert_visible", "assert_text"].includes(String(value))
    ? String(value) as BrowserActionType
    : "assert_visible";
}

function scenarioStatus(value: unknown): BrowserScenarioStatus {
  return ["draft", "needs_input", "confirmed", "stale"].includes(String(value))
    ? String(value) as BrowserScenarioStatus
    : "draft";
}

function readAction(value: unknown, fallbackId: string): BrowserActionDraft {
  const action = record(value);
  const target = record(action.semanticTarget);
  const hints = record(action.targetHints);
  const assertion = record(action.assertionIntent);
  return {
    actionId: String(action.actionId || fallbackId),
    actionType: actionType(action.actionType),
    url: String(target.url ?? hints.url ?? ""),
    role: String(target.role ?? "button"),
    name: String(target.name ?? ""),
    selector: String(hints.selector ?? hints.css ?? ""),
    testId: String(hints.testId ?? ""),
    expectedText: String(assertion.expectedText ?? assertion.text ?? assertion.expected ?? ""),
    match: assertion.match === "exact" ? "exact" : "contains",
    valueRef: String(action.valueRef ?? ""),
    secretRef: String(action.secretRef ?? ""),
    sourceRefs: referenceArray(action.sourceRefs),
    confidence: Number(action.confidence ?? 1),
    limitations: stringArray(action.limitations),
    origin: action.origin === "generated" || action.origin === "legacy" ? action.origin : "manual",
  };
}

function readScenario(value: unknown, index: number, fallbackUrl: string): BrowserScenarioDraft {
  const scenario = record(value);
  const scenarioId = String(scenario.scenarioId || `scenario-${index + 1}`);
  const actions = Array.isArray(scenario.actions)
    ? scenario.actions.map((action, actionIndex) => readAction(action, `${scenarioId}-action-${actionIndex + 1}`))
    : [];
  return {
    scenarioId,
    name: String(scenario.name || `Scenario ${index + 1}`),
    goal: String(scenario.goal || ""),
    targetUrl: String(scenario.targetUrl || fallbackUrl),
    preconditions: stringArray(scenario.preconditions),
    actions,
    sourceRefs: referenceArray(scenario.sourceRefs),
    confidence: Number(scenario.confidence ?? 1),
    limitations: stringArray(scenario.limitations),
    status: scenarioStatus(scenario.status),
    selected: scenario.selected !== false,
    origin: scenario.origin === "generated" || scenario.origin === "legacy" ? scenario.origin : "manual",
  };
}

export function newBrowserAction(scenarioId: string, index: number, type: BrowserActionType = "assert_visible"): BrowserActionDraft {
  return {
    actionId: `${scenarioId}-action-${index + 1}`,
    actionType: type,
    url: "",
    role: "button",
    name: "",
    selector: "",
    testId: "",
    expectedText: "",
    match: "contains",
    valueRef: "",
    secretRef: "",
    sourceRefs: [],
    confidence: 1,
    limitations: [],
    origin: "manual",
  };
}

export function newBrowserScenario(index: number, targetUrl = ""): BrowserScenarioDraft {
  const scenarioId = `manual-scenario-${Date.now()}-${index + 1}`;
  return {
    scenarioId,
    name: `Scenario ${index + 1}`,
    goal: "",
    targetUrl,
    preconditions: [],
    actions: [newBrowserAction(scenarioId, 0)],
    sourceRefs: [],
    confidence: 1,
    limitations: [],
    status: "draft",
    selected: true,
    origin: "manual",
  };
}

function emptyBrowserPlan(mode: BrowserPlanDraft["mode"]): BrowserPlanDraft {
  return {
    mode,
    schemaVersion: "community.executable-scenarios.v1",
    revision: 1,
    sourceFingerprint: "",
    sourceChanged: false,
    acceptCurrentSource: false,
    changeSummary: {},
    scenarios: [],
  };
}

export function readBrowserPlan(config: DomainConfiguration): BrowserPlanDraft {
  const functional = config.functional ?? {};
  const collection = record(functional.executableScenarios);
  const rawScenarios = Array.isArray(collection.scenarios) ? collection.scenarios : [];
  if (rawScenarios.length > 0) {
    return {
      mode: "scenarios",
      schemaVersion: "community.executable-scenarios.v1",
      revision: Number(collection.revision ?? 1),
      sourceFingerprint: String(collection.sourceFingerprint ?? ""),
      sourceChanged: collection.sourceChanged === true,
      acceptCurrentSource: false,
      changeSummary: record(collection.changeSummary),
      scenarios: rawScenarios.map((scenario, index) => readScenario(scenario, index, String(functional.targetUrl ?? ""))),
    };
  }

  const legacyActions = Array.isArray(functional.semanticActions)
    ? functional.semanticActions
    : functional.semanticAction && typeof functional.semanticAction === "object"
      ? [functional.semanticAction]
      : [];
  if (functional.actualExecution === true && legacyActions.length > 0) {
    if (legacyActions.some((item) => !["navigate", "fill", "click", "assert_visible", "assert_text"].includes(String(record(item).actionType)))) {
      return emptyBrowserPlan("preserve");
    }
    const scenario = newBrowserScenario(0, String(functional.targetUrl ?? functional.url ?? ""));
    return {
      ...emptyBrowserPlan("scenarios"),
      scenarios: [{
        ...scenario,
        scenarioId: "legacy-browser-scenario",
        name: "Legacy browser scenario",
        goal: "Preserved browser execution configuration",
        actions: legacyActions.map((action, index) => readAction(action, `legacy-browser-action-${index + 1}`)),
        status: "confirmed",
        origin: "legacy",
      }],
    };
  }
  return emptyBrowserPlan("none");
}

function validUrl(value: string) {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) && !url.username && !url.password;
  } catch {
    return false;
  }
}

export function browserPlanError(draft: BrowserPlanDraft): string | null {
  if (draft.mode === "none" || draft.mode === "preserve") return null;
  const confirmed = draft.scenarios.filter((scenario) => scenario.status === "confirmed");
  if (draft.sourceChanged && confirmed.length > 0 && !draft.acceptCurrentSource) return "browserSourceChanged";
  for (const scenario of confirmed) {
    if (!validUrl(scenario.targetUrl)) return "browserTargetUrlInvalid";
    if (scenario.actions.length === 0) return "browserActionsRequired";
    for (const action of scenario.actions) {
      const hasTarget = Boolean(action.selector.trim() || action.testId.trim() || action.name.trim());
      if (action.actionType !== "navigate" && !hasTarget) return "browserTargetRequired";
      if (action.actionType === "assert_text" && !action.expectedText.trim()) return "browserExpectedTextRequired";
      if (action.actionType === "fill" && Boolean(action.valueRef.trim()) === Boolean(action.secretRef.trim())) return "browserFillReferenceRequired";
    }
  }
  return null;
}

function buildAction(action: BrowserActionDraft, riskLevel: string) {
  const semanticTarget: Record<string, unknown> = {};
  const targetHints: Record<string, unknown> = {};
  if (action.actionType === "navigate" && action.url.trim()) semanticTarget.url = action.url.trim();
  if (action.role.trim()) semanticTarget.role = action.role.trim();
  if (action.name.trim()) semanticTarget.name = action.name.trim();
  if (action.selector.trim()) targetHints.selector = action.selector.trim();
  if (action.testId.trim()) targetHints.testId = action.testId.trim();
  const built: Record<string, unknown> = {
    schemaVersion: "phase7.v1",
    actionId: action.actionId,
    actionType: action.actionType,
    semanticTarget,
    targetHints,
    locatorStrategy: { primary: "dom", fallback: ["accessibility"] },
    fallbackPolicy: { allowCoordinateClick: false },
    assertionIntent: action.actionType === "assert_text" ? { expectedText: action.expectedText, match: action.match } : {},
    riskLevel,
    policyRefs: [],
    sourceRefs: action.sourceRefs,
    confidence: action.confidence,
    limitations: action.limitations,
    origin: action.origin,
  };
  if (action.actionType === "fill" && action.valueRef.trim()) built.valueRef = action.valueRef.trim();
  if (action.actionType === "fill" && action.secretRef.trim()) built.secretRef = action.secretRef.trim();
  return built;
}

export function buildBrowserPlan(config: DomainConfiguration, draft: BrowserPlanDraft, riskLevel: string): DomainConfiguration {
  const error = browserPlanError(draft);
  if (error) throw new Error(error);
  if (draft.mode === "preserve") return config;
  if (draft.mode === "none") {
    const functional: Record<string, unknown> = { ...(config.functional ?? {}), actualExecution: false };
    delete functional.executableScenarios;
    delete functional.semanticAction;
    delete functional.semanticActions;
    return { ...config, functional };
  }
  const scenarios = draft.scenarios.map((scenario) => ({
    scenarioId: scenario.scenarioId,
    name: scenario.name.trim(),
    goal: scenario.goal.trim(),
    targetUrl: scenario.targetUrl.trim(),
    preconditions: scenario.preconditions,
    actions: scenario.actions.map((action) => buildAction(action, riskLevel)),
    sourceRefs: scenario.sourceRefs,
    confidence: scenario.confidence,
    limitations: scenario.limitations,
    status: scenario.status,
    selected: scenario.selected,
    origin: scenario.origin,
  }));
  return {
    ...config,
    functional: {
      ...(config.functional ?? {}),
      actualExecution: scenarios.some((scenario) => scenario.selected && scenario.status === "confirmed"),
      executableScenarios: {
        schemaVersion: draft.schemaVersion,
        revision: draft.revision + 1,
        sourceFingerprint: draft.sourceFingerprint,
        sourceChanged: draft.sourceChanged,
        acceptCurrentSource: draft.acceptCurrentSource,
        changeSummary: draft.changeSummary,
        scenarios,
      },
    },
  };
}

export function executableScenarioIds(config: DomainConfiguration) {
  const collection = record(config.functional?.executableScenarios);
  const scenarios = Array.isArray(collection.scenarios) ? collection.scenarios : [];
  return scenarios
    .map(record)
    .filter((scenario) => scenario.selected !== false && scenario.status === "confirmed")
    .map((scenario) => String(scenario.scenarioId || ""))
    .filter(Boolean);
}
