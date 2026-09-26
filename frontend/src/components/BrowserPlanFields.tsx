/* SPDX-License-Identifier: Apache-2.0 */
import { Locale, t } from "../i18n";
import {
  newBrowserAction,
  newBrowserScenario,
  type BrowserActionDraft,
  type BrowserPlanDraft,
  type BrowserScenarioDraft,
  type BrowserScenarioInsights,
} from "../lib/browserPlan";

export function BrowserPlanFields({ locale, value, insights, disabled, onChange }: {
  locale: Locale;
  value: BrowserPlanDraft;
  insights?: BrowserScenarioInsights | null;
  disabled: boolean;
  onChange: (value: BrowserPlanDraft) => void;
}) {
  const environmentTargetUrl = String(insights?.environmentTargetUrl ?? "");
  const locatorHints = insights?.historicalLocatorHints ?? [];
  const updateScenario = (index: number, update: Partial<BrowserScenarioDraft>, preserveStatus = false) => {
    onChange({
      ...value,
      scenarios: value.scenarios.map((scenario, scenarioIndex) => scenarioIndex === index
        ? { ...scenario, ...update, status: preserveStatus ? (update.status ?? scenario.status) : "draft" }
        : scenario),
    });
  };
  const updateAction = (scenarioIndex: number, actionIndex: number, update: Partial<BrowserActionDraft>) => {
    const scenario = value.scenarios[scenarioIndex];
    updateScenario(scenarioIndex, {
      actions: scenario.actions.map((action, currentIndex) => currentIndex === actionIndex ? { ...action, ...update } : action),
    });
  };
  const addScenario = () => {
    onChange({
      ...value,
      mode: "scenarios",
      scenarios: [...value.scenarios, newBrowserScenario(value.scenarios.length, environmentTargetUrl)],
    });
  };
  const applyLocatorHint = (hint: Record<string, unknown>) => {
    const hintedScenarioId = String(hint.scenarioId ?? "");
    const scenarioIndex = Math.max(0, value.scenarios.findIndex((scenario) => scenario.scenarioId === hintedScenarioId));
    const scenario = value.scenarios[scenarioIndex];
    if (!scenario || scenario.actions.length === 0) return;
    const hintedActionId = String(hint.actionId ?? "");
    const matchedActionIndex = scenario.actions.findIndex((action) => action.actionId === hintedActionId);
    const actionIndex = matchedActionIndex >= 0 ? matchedActionIndex : 0;
    updateAction(scenarioIndex, actionIndex, {
      selector: String(hint.selector ?? ""),
      testId: String(hint.testId ?? ""),
      role: String(hint.role ?? scenario.actions[actionIndex].role),
      name: String(hint.name ?? scenario.actions[actionIndex].name),
    });
  };
  return (
    <fieldset disabled={disabled} className="detail-stack browser-plan-fields">
      <legend>{t(locale, "browserTestConfiguration")}</legend>
      <label className="form-field">
        {t(locale, "browserScenarioMode")}
        <select
          value={value.mode}
          onChange={(event) => {
            const mode = event.target.value as BrowserPlanDraft["mode"];
            onChange({
              ...value,
              mode,
              scenarios: mode === "scenarios" && value.scenarios.length === 0
                ? [newBrowserScenario(0, environmentTargetUrl)]
                : value.scenarios,
            });
          }}
        >
          <option value="none">{t(locale, "browserNoActualExecution")}</option>
          {value.mode === "preserve" ? <option value="preserve">{t(locale, "browserPreserveConfiguration")}</option> : null}
          <option value="scenarios">{t(locale, "browserScenarioCollection")}</option>
        </select>
      </label>
      {value.mode === "preserve" ? <p>{t(locale, "browserAdvancedConfigurationPreserved")}</p> : null}
      {value.mode === "scenarios" ? <>
        <p>{t(locale, "browserScenarioHelp")}</p>
        {environmentTargetUrl ? (
          <div className="browser-suggestion-row">
            <span>{t(locale, "browserEnvironmentSuggestion")}: {environmentTargetUrl}</span>
            <button
              className="link-button"
              type="button"
              onClick={() => onChange({
                ...value,
                scenarios: value.scenarios.map((scenario) => ({
                  ...scenario,
                  targetUrl: scenario.targetUrl || environmentTargetUrl,
                  status: scenario.targetUrl ? scenario.status : "draft",
                })),
              })}
            >
              {t(locale, "browserApplySuggestion")}
            </button>
          </div>
        ) : null}
        {value.sourceChanged ? (
          <div className="notice-banner notice-banner--error">
            <strong>{t(locale, "browserSourceChangedTitle")}</strong>
            <p>{t(locale, "browserSourceChangedHelp")}</p>
            <label className="check-row">
              <input
                checked={value.acceptCurrentSource}
                type="checkbox"
                onChange={(event) => onChange({
                  ...value,
                  acceptCurrentSource: event.target.checked,
                  scenarios: event.target.checked
                    ? value.scenarios.map((scenario) => ({ ...scenario, status: "draft" }))
                    : value.scenarios,
                })}
              />
              <span>{t(locale, "browserAcceptCurrentSource")}</span>
            </label>
          </div>
        ) : null}
        <div className="browser-scenario-list">
          {value.scenarios.map((scenario, scenarioIndex) => (
            <article className="browser-scenario-card" key={scenario.scenarioId}>
              <div className="browser-scenario-card__header">
                <div>
                  <strong>{scenario.name || `${t(locale, "browserScenario")} ${scenarioIndex + 1}`}</strong>
                  <span>{t(locale, `browserScenarioStatus_${scenario.status}`)}</span>
                </div>
                <div className="button-row">
                  <label className="check-row">
                    <input
                      aria-label={`${t(locale, "browserSelectScenario")} ${scenarioIndex + 1}`}
                      checked={scenario.selected}
                      type="checkbox"
                      onChange={(event) => updateScenario(scenarioIndex, { selected: event.target.checked }, true)}
                    />
                    <span>{t(locale, "browserSelectedForExecution")}</span>
                  </label>
                  <button
                    className="link-button link-button--danger"
                    type="button"
                    onClick={() => onChange({ ...value, scenarios: value.scenarios.filter((_, index) => index !== scenarioIndex) })}
                  >
                    {t(locale, "remove")}
                  </button>
                </div>
              </div>
              <label className="form-field">
                {t(locale, "browserScenarioName")}
                <input
                  aria-label={`${t(locale, "browserScenarioName")} ${scenarioIndex + 1}`}
                  value={scenario.name}
                  onChange={(event) => updateScenario(scenarioIndex, { name: event.target.value })}
                />
              </label>
              <label className="form-field">
                {t(locale, "browserScenarioGoal")}
                <textarea
                  aria-label={`${t(locale, "browserScenarioGoal")} ${scenarioIndex + 1}`}
                  rows={2}
                  value={scenario.goal}
                  onChange={(event) => updateScenario(scenarioIndex, { goal: event.target.value })}
                />
              </label>
              <label className="form-field">
                {t(locale, "browserTargetUrl")}
                <input
                  aria-label={`${t(locale, "browserTargetUrl")} ${scenarioIndex + 1}`}
                  type="url"
                  value={scenario.targetUrl}
                  onChange={(event) => updateScenario(scenarioIndex, { targetUrl: event.target.value })}
                />
              </label>
              <label className="form-field">
                {t(locale, "browserPreconditions")}
                <textarea
                  aria-label={`${t(locale, "browserPreconditions")} ${scenarioIndex + 1}`}
                  rows={2}
                  value={scenario.preconditions.join("\n")}
                  onChange={(event) => updateScenario(scenarioIndex, { preconditions: splitLines(event.target.value) })}
                />
              </label>
              <div className="browser-action-list">
                {scenario.actions.map((action, actionIndex) => (
                  <div className="browser-action-card" key={action.actionId}>
                    <div className="browser-action-card__header">
                      <strong>{t(locale, "browserAction")} {actionIndex + 1}</strong>
                      <button
                        className="link-button link-button--danger"
                        type="button"
                        onClick={() => updateScenario(scenarioIndex, { actions: scenario.actions.filter((_, index) => index !== actionIndex) })}
                      >
                        {t(locale, "remove")}
                      </button>
                    </div>
                    <label className="form-field">
                      {t(locale, "browserActionType")}
                      <select
                        aria-label={`${t(locale, "browserActionType")} ${scenarioIndex + 1}.${actionIndex + 1}`}
                        value={action.actionType}
                        onChange={(event) => updateAction(scenarioIndex, actionIndex, { actionType: event.target.value as BrowserActionDraft["actionType"] })}
                      >
                        <option value="navigate">{t(locale, "browserNavigate")}</option>
                        <option value="fill">{t(locale, "browserFill")}</option>
                        <option value="click">{t(locale, "browserClick")}</option>
                        <option value="assert_visible">{t(locale, "browserAssertVisible")}</option>
                        <option value="assert_text">{t(locale, "browserAssertText")}</option>
                      </select>
                    </label>
                    {action.actionType === "navigate" ? (
                      <label className="form-field">
                        {t(locale, "browserActionUrl")}
                        <input aria-label={`${t(locale, "browserActionUrl")} ${scenarioIndex + 1}.${actionIndex + 1}`} type="url" value={action.url} onChange={(event) => updateAction(scenarioIndex, actionIndex, { url: event.target.value })} />
                      </label>
                    ) : <>
                      <label className="form-field">
                        {t(locale, "browserElementRole")}
                        <input aria-label={`${t(locale, "browserElementRole")} ${scenarioIndex + 1}.${actionIndex + 1}`} value={action.role} onChange={(event) => updateAction(scenarioIndex, actionIndex, { role: event.target.value })} />
                      </label>
                      <label className="form-field">
                        {t(locale, "browserAccessibleName")}
                        <input aria-label={`${t(locale, "browserAccessibleName")} ${scenarioIndex + 1}.${actionIndex + 1}`} value={action.name} onChange={(event) => updateAction(scenarioIndex, actionIndex, { name: event.target.value })} />
                      </label>
                      <label className="form-field">
                        {t(locale, "browserSelector")}
                        <input aria-label={`${t(locale, "browserSelector")} ${scenarioIndex + 1}.${actionIndex + 1}`} value={action.selector} onChange={(event) => updateAction(scenarioIndex, actionIndex, { selector: event.target.value })} />
                      </label>
                      <label className="form-field">
                        {t(locale, "browserTestId")}
                        <input aria-label={`${t(locale, "browserTestId")} ${scenarioIndex + 1}.${actionIndex + 1}`} value={action.testId} onChange={(event) => updateAction(scenarioIndex, actionIndex, { testId: event.target.value })} />
                      </label>
                    </>}
                    {action.actionType === "fill" ? <>
                      <label className="form-field">
                        {t(locale, "browserValueRef")}
                        <input aria-label={`${t(locale, "browserValueRef")} ${scenarioIndex + 1}.${actionIndex + 1}`} value={action.valueRef} onChange={(event) => updateAction(scenarioIndex, actionIndex, { valueRef: event.target.value, secretRef: "" })} />
                      </label>
                      <label className="form-field">
                        {t(locale, "browserSecretRef")}
                        <input aria-label={`${t(locale, "browserSecretRef")} ${scenarioIndex + 1}.${actionIndex + 1}`} value={action.secretRef} onChange={(event) => updateAction(scenarioIndex, actionIndex, { secretRef: event.target.value, valueRef: "" })} />
                      </label>
                    </> : null}
                    {action.actionType === "assert_text" ? <>
                      <label className="form-field">
                        {t(locale, "browserExpectedText")}
                        <input aria-label={`${t(locale, "browserExpectedText")} ${scenarioIndex + 1}.${actionIndex + 1}`} value={action.expectedText} onChange={(event) => updateAction(scenarioIndex, actionIndex, { expectedText: event.target.value })} />
                      </label>
                      <label className="form-field">
                        {t(locale, "browserTextMatch")}
                        <select aria-label={`${t(locale, "browserTextMatch")} ${scenarioIndex + 1}.${actionIndex + 1}`} value={action.match} onChange={(event) => updateAction(scenarioIndex, actionIndex, { match: event.target.value as BrowserActionDraft["match"] })}>
                          <option value="contains">{t(locale, "browserTextContains")}</option>
                          <option value="exact">{t(locale, "browserTextExact")}</option>
                        </select>
                      </label>
                    </> : null}
                    {action.limitations.length > 0 ? <small>{t(locale, "browserGenerationLimitations")}: {action.limitations.join(", ")}</small> : null}
                  </div>
                ))}
              </div>
              <div className="button-row">
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => updateScenario(scenarioIndex, { actions: [...scenario.actions, newBrowserAction(scenario.scenarioId, scenario.actions.length)] })}
                >
                  {t(locale, "browserAddAction")}
                </button>
                <label className="check-row">
                  <input
                    aria-label={`${t(locale, "browserConfirmScenario")} ${scenarioIndex + 1}`}
                    checked={scenario.status === "confirmed"}
                    disabled={value.sourceChanged && !value.acceptCurrentSource}
                    type="checkbox"
                    onChange={(event) => updateScenario(
                      scenarioIndex,
                      { status: event.target.checked ? "confirmed" : "draft" },
                      true,
                    )}
                  />
                  <span>{t(locale, "browserConfirmScenario")}</span>
                </label>
              </div>
              {scenario.sourceRefs.length > 0 ? <small>{t(locale, "browserSourceRefs")}: {scenario.sourceRefs.length}</small> : null}
              {scenario.limitations.length > 0 ? <small>{t(locale, "browserGenerationLimitations")}: {scenario.limitations.join(", ")}</small> : null}
            </article>
          ))}
        </div>
        <button className="secondary-button" type="button" onClick={addScenario}>{t(locale, "browserAddScenario")}</button>
        {locatorHints.length > 0 ? (
          <details className="browser-locator-history">
            <summary>{t(locale, "browserHistoricalLocatorHints")} ({locatorHints.length})</summary>
            <ul>
              {locatorHints.slice(0, 10).map((hint, index) => (
                <li key={`${String(hint.executionId ?? "execution")}-${index}`}>
                  <span>{String(hint.selector ?? hint.testId ?? `${hint.role ?? ""} ${hint.name ?? ""}`).trim()}</span>
                  <button className="link-button" type="button" onClick={() => applyLocatorHint(hint)}>
                    {t(locale, "browserApplyLocatorHint")}
                  </button>
                </li>
              ))}
            </ul>
          </details>
        ) : null}
      </> : null}
    </fieldset>
  );
}

function splitLines(value: string) {
  return value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
}
