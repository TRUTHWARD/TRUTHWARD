/* SPDX-License-Identifier: Apache-2.0 */
import { Locale, t } from "../i18n";
import type { BrowserPlanDraft } from "../lib/browserPlan";

export function BrowserPlanFields({ locale, value, disabled, onChange }: {
  locale: Locale;
  value: BrowserPlanDraft;
  disabled: boolean;
  onChange: (value: BrowserPlanDraft) => void;
}) {
  const editing = value.mode === "assert_visible" || value.mode === "assert_text";
  return (
    <fieldset disabled={disabled} className="detail-stack browser-plan-fields">
      <legend>{t(locale, "browserTestConfiguration")}</legend>
      <label className="form-field">
        {t(locale, "browserAssertionTemplate")}
        <select value={value.mode} onChange={event => onChange({ ...value, mode: event.target.value as BrowserPlanDraft["mode"] })}>
          <option value="none">{t(locale, "browserNoActualExecution")}</option>
          {value.mode === "preserve" ? <option value="preserve">{t(locale, "browserPreserveConfiguration")}</option> : null}
          <option value="assert_visible">{t(locale, "browserAssertVisible")}</option>
          <option value="assert_text">{t(locale, "browserAssertText")}</option>
        </select>
      </label>
      {value.mode === "preserve" ? <p>{t(locale, "browserAdvancedConfigurationPreserved")}</p> : null}
      {editing ? <>
        <p>{t(locale, "browserTemplateHelp")}</p>
        <label className="form-field">
          {t(locale, "browserTargetUrl")}
          <input type="url" required value={value.targetUrl} onChange={event => onChange({ ...value, targetUrl: event.target.value })} />
        </label>
        <label className="form-field">
          {t(locale, "browserElementRole")}
          <input value={value.role} onChange={event => onChange({ ...value, role: event.target.value })} />
        </label>
        <label className="form-field">
          {t(locale, "browserAccessibleName")}
          <input required={!value.selector.trim()} value={value.name} onChange={event => onChange({ ...value, name: event.target.value })} />
        </label>
        <label className="form-field">
          {t(locale, "browserSelector")}
          <input value={value.selector} onChange={event => onChange({ ...value, selector: event.target.value })} />
        </label>
        {value.mode === "assert_text" ? <>
          <label className="form-field">
            {t(locale, "browserExpectedText")}
            <input required value={value.expectedText} onChange={event => onChange({ ...value, expectedText: event.target.value })} />
          </label>
          <label className="form-field">
            {t(locale, "browserTextMatch")}
            <select value={value.match} onChange={event => onChange({ ...value, match: event.target.value as BrowserPlanDraft["match"] })}>
              <option value="contains">{t(locale, "browserTextContains")}</option>
              <option value="exact">{t(locale, "browserTextExact")}</option>
            </select>
          </label>
        </> : null}
      </> : null}
    </fieldset>
  );
}
