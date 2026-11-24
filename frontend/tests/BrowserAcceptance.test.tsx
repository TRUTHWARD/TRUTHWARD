/* SPDX-License-Identifier: Apache-2.0 */
import { useState } from "react";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { BrowserPlanFields } from "../src/components/BrowserPlanFields";
import { browserPlanError, buildBrowserPlan, newBrowserScenario, readBrowserPlan, type BrowserPlanDraft } from "../src/lib/browserPlan";

afterEach(cleanup);

function scenarioDraft(): BrowserPlanDraft {
  const scenario = newBrowserScenario(0, "https://example.test");
  scenario.preconditions = ["No discount; unit price 10"];
  scenario.goal = "Buy three items";
  scenario.actions[0] = { ...scenario.actions[0], actionType: "assert_text", role: "status", name: "Total", expectedText: "30" };
  scenario.acceptance!.expectedOutcome = "The order total is 30";
  return { ...readBrowserPlan({}), mode: "scenarios", scenarios: [scenario] };
}

function Editor({ initial, disabled = false }: { initial: BrowserPlanDraft; disabled?: boolean }) {
  const [value, setValue] = useState(initial);
  return <>
    <BrowserPlanFields locale="en-US" value={value} disabled={disabled} onChange={setValue} insights={{ acceptanceSources: [{ ref: "test-plan-input://requirements#acceptance-criteria/0", text: "Three items at 10 each cost 30" }] }} />
    <output data-testid="saved">{JSON.stringify(buildBrowserPlan({}, { ...value, scenarios: value.scenarios.map(s => ({ ...s, status: "draft" })) }, "low"))}</output>
  </>;
}

describe("business expectation review", () => {
  it("shows the business result before collapsed execution details and preserves source on save", () => {
    render(<Editor initial={scenarioDraft()} />);
    const details = screen.getByText("Review or edit browser execution details").closest("details")!;
    expect(details).not.toHaveAttribute("open");
    expect(screen.getByLabelText("Expected business result 1")).toHaveValue("The order total is 30");
    fireEvent.change(screen.getByLabelText("Source acceptance criterion 1"), { target: { value: "test-plan-input://requirements#acceptance-criteria/0" } });
    expect(screen.getByText("Three items at 10 each cost 30", { selector: "blockquote" })).toBeTruthy();
    fireEvent.click(screen.getByLabelText("I have reviewed the conditions and expected business result 1"));
    const saved = JSON.parse(screen.getByTestId("saved").textContent!);
    expect(saved.functional.executableScenarios.scenarios[0].acceptance).toMatchObject({
      expectedOutcome: "The order total is 30", sourceText: "Three items at 10 each cost 30", basis: "requirement", reviewed: true,
    });
    expect(saved.functional.executableScenarios.scenarios[0].actions[0].assertionIntent.expectedText).toBe("30");
  });

  it("requires business review and refuses confirmation while questions remain", () => {
    const draft = scenarioDraft();
    draft.scenarios[0].status = "confirmed";
    expect(browserPlanError(draft)).toBe("browserBusinessReviewRequired");
    draft.scenarios[0].acceptance!.openQuestions = ["Can a member discount apply?"];
    expect(browserPlanError(draft)).toBe("browserBusinessQuestionsUnresolved");
    render(<Editor initial={draft} />);
    expect(screen.getByLabelText("I have reviewed the conditions and expected business result 1")).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Questions to resolve (one per line) 1"), { target: { value: "" } });
    expect(screen.getByLabelText("I have reviewed the conditions and expected business result 1")).toBeEnabled();
  });

  it("offers source text as an empty business draft without copying it into a page assertion", () => {
    const draft = scenarioDraft();
    draft.scenarios[0].acceptance!.expectedOutcome = "";
    render(<Editor initial={draft} />);
    fireEvent.change(screen.getByLabelText("Source acceptance criterion 1"), { target: { value: "test-plan-input://requirements#acceptance-criteria/0" } });
    expect(screen.getByLabelText("Expected business result 1")).toHaveValue("Three items at 10 each cost 30");
    expect(screen.getByLabelText("Expected element text 1.1")).toHaveValue("30");
    expect(screen.getByLabelText("I have reviewed the conditions and expected business result 1")).not.toBeChecked();
  });

  it("invalidates both reviews when conditions or expected results change", () => {
    const draft = scenarioDraft();
    draft.scenarios[0].acceptance!.reviewed = true;
    draft.scenarios[0].status = "confirmed";
    render(<Editor initial={draft} />);
    fireEvent.change(screen.getByLabelText("Preconditions (one per line) 1"), { target: { value: "Member discount applies" } });
    expect(screen.getByLabelText("I have reviewed the conditions and expected business result 1")).not.toBeChecked();
    expect(screen.getByLabelText("Reviewed and confirmed 1")).not.toBeChecked();
    fireEvent.click(screen.getByLabelText("I have reviewed the conditions and expected business result 1"));
    fireEvent.change(screen.getByLabelText("Expected business result 1"), { target: { value: "Total is 27" } });
    expect(screen.getByLabelText("I have reviewed the conditions and expected business result 1")).not.toBeChecked();
  });

  it("keeps business review separate from browser readiness and preserves it after reload", () => {
    const draft = scenarioDraft();
    draft.scenarios[0].acceptance!.reviewed = true;
    draft.scenarios[0].actions[0].name = "";
    const config = buildBrowserPlan({}, draft, "high");
    const read = readBrowserPlan(config);
    expect(read.scenarios[0].acceptance?.reviewed).toBe(true);
    read.scenarios[0].status = "confirmed";
    expect(browserPlanError(read)).toBe("browserTargetRequired");
  });

  it("disables all expectation controls in a read-only context", () => {
    render(<Editor initial={scenarioDraft()} disabled />);
    expect(screen.getByLabelText("Expected business result 1")).toBeDisabled();
    expect(screen.getByLabelText("Source acceptance criterion 1")).toBeDisabled();
    expect(screen.getByLabelText("I have reviewed the conditions and expected business result 1")).toBeDisabled();
  });

  it("shows current readiness instead of obsolete candidate validation codes", () => {
    const draft = scenarioDraft();
    draft.scenarios[0].limitations = ["BUSINESS_EXPECTATION_REVIEW_REQUIRED", "ELEMENT_TARGET_REQUIRED", "Review the supported discount combinations"];
    draft.scenarios[0].actions[0].limitations = ["ELEMENT_TARGET_REQUIRED"];
    render(<Editor initial={draft} />);
    expect(within(screen.getByRole("group", { name: "Real browser test" })).queryByText(/BUSINESS_EXPECTATION_REVIEW_REQUIRED|ELEMENT_TARGET_REQUIRED/)).toBeNull();
    expect(within(screen.getByRole("group", { name: "Real browser test" })).getByText(/Review the supported discount combinations/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText("I have reviewed the conditions and expected business result 1"));
    expect(screen.queryByText("Review and confirm the business expectation before confirming execution.")).toBeNull();
  });
});
