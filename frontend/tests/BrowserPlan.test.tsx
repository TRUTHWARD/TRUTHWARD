/* SPDX-License-Identifier: Apache-2.0 */
import type { ComponentProps } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WorkflowPage } from "../src/pages/WorkflowPage";
import { browserPlanError, buildBrowserPlan, newBrowserScenario, readBrowserPlan } from "../src/lib/browserPlan";

afterEach(cleanup);

function workflow(config: Record<string, Record<string, unknown>>, executableScenarioInsights?: {
  schemaVersion: string;
  environmentTargetUrl: string | null;
  historicalLocatorHints: Array<Record<string, unknown>>;
}) {
  const action = vi.fn(async () => undefined);
  const props: ComponentProps<typeof WorkflowPage> = {
    approvals: [], clarifications: [], environments: [], error: null, executionFindings: [],
    executionProgress: null, executionTasks: [], executions: [], jobs: [], loading: false, locale: "en-US",
    currentUser: { id: "user", name: "User", email: "user@example.test", roles: [], status: "active", edition: "community", capabilities: ["test_plans.manage", "executions.manage"] },
    onAnswerClarification: action, onApproveApproval: action, onCancelApproval: action,
    onCancelExecution: action, onCreateExecution: action, onCreatePlan: action,
    onCreateRequirementLibraryPipeline: action, onCreateRequirementPipeline: action, onDeletePlan: action,
    onGateExecution: action, onGeneratePlan: action, onHealExecution: action, onNavigateRoute: vi.fn(),
    onRejectApproval: action, onRetryExecution: action, onSelectExecution: vi.fn(),
    onSelectPipeline: action, onSelectPlan: vi.fn(), onUpdatePlan: action,
    pipelineReplay: null, pipelines: [], projects: [], replay: null, selectedExecutionId: null,
    selectedPipelineId: null, selectedPlanId: "plan", workflowRunProjection: null, workflowRuns: [],
    plans: [{ id: "plan", name: "Existing plan", status: "draft", environment: "local", projectId: "project",
      environmentId: "environment", domains: ["functional"], domainConfig: config, riskLevel: "high",
      sourceType: "manual", sourceRef: null, requirementVersionId: null, requirementScope: null,
      input: {}, generatedPlan: {}, executableScenarioInsights }],
  };
  render(<WorkflowPage {...props} />);
  return action;
}

describe("browser plan editing", () => {
  it("shows missing plan name beside the create button instead of silently blocking submit", () => {
    const create = workflow({});
    fireEvent.change(screen.getByLabelText("Plan name"), { target: { value: "" } });
    const button = screen.getByRole("button", { name: "Create plan" });
    fireEvent.click(button);
    expect(create).not.toHaveBeenCalled();
    expect(within(button.closest("form")!).getByRole("alert")).toHaveTextContent("Enter a plan name before saving.");
  });

  it("shows browser scope validation beside the create button", () => {
    const create = workflow({});
    const button = screen.getByRole("button", { name: "Create plan" });
    const form = button.closest("form")!;
    fireEvent.change(within(form).getByLabelText("Project"), { target: { value: "" } });
    fireEvent.change(within(form).getByLabelText("Browser execution mode"), { target: { value: "scenarios" } });
    fireEvent.click(button);
    expect(create).not.toHaveBeenCalled();
    expect(within(form).getByRole("alert")).toHaveTextContent("Select a project, its environment, and the functional test domain for a real browser test.");
  });

  it("shows backend-managed plan state and hides Enterprise approval controls in Community", () => {
    workflow({});
    expect(screen.queryByRole("combobox", { name: "Status" })).toBeNull();
    expect(screen.getByText("The backend advances this lifecycle state from creation and execution results; it is not an approval choice.")).toBeTruthy();
    expect(screen.getByLabelText(/^Plan source/)).toHaveAttribute("readonly");
    expect(screen.queryByText("Approval Center")).toBeNull();
  });

  it("does not label the Community workflow read-only when plans and executions are writable", () => {
    workflow({});
    expect(screen.queryByText("Current capabilities only allow read-only workflow observation. Write actions remain backend-guarded.")).toBeNull();
  });

  it("preserves advanced execution configuration when updating unrelated plan fields", async () => {
    const config = {
      functional: { actualExecution: true, targetUrl: "https://example.test", semanticAction: { actionType: "navigate", semanticTarget: { url: "https://example.test" } }, timeoutMs: 1234 },
      performance: { recipe: "existing" },
    };
    const update = workflow(config);
    fireEvent.change(screen.getByLabelText("Plan name"), { target: { value: "Renamed plan" } });
    fireEvent.click(screen.getByRole("button", { name: "Update plan", exact: true }));
    await waitFor(() => expect(update).toHaveBeenCalledWith("plan", expect.objectContaining({ name: "Renamed plan", domainConfig: config })));
    expect(update.mock.calls.at(-1)?.[1]).not.toHaveProperty("status");
  });

  it("submits a real assertion without lowering the plan risk or clearing other domain settings", async () => {
    const update = workflow({ performance: { preserved: true } });
    fireEvent.change(screen.getByLabelText("Browser execution mode"), { target: { value: "scenarios" } });
    fireEvent.change(screen.getByLabelText("Action type 1.1"), { target: { value: "assert_text" } });
    fireEvent.change(screen.getByLabelText("Browser target URL 1"), { target: { value: "http://127.0.0.1:8765" } });
    fireEvent.change(screen.getByLabelText("Element accessible name"), { target: { value: "Submit" } });
    fireEvent.change(screen.getByLabelText("Expected element text"), { target: { value: "Submit" } });
    confirmBusinessExpectation("The Submit button displays Submit");
    fireEvent.click(screen.getByLabelText("Reviewed and confirmed 1"));
    fireEvent.click(screen.getByRole("button", { name: "Update plan", exact: true }));
    await waitFor(() => expect(update).toHaveBeenCalledWith("plan", expect.objectContaining({
      riskLevel: "high", domainConfig: expect.objectContaining({
        performance: { preserved: true }, functional: expect.objectContaining({ actualExecution: true,
          executableScenarios: expect.objectContaining({ scenarios: [expect.objectContaining({ status: "confirmed", actions: [expect.objectContaining({ actionType: "assert_text", riskLevel: "high", assertionIntent: { expectedText: "Submit", match: "contains" } })] })] }),
        }),
      }),
    })));
  });

  it("keeps multiple assertions in one confirmed scenario", async () => {
    const update = workflow({});
    fireEvent.change(screen.getByLabelText("Browser execution mode"), { target: { value: "scenarios" } });
    fireEvent.change(screen.getByLabelText("Browser target URL 1"), { target: { value: "https://example.test" } });
    fireEvent.change(screen.getByLabelText("Element accessible name"), { target: { value: "Submit" } });
    fireEvent.click(screen.getByText("Review or edit browser execution details"));
    fireEvent.click(screen.getByRole("button", { name: "Add action" }));
    fireEvent.change(screen.getByLabelText("Action type 1.2"), { target: { value: "assert_text" } });
    const names = screen.getAllByLabelText("Element accessible name");
    fireEvent.change(names[1], { target: { value: "Confirmation" } });
    fireEvent.change(screen.getByLabelText("Expected element text"), { target: { value: "Saved" } });
    confirmBusinessExpectation("Submit is visible and confirmation displays Saved");
    fireEvent.click(screen.getByLabelText("Reviewed and confirmed 1"));
    fireEvent.click(screen.getByRole("button", { name: "Update plan", exact: true }));
    await waitFor(() => expect(update).toHaveBeenCalledWith("plan", expect.objectContaining({
      domainConfig: expect.objectContaining({
        functional: expect.objectContaining({
          executableScenarios: expect.objectContaining({ scenarios: [expect.objectContaining({ actions: expect.arrayContaining([
            expect.objectContaining({ actionType: "assert_visible" }),
            expect.objectContaining({ actionType: "assert_text" }),
          ]) })] }),
        }),
      }),
    })));
  });

  it("does not submit an invalid target through the update button", async () => {
    const update = workflow({});
    fireEvent.change(screen.getByLabelText("Browser execution mode"), { target: { value: "scenarios" } });
    fireEvent.change(screen.getByLabelText("Browser target URL 1"), { target: { value: "file:///etc/passwd" } });
    fireEvent.change(screen.getByLabelText("Element accessible name"), { target: { value: "Submit" } });
    confirmBusinessExpectation("Submit is visible");
    fireEvent.click(screen.getByLabelText("Reviewed and confirmed 1"));
    fireEvent.click(screen.getByRole("button", { name: "Update plan", exact: true }));
    expect(update).not.toHaveBeenCalled();
    expect(screen.getAllByText("Enter an HTTP or HTTPS target URL without embedded credentials.").length).toBeGreaterThan(0);
  });

  it("applies a successful historical locator as an editable draft", async () => {
    const scenario = newBrowserScenario(0, "https://example.test");
    scenario.scenarioId = "checkout";
    scenario.actions[0].actionId = "checkout-visible";
    scenario.actions[0].name = "Submit";
    scenario.acceptance = undefined; // Exercise pre-existing configuration compatibility.
    scenario.status = "confirmed";
    const config = buildBrowserPlan(
      {},
      { ...readBrowserPlan({}), mode: "scenarios", scenarios: [scenario] },
      "high",
    );
    const update = workflow(config, {
      schemaVersion: "community.executable-scenario-insights.v1",
      environmentTargetUrl: null,
      historicalLocatorHints: [{
        scenarioId: "checkout",
        actionId: "checkout-visible",
        selector: "[data-testid='submit']",
        executionId: "execution-1",
      }],
    });

    fireEvent.click(screen.getByRole("button", { name: "Use locator" }));
    fireEvent.click(screen.getByRole("button", { name: "Update plan", exact: true }));

    await waitFor(() => expect(update).toHaveBeenCalledWith("plan", expect.objectContaining({
      domainConfig: expect.objectContaining({
        functional: expect.objectContaining({
          executableScenarios: expect.objectContaining({
            scenarios: [expect.objectContaining({
              status: "draft",
              actions: [expect.objectContaining({ targetHints: { selector: "[data-testid='submit']" } })],
            })],
          }),
        }),
      }),
    })));
  });

  it("preserves an action-specific navigation URL", () => {
    const scenario = newBrowserScenario(0, "https://example.test/start");
    scenario.status = "confirmed";
    scenario.actions[0] = {
      ...scenario.actions[0],
      actionType: "navigate",
      url: "https://example.test/checkout",
    };
    scenario.acceptance = undefined; // Legacy navigation-only configurations remain valid.

    const config = buildBrowserPlan(
      {},
      { ...readBrowserPlan({}), mode: "scenarios", scenarios: [scenario] },
      "low",
    );

    const collection = config.functional.executableScenarios as { scenarios: Array<{ actions: Array<{ semanticTarget: { url: string } }> }> };
    expect(collection.scenarios[0].actions[0].semanticTarget.url).toBe("https://example.test/checkout");
  });

  it.each(["file:///tmp/page", "https://user:password@example.test", "javascript:alert(1)"])("rejects unsafe template URL %s", targetUrl => {
    const scenario = newBrowserScenario(0, targetUrl);
    scenario.status = "confirmed";
    scenario.actions[0].name = "Submit";
    scenario.acceptance!.expectedOutcome = "Submit is visible";
    scenario.acceptance!.reviewed = true;
    const draft = { ...readBrowserPlan({}), mode: "scenarios" as const, scenarios: [scenario] };
    expect(browserPlanError(draft)).toBe("browserTargetUrlInvalid");
    expect(() => buildBrowserPlan({}, draft, "low")).toThrow();
  });
});

function confirmBusinessExpectation(expected: string) {
  fireEvent.change(screen.getByLabelText("Expected business result 1"), { target: { value: expected } });
  fireEvent.click(screen.getByLabelText("I have reviewed the conditions and expected business result 1"));
}
