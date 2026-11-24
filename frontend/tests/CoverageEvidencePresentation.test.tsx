/* SPDX-License-Identifier: Apache-2.0 */
import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { CoverageProofBundle } from "../src/lib/api";
import { CoverageMatrixPage } from "../src/pages/CoverageMatrixPage";


const proof: CoverageProofBundle = {
  schemaVersion: "phase8.coverage-proof.v1",
  generatedAt: "2026-09-23T00:00:00Z",
  requirementVersionId: "requirement-version-1",
  requirementVersionIds: ["requirement-version-1"],
  requirementItemId: "requirement-item-1",
  requirementScope: null,
  coverageStatus: "covered",
  proofStatus: "complete",
  proofChain: [{
    testPointId: "point-1",
    testCaseId: "case-1",
    executionTaskId: "task-1",
    proofEdges: [],
    evidenceArtifactRefs: [{ id: "screenshot-1" }],
    rawFindingRefs: [],
    normalizedFindingRefs: [{ id: "finding-1" }],
    gateDecisionRef: "gate-1",
    gateInputSnapshotRef: null,
    policySnapshotRef: null,
    approvalRefs: [],
    traceRefs: ["trace://trace-1"],
    auditRefs: [],
    traceabilitySnapshotRef: "traceability-snapshot://traceability-1",
    traceabilitySnapshotHash: `sha256:${"a".repeat(64)}`,
    coverageMatrixSnapshotRef: "coverage-snapshot://coverage-1",
    coverageMatrixSnapshotHash: `sha256:${"b".repeat(64)}`,
    replayExportRef: null,
    replayExportHash: null,
    proofIssues: [],
  }],
  proofIssues: [],
  traceId: "trace-1",
};

describe("CoverageMatrixPage evidence presentation", () => {
  it("shows proof entities and snapshots instead of requiring raw JSON inspection", () => {
    const view = render(<CoverageMatrixPage coverageMatrix={null} coverageProof={proof} coverageSummary={null} locale="en-US" onSelectPlan={vi.fn()} onSelectRequirementItem={vi.fn()} plans={[]} proofError={null} proofLoading={false} selectedPlanId={null} selectedRequirementItemId="requirement-item-1" />);

    expect(view.getByText("Artifact · screenshot-1")).toBeInTheDocument();
    expect(view.getByText("Normalized finding · finding-1")).toBeInTheDocument();
    expect(view.getByText("Gate decision · gate-1")).toBeInTheDocument();
    expect(view.getByText("Traceability snapshot · traceability-1")).toBeInTheDocument();
    expect(view.queryByText(/traceabilitySnapshotRef/)).toBeNull();
  });
});
