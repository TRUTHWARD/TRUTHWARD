/* SPDX-License-Identifier: Apache-2.0 */
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { EvidenceReferenceList } from "../src/components/EvidenceReferenceList";


describe("EvidenceReferenceList", () => {
  it("presents stable references as readable cards and keeps the raw URI in technical details", () => {
    const view = render(<EvidenceReferenceList locale="zh-CN" refs={[{
      type: "requirement_version",
      ref: "requirement_version://23e3bf3a-42f1-429c-972d-ca256d12fe10",
      contentHash: `sha256:${"a".repeat(64)}`,
    }]} />);

    expect(view.getByText("需求版本 · 23e3bf3a-42f…6d12fe10")).toBeInTheDocument();
    expect(view.getByText("作为可追溯输入使用的冻结需求版本。")).toBeInTheDocument();
    expect(view.getByText("requirement_version://23e3bf3a-42f1-429c-972d-ca256d12fe10").closest("details")).not.toBeNull();
  });

  it("creates only controlled local detail links", () => {
    const linked = render(<EvidenceReferenceList locale="en-US" refs={[{ type: "change_set", ref: "change-set://change-1" }]} />);
    expect(linked.getByRole("link", { name: /View details: Change set change-1/ })).toHaveAttribute("href", "/change-sets?changeSetId=change-1");
    linked.unmount();

    const unsafe = render(<EvidenceReferenceList locale="en-US" refs={[{ type: "evidence", ref: "evidence://1", href: "https://example.test/raw" }]} />);
    expect(unsafe.queryByRole("link", { name: "View details" })).toBeNull();
  });

  it("uses safe projection labels, summaries and availability when supplied", () => {
    const view = render(<EvidenceReferenceList locale="en-US" refs={[{
      type: "artifact",
      ref: "artifact://redacted/1",
      title: "Sanitized browser screenshot",
      summary: "Checkout confirmation after the test action.",
      available: false,
      unavailableReasonCode: "retention_expired",
      href: "/artifacts/1",
    }]} />);

    expect(view.getByText("Sanitized browser screenshot")).toBeInTheDocument();
    expect(view.getByText("retention_expired")).toBeInTheDocument();
    expect(view.queryByRole("link", { name: "View details" })).toBeNull();
  });
});
