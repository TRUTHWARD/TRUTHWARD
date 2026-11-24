/* SPDX-License-Identifier: Apache-2.0 */
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { JobsPage } from "../src/pages/JobsPage";
import type { JobItem } from "../src/store/platform";

const failedJob: JobItem = {
  id: "435f9f37-5f9c-4292-96bc-6cd5d8ac7e43",
  jobType: "execution.run",
  status: "failed",
  progress: 100,
  payload: {},
  result: {},
  resultRef: null,
  errorMessage: "ZAP authorization scan was not executed because no runnable scanner is configured",
  startedAt: null,
  endedAt: null,
  createdAt: "2026-09-29T00:00:00Z",
  updatedAt: "2026-09-29T00:00:00Z",
};

describe("queue job failure reason", () => {
  afterEach(cleanup);

  it("shows the actionable ZAP cause in both the list and detail", () => {
    render(
      <JobsPage
        locale="zh-CN"
        jobs={[failedJob]}
        selectedJobId={failedJob.id}
        onSelectJob={vi.fn()}
        runtimeReadiness={null}
      />,
    );

    expect(screen.getAllByText(/未配置可运行的 ZAP 扫描器/)).toHaveLength(2);
    expect(screen.getAllByText("失败")).toHaveLength(3);
    expect(screen.queryByText("100%")).not.toBeInTheDocument();
  });
});
