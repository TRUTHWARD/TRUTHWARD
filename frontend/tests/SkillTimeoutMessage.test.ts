/* SPDX-License-Identifier: Apache-2.0 */
import { describe, expect, it } from "vitest";

import { userFacingError } from "../src/i18n";

describe("persisted task timeout reason", () => {
  it("shows the task timeout instead of a generic workflow failure", () => {
    expect(userFacingError("zh-CN", new Error("SKILL_ADAPTER_TIMEOUT"), "workflowActionFailed"))
      .toContain("超过允许时间");
    expect(userFacingError("en-US", new Error("SKILL_ADAPTER_TIMEOUT"), "workflowActionFailed"))
      .toContain("allowed time");
  });
});
