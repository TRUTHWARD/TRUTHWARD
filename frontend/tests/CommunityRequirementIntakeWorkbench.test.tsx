/* SPDX-License-Identifier: Apache-2.0 */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { RequirementIntakePage } from "../src/pages/RequirementIntakePage";

const timestamp = "2026-09-14T02:30:00Z";
const project = {
  id: "project-1",
  key: "QA",
  name: "QA",
  description: null,
  status: "active",
  metadata: {},
  planCount: 0,
  executionCount: 0,
  environmentCount: 0,
  memberCount: 1,
  createdBy: "admin",
  createdAt: timestamp,
  updatedAt: timestamp,
};
const currentUser = {
  id: "admin",
  name: "Admin",
  email: "admin@example.test",
  roles: ["admin"],
  status: "active",
  edition: "community" as const,
  capabilities: ["requirements.read", "requirements.manage"],
};
const pipeline = {
  orchestrationId: "pipeline-1",
  requirementVersionId: "version-1",
  requirementScope: null,
  planId: null,
  executionId: null,
  status: "running",
  currentStep: "PLAN",
  blocked: false,
  result: {},
  errorMessage: null,
};

function libraryResponse(items: Array<Record<string, unknown>>) {
  return {
    schemaVersion: "phase8.requirement-library.v1",
    generatedAt: timestamp,
    filters: { projectId: null, environmentId: null, requirementVersionId: null, sourceType: null, status: null, keyword: null },
    items,
    total: items.length,
    page: 1,
    pageSize: 100,
    summary: {
      requirementVersionCount: items.filter((item) => item.itemType === "requirement_version").length,
      intakeDraftCount: items.filter((item) => item.itemType === "requirement_intake_draft").length,
      intakePreviewCount: items.filter((item) => item.itemType === "requirement_intake_preview").length,
      requirementItemCount: items.filter((item) => item.itemType === "requirement_item").length,
      returnedCount: items.length,
    },
    capability: { required: "requirements.read", readOnly: true, directMutation: false },
  };
}

function versionItem() {
  return {
    itemId: "requirement-version:version-1",
    itemType: "requirement_version",
    sourceType: "paste",
    status: "active",
    title: "Checkout requirement",
    summary: "Checkout must work",
    projectId: project.id,
    environmentId: null,
    environment: "local",
    sourceRef: "requirements/checkout",
    sourceUri: null,
    requirementVersionId: "version-1",
    linkedRequirementVersionId: "version-1",
    requirementItemId: null,
    requirementItemIndex: null,
    intakeDraftId: null,
    intakePreviewId: null,
    linkedPipelineId: null,
    contentHash: `sha256:${"a".repeat(64)}`,
    requirementCount: 1,
    acceptanceCriteriaCount: 1,
    artifactRefs: [],
    evidenceRefs: [],
    traceId: null,
    createdAt: timestamp,
    updatedAt: timestamp,
    metadata: {},
  };
}

describe("Community requirement intake workbench", () => {
  afterEach(() => window.sessionStorage.clear());

  it("creates an upload batch when files are the only selected source", async () => {
    const batch = {
      batchId: "batch-1",
      name: "需求批次",
      status: "pending",
      summary: { successfulSources: 0, failedSources: 0, confirmedSources: 0 },
      sources: [],
    };
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const data = init?.method === "POST" && url.endsWith("/requirement-intake/batches/uploads")
        ? batch
        : url.includes("/requirement-intake/batches")
          ? { items: [], total: 0, page: 1, pageSize: 20 }
          : libraryResponse([]);
      return new Response(JSON.stringify({ data }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(
      <RequirementIntakePage
        connectorBindings={[]}
        currentUser={currentUser}
        environments={[]}
        locale="zh-CN"
        onPipelineConfirmed={vi.fn(async () => undefined)}
        onViewPipeline={vi.fn()}
        projects={[project]}
      />,
    );

    const file = new File(["需求内容"], "产品文档.txt", { type: "text/plain" });
    const fileInput = screen.getByLabelText("多文件来源");
    const createButton = screen.getByRole("button", { name: "创建批次" });
    expect(screen.queryByLabelText("幂等键")).toBeNull();
    fireEvent.click(createButton);
    await screen.findByText("请至少添加一个粘贴、链接、连接器或文件来源。");
    await waitFor(() => expect(createButton).not.toBeDisabled());

    fireEvent.change(fileInput, { target: { files: [file] } });
    expect(screen.queryByText("请至少添加一个粘贴、链接、连接器或文件来源。")).toBeNull();
    expect(screen.getByText("已选择文件，点击“创建批次”后才会上传。")).toBeTruthy();
    fireEvent.click(createButton);

    await screen.findByText("需求接入批次已创建。");
    expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/requirement-intake/batches/uploads"))).toHaveLength(1);
    const uploadRequest = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/requirement-intake/batches/uploads"));
    expect(uploadRequest?.[1]?.method).toBe("POST");
    expect((uploadRequest?.[1]?.body as FormData).getAll("files")).toEqual([file]);
    const originalKey = (uploadRequest?.[1]?.body as FormData).get("idempotencyKey");
    expect(originalKey).toMatch(/^[\w-]+$/);
    expect(screen.queryByText("请至少添加一个粘贴、链接、连接器或文件来源。")).toBeNull();

    await waitFor(() => expect(createButton).not.toBeDisabled());
    fireEvent.click(createButton);
    await waitFor(() => expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/requirement-intake/batches/uploads"))).toHaveLength(2));
    const uploads = fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/requirement-intake/batches/uploads"));
    expect((uploads[1][1]?.body as FormData).get("idempotencyKey")).toBe(originalKey);

    await waitFor(() => expect(createButton).not.toBeDisabled());
    fireEvent.change(fileInput, { target: { files: [new File(["新内容"], "产品文档.txt", { type: "text/plain" })] } });
    fireEvent.click(createButton);
    await waitFor(() => expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/requirement-intake/batches/uploads"))).toHaveLength(3));
    const changedUpload = fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/requirement-intake/batches/uploads"))[2];
    expect((changedUpload[1]?.body as FormData).get("idempotencyKey")).not.toBe(originalKey);
  });

  it("reports mixed source types before creating an incomplete batch", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const data = String(input).includes("/requirement-intake/batches")
        ? { items: [], total: 0, page: 1, pageSize: 20 }
        : libraryResponse([]);
      return new Response(JSON.stringify({ data }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(
      <RequirementIntakePage
        connectorBindings={[]}
        currentUser={currentUser}
        environments={[]}
        locale="zh-CN"
        onPipelineConfirmed={vi.fn(async () => undefined)}
        onViewPipeline={vi.fn()}
        projects={[project]}
      />,
    );

    fireEvent.change(screen.getByLabelText("多文件来源"), {
      target: { files: [new File(["需求内容"], "产品文档.txt", { type: "text/plain" })] },
    });
    fireEvent.change(screen.getByLabelText("粘贴来源"), { target: { value: "另一条需求" } });
    fireEvent.click(screen.getByRole("button", { name: "创建批次" }));

    await screen.findByText("文件与粘贴、链接或连接器来源需分别创建批次。请清除其中一类来源后重试。");
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
  });

  it("generates a key for text batches and rotates it when the request changes", async () => {
    const batch = {
      batchId: "batch-text-1",
      name: "需求批次",
      status: "pending",
      summary: { successfulSources: 0, failedSources: 0, confirmedSources: 0 },
      sources: [],
    };
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const data = init?.method === "POST" && String(input).endsWith("/requirement-intake/batches")
        ? batch
        : String(input).includes("/requirement-intake/batches")
          ? { items: [], total: 0, page: 1, pageSize: 20 }
          : libraryResponse([]);
      return new Response(JSON.stringify({ data }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(
      <RequirementIntakePage
        connectorBindings={[]}
        currentUser={currentUser}
        environments={[]}
        locale="zh-CN"
        onPipelineConfirmed={vi.fn(async () => undefined)}
        onViewPipeline={vi.fn()}
        projects={[project]}
      />,
    );

    const pasteInput = screen.getByLabelText("粘贴来源");
    const createButton = screen.getByRole("button", { name: "创建批次" });
    fireEvent.change(pasteInput, { target: { value: "需求一" } });
    fireEvent.click(createButton);
    await waitFor(() => expect(fetchMock.mock.calls.filter(([input, init]) => init?.method === "POST" && String(input).endsWith("/requirement-intake/batches"))).toHaveLength(1));
    const requests = fetchMock.mock.calls.filter(([input, init]) => init?.method === "POST" && String(input).endsWith("/requirement-intake/batches"));
    const originalKey = JSON.parse(String(requests[0][1]?.body)).idempotencyKey;
    expect(originalKey).toMatch(/^[\w-]+$/);

    await waitFor(() => expect(createButton).not.toBeDisabled());
    fireEvent.change(pasteInput, { target: { value: "需求二" } });
    fireEvent.click(createButton);
    await waitFor(() => expect(fetchMock.mock.calls.filter(([input, init]) => init?.method === "POST" && String(input).endsWith("/requirement-intake/batches"))).toHaveLength(2));
    const changedRequests = fetchMock.mock.calls.filter(([input, init]) => init?.method === "POST" && String(input).endsWith("/requirement-intake/batches"));
    expect(JSON.parse(String(changedRequests[1][1]?.body)).idempotencyKey).not.toBe(originalKey);
  });

  it("reuses the pending upload key after remounting following a network failure", async () => {
    const batch = {
      batchId: "batch-recovered",
      name: "需求批次",
      status: "pending",
      summary: { successfulSources: 0, failedSources: 0, confirmedSources: 0 },
      sources: [],
    };
    let uploadAttempts = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      let data: unknown;
      if (init?.method === "POST" && String(input).endsWith("/requirement-intake/batches/uploads")) {
        uploadAttempts += 1;
        if (uploadAttempts === 1) throw new TypeError("Network connection lost");
        data = batch;
      } else if (String(input).includes("/requirement-intake/batches")) {
        data = { items: [], total: 0, page: 1, pageSize: 20 };
      } else {
        data = libraryResponse([]);
      }
      return new Response(JSON.stringify({ data }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const props = {
      connectorBindings: [],
      currentUser,
      environments: [],
      locale: "zh-CN" as const,
      onPipelineConfirmed: vi.fn(async () => undefined),
      onViewPipeline: vi.fn(),
      projects: [project],
    };
    const firstRender = render(<RequirementIntakePage {...props} />);
    const firstFile = new File(["需求内容"], "产品文档.txt", { type: "text/plain", lastModified: 1234 });
    fireEvent.change(screen.getByLabelText("多文件来源"), { target: { files: [firstFile] } });
    fireEvent.click(screen.getByRole("button", { name: "创建批次" }));
    await waitFor(() => expect(uploadAttempts).toBe(1));
    await waitFor(() => expect(screen.getByRole("button", { name: "创建批次" })).not.toBeDisabled());
    const firstUpload = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/requirement-intake/batches/uploads"));
    const firstKey = (firstUpload?.[1]?.body as FormData).get("idempotencyKey");
    expect(window.sessionStorage.getItem("truthward.requirement-batch-pending.v1")).toContain(String(firstKey));

    firstRender.unmount();
    render(<RequirementIntakePage {...props} />);
    const sameFile = new File(["需求内容"], "产品文档.txt", { type: "text/plain", lastModified: 1234 });
    fireEvent.change(screen.getByLabelText("多文件来源"), { target: { files: [sameFile] } });
    fireEvent.click(screen.getByRole("button", { name: "创建批次" }));
    await screen.findByText("需求接入批次已创建。");
    const uploads = fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/requirement-intake/batches/uploads"));
    expect((uploads[1][1]?.body as FormData).get("idempotencyKey")).toBe(firstKey);
    expect(window.sessionStorage.getItem("truthward.requirement-batch-pending.v1")).toBeNull();
  });

  it("starts a pipeline directly from a selected existing requirement version", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      let data: unknown;
      if (url.endsWith("/requirements/library/pipelines")) {
        data = pipeline;
      } else if (url.includes("/requirements/library")) {
        data = libraryResponse([versionItem()]);
      } else if (url.includes("/requirement-intake/batches")) {
        data = { items: [], total: 0, page: 1, pageSize: 20 };
      } else {
        data = {};
      }
      return new Response(JSON.stringify({ data }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const onPipelineConfirmed = vi.fn(async () => undefined);
    const onViewPipeline = vi.fn();

    render(
      <RequirementIntakePage
        connectorBindings={[]}
        currentUser={currentUser}
        environments={[]}
        locale="zh-CN"
        onPipelineConfirmed={onPipelineConfirmed}
        onViewPipeline={onViewPipeline}
        projects={[project]}
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "进入 Pipeline" }));

    await waitFor(() => expect(onPipelineConfirmed).toHaveBeenCalledWith(pipeline));
    expect(onViewPipeline).toHaveBeenCalledWith(pipeline.orchestrationId);
    const request = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/requirements/library/pipelines"));
    expect(request?.[1]?.method).toBe("POST");
    expect(JSON.parse(String(request?.[1]?.body))).toMatchObject({
      selectionMode: "requirement_version",
      requirementVersionId: "version-1",
    });
  });
});
