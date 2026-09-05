/* SPDX-License-Identifier: Apache-2.0 */
import { access, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";

const requireFromFrontend = createRequire(new URL("../../frontend/package.json", import.meta.url));
const { chromium } = requireFromFrontend("playwright");
const playwrightPackage = requireFromFrontend("playwright/package.json");
const playwrightBrowsersPath = process.env.PLAYWRIGHT_BROWSERS_PATH
  ? path.resolve(process.env.PLAYWRIGHT_BROWSERS_PATH)
  : null;

const args = parseArgs(process.argv.slice(2));
const inputPath = path.resolve(requireArg("input"));
const artifactDir = path.resolve(requireArg("artifact-dir"));
const reportPath = path.resolve(requireArg("report"));
const request = JSON.parse(await readFile(inputPath, "utf8"));
const valueBindings = parseValueBindings();
const redactionValues = Object.values(valueBindings).filter((value) => value.length > 0);
const prefix = request.mode === "capture" ? "visual" : "execution";

const screenshotPath = path.join(artifactDir, `${prefix}-screenshot.png`);
const domSnapshotPath = path.join(artifactDir, `${prefix}-dom-snapshot.json`);
const accessibilityTreePath = path.join(artifactDir, `${prefix}-accessibility-tree.json`);
const harPath = path.join(artifactDir, `${prefix}-network.har`);
const videoDir = path.join(artifactDir, `${prefix}-video`);
const videoPath = path.join(artifactDir, `${prefix}-video.webm`);
const tracePaths = [];
const actionResults = [];
const artifacts = [];
let failure = null;
let failureKind = null;
let browser = null;
let context = null;
let page = null;
let tracingActive = false;
let traceSequence = 0;
let exitCode = 0;

await mkdir(artifactDir, { recursive: true });
await mkdir(videoDir, { recursive: true });

try {
  const executablePath = chromium.executablePath();
  await access(executablePath, fsConstants.X_OK);
  browser = await chromium.launch({
    executablePath,
    headless: true,
  });
  context = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    recordHar: {
      path: harPath,
      content: "omit",
      mode: "minimal",
    },
    recordVideo: {
      dir: videoDir,
      size: { width: 1280, height: 720 },
    },
  });
  await startTracing();
  page = await context.newPage();
  page.setDefaultTimeout(normalizedTimeout(request.actionTimeoutMs, 5000));
  page.setDefaultNavigationTimeout(normalizedTimeout(request.navigationTimeoutMs, 5000));

  if (request.targetUrl) {
    await page.goto(String(request.targetUrl), {
      waitUntil: "domcontentloaded",
      timeout: normalizedTimeout(request.navigationTimeoutMs, 5000),
    });
    await installVisualRedaction(page);
  }

  if (request.mode === "execute") {
    const semanticActions = Array.isArray(request.semanticActions) ? request.semanticActions : [];
    for (const action of semanticActions) {
      await executeSemanticAction(page, action);
    }
  }
} catch (error) {
  failure = sanitizeText(error instanceof Error ? error.message : String(error));
  failureKind = classifyFailure(error);
  exitCode = failureKind === "timeout" ? 124 : failureKind === "verification_failure" ? 2 : 1;
} finally {
  if (page && !page.isClosed()) {
    await capturePageEvidence(page).catch((error) => {
      failure ??= sanitizeText(error instanceof Error ? error.message : String(error));
      failureKind ??= classifyFailure(error);
      exitCode ||= 1;
    });
  }
  await stopTracing().catch((error) => {
    failure ??= sanitizeText(error instanceof Error ? error.message : String(error));
    failureKind ??= "tool_error";
    exitCode ||= 1;
  });

  let recordedVideoPath = null;
  if (page && !page.isClosed()) {
    recordedVideoPath = await page.video()?.path().catch(() => null);
  }
  if (context) {
    await context.close().catch((error) => {
      failure ??= sanitizeText(error instanceof Error ? error.message : String(error));
      failureKind ??= "tool_error";
      exitCode ||= 1;
    });
  }
  if (recordedVideoPath) {
    await rename(recordedVideoPath, videoPath).catch(() => undefined);
  }
  if (browser) {
    await browser.close().catch(() => undefined);
  }
}

await redactJsonFile(harPath);
await collectArtifacts();

const executablePath = chromium.executablePath();
const browserVersion = browser?.version?.() ?? inferBrowserVersion(executablePath);
const report = {
  schemaVersion: "tst-p1-020.playwright-actual-report.v1",
  status: exitCode === 0 ? "passed" : failureKind === "verification_failure" ? "verification_failed" : "failed",
  failureKind,
  failure,
  actualExecution: true,
  executionMode: "actual",
  validationClass: "named_tool_actual",
  namedTool: "playwright",
  namedToolExecuted: true,
  customCommandExecuted: false,
  browser: {
    name: "chromium",
    version: browserVersion,
    executablePath,
    revision: browserRevision(executablePath),
    pinned: playwrightBrowsersPath
      ? executablePath.startsWith(`${playwrightBrowsersPath}${path.sep}`)
      : executablePath.includes(`${path.sep}.ms-playwright${path.sep}`),
  },
  playwrightVersion: playwrightPackage.version,
  targetOrigin: safeOrigin(request.targetUrl),
  actionResults,
  artifactCount: artifacts.length,
  artifacts,
};
await writeFile(reportPath, JSON.stringify(report, null, 2), "utf8");
process.stdout.write(
  JSON.stringify({
    status: report.status,
    actualExecution: true,
    namedTool: report.namedTool,
    playwrightVersion: report.playwrightVersion,
    browser: report.browser,
    artifactCount: report.artifactCount,
  }),
);
process.exitCode = exitCode;

function parseArgs(rawArgs) {
  const parsed = {};
  for (let index = 0; index < rawArgs.length; index += 2) {
    const key = rawArgs[index]?.replace(/^--/, "");
    const value = rawArgs[index + 1];
    if (key && value) {
      parsed[key] = value;
    }
  }
  return parsed;
}

function requireArg(name) {
  const value = args[name];
  if (!value) {
    throw new Error(`Missing required argument --${name}`);
  }
  return value;
}

function parseValueBindings() {
  const raw = process.env.AGENTIC_QA_PLAYWRIGHT_VALUE_BINDINGS_JSON ?? "{}";
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("value bindings must be a JSON object");
  }
  return Object.fromEntries(
    Object.entries(parsed).map(([key, value]) => [String(key), String(value)]),
  );
}

function normalizedTimeout(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

async function startTracing() {
  if (!context || tracingActive) {
    return;
  }
  await context.tracing.start({ screenshots: true, snapshots: true, sources: false });
  tracingActive = true;
}

async function stopTracing() {
  if (!context || !tracingActive) {
    return;
  }
  traceSequence += 1;
  const tracePath = path.join(
    artifactDir,
    `${prefix}-trace-${String(traceSequence).padStart(2, "0")}.zip`,
  );
  await context.tracing.stop({ path: tracePath });
  tracePaths.push(tracePath);
  tracingActive = false;
}

async function executeSemanticAction(activePage, action) {
  const actionId = String(action?.actionId ?? `action-${actionResults.length + 1}`);
  const actionType = String(action?.actionType ?? "");
  const startedAt = new Date().toISOString();
  try {
    if (actionType === "navigate") {
      const targetUrl =
        action?.semanticTarget?.url ??
        action?.targetHints?.url ??
        request.targetUrl;
      if (!targetUrl) {
        throw policyError("navigate requires semanticTarget.url, targetHints.url, or targetUrl");
      }
      await activePage.goto(String(targetUrl), {
        waitUntil: "domcontentloaded",
        timeout: normalizedTimeout(request.navigationTimeoutMs, 5000),
      });
      await installVisualRedaction(activePage);
    } else if (actionType === "fill") {
      const ref = action?.valueRef ?? action?.secretRef;
      if (!ref || Object.prototype.hasOwnProperty.call(action ?? {}, "value")) {
        throw policyError("fill requires valueRef or secretRef and forbids inline value");
      }
      if (!Object.prototype.hasOwnProperty.call(valueBindings, String(ref))) {
        throw policyError(`fill reference is unresolved: ${String(ref)}`);
      }
      await stopTracing();
      await installVisualRedaction(activePage);
      await locatorFor(activePage, action).fill(valueBindings[String(ref)]);
    } else if (actionType === "click") {
      rejectCoordinateClick(action);
      await locatorFor(activePage, action).click();
      if (!tracingActive && (await pageInputsAreClear(activePage))) {
        await startTracing();
      }
    } else if (actionType === "assert_visible") {
      await locatorFor(activePage, action).waitFor({
        state: "visible",
        timeout: normalizedTimeout(request.actionTimeoutMs, 5000),
      });
    } else if (actionType === "assert_text") {
      const locator = locatorFor(activePage, action);
      const expected = String(
        action?.assertionIntent?.expectedText ??
          action?.assertionIntent?.text ??
          action?.assertionIntent?.expected ??
          "",
      );
      if (!expected) {
        throw policyError("assert_text requires assertionIntent.expectedText");
      }
      await locator.waitFor({
        state: "visible",
        timeout: normalizedTimeout(request.actionTimeoutMs, 5000),
      });
      const actual = String((await locator.textContent()) ?? "");
      const exact = action?.assertionIntent?.match === "exact";
      const matched = exact ? actual.trim() === expected : actual.includes(expected);
      if (!matched) {
        throw verificationError(
          `assert_text did not match for action ${actionId}; expected text was not present`,
        );
      }
    } else {
      throw policyError(`unsupported SemanticAction actionType: ${actionType}`);
    }
    actionResults.push({
      actionId,
      actionType,
      status: "passed",
      startedAt,
      endedAt: new Date().toISOString(),
      verification: actionType.startsWith("assert_") ? "passed" : "not_applicable",
    });
  } catch (error) {
    actionResults.push({
      actionId,
      actionType,
      status: "failed",
      startedAt,
      endedAt: new Date().toISOString(),
      verification: actionType.startsWith("assert_") ? "failed" : "not_applicable",
      error: sanitizeText(error instanceof Error ? error.message : String(error)),
    });
    throw error;
  }
}

function locatorFor(activePage, action) {
  const hints = action?.targetHints ?? {};
  const target = action?.semanticTarget ?? {};
  if (hints.selector || hints.css) {
    return activePage.locator(String(hints.selector ?? hints.css)).first();
  }
  if (hints.testId) {
    return activePage.getByTestId(String(hints.testId)).first();
  }
  if (target.role && target.name) {
    return activePage.getByRole(String(target.role), { name: String(target.name) }).first();
  }
  if (hints.text || target.name) {
    return activePage.getByText(String(hints.text ?? target.name), { exact: false }).first();
  }
  throw policyError("SemanticAction requires a DOM/accessibility target; free coordinates are forbidden");
}

function rejectCoordinateClick(action) {
  const hints = action?.targetHints ?? {};
  if (
    hints.coordinate ||
    hints.boundingBox ||
    action?.locatorStrategy?.primary === "coordinate" ||
    action?.locatorStrategy?.primary === "screen_coordinate"
  ) {
    throw policyError(
      "coordinate click requires execution-service authorization, evidence, and post-action verification",
    );
  }
}

async function installVisualRedaction(activePage) {
  await activePage
    .addStyleTag({
      content:
        "input,textarea{color:transparent!important;text-shadow:0 0 8px #111!important;-webkit-text-security:disc!important}",
    })
    .catch(() => undefined);
}

async function pageInputsAreClear(activePage) {
  return activePage
    .locator("input,textarea")
    .evaluateAll((nodes) => nodes.every((node) => !("value" in node) || node.value === ""))
    .catch(() => false);
}

async function capturePageEvidence(activePage) {
  await installVisualRedaction(activePage);
  await activePage.screenshot({ path: screenshotPath, fullPage: true });
  const domSnapshot = await activePage.evaluate(() => {
    const nodes = Array.from(
      document.querySelectorAll(
        "html,body,main,form,input,textarea,button,[role],[data-testid],h1,h2,h3,p,label",
      ),
    ).slice(0, 500);
    return {
      url: location.href,
      title: document.title,
      nodes: nodes.map((node) => ({
        tag: node.tagName.toLowerCase(),
        id: node.id || null,
        role: node.getAttribute("role"),
        name:
          node.getAttribute("aria-label") ??
          node.getAttribute("name") ??
          node.getAttribute("data-testid"),
        testId: node.getAttribute("data-testid"),
        type: node.getAttribute("type"),
        text:
          node instanceof HTMLInputElement || node instanceof HTMLTextAreaElement
            ? "[REDACTED]"
            : (node.textContent ?? "").replace(/\s+/g, " ").trim().slice(0, 300),
        visible: Boolean(node.getClientRects().length),
      })),
      redaction: { status: "redacted", inputValues: "removed" },
    };
  });
  await writeFile(
    domSnapshotPath,
    JSON.stringify(sanitizeValue(domSnapshot), null, 2),
    "utf8",
  );

  const cdp = await context.newCDPSession(activePage);
  await cdp.send("Accessibility.enable");
  const accessibilityTree = await cdp.send("Accessibility.getFullAXTree");
  await cdp.detach();
  await writeFile(
    accessibilityTreePath,
    JSON.stringify(
      {
        ...sanitizeValue(accessibilityTree),
        redaction: { status: "redacted", values: "removed" },
      },
      null,
      2,
    ),
    "utf8",
  );
}

async function collectArtifacts() {
  const candidates = [
    {
      artifactType: "screenshot",
      path: screenshotPath,
      summary: "redacted Playwright screenshot from actual Chromium execution",
    },
    {
      artifactType: "dom_snapshot",
      path: domSnapshotPath,
      summary: "redacted DOM snapshot from actual Chromium execution",
    },
    {
      artifactType: "accessibility_tree",
      path: accessibilityTreePath,
      summary: "redacted Chromium accessibility tree",
    },
    {
      artifactType: "har",
      path: harPath,
      summary: "redacted Playwright HAR from actual Chromium execution",
    },
    {
      artifactType: "video",
      path: videoPath,
      summary: "redacted Playwright video from actual Chromium execution",
    },
    ...tracePaths.map((tracePath) => ({
      artifactType: "trace",
      path: tracePath,
      summary: "Playwright trace from actual Chromium execution",
    })),
  ];
  for (const candidate of candidates) {
    if (await fileExists(candidate.path)) {
      const file = await readFile(candidate.path);
      if (file.length > 0) {
        artifacts.push({
          ...candidate,
          byteSize: file.length,
          redactionStatus: "redacted",
        });
      }
    }
  }
}

async function redactJsonFile(filePath) {
  if (!(await fileExists(filePath))) {
    return;
  }
  const raw = await readFile(filePath, "utf8");
  await writeFile(filePath, sanitizeText(raw), "utf8");
}

async function fileExists(filePath) {
  try {
    await access(filePath, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function sanitizeValue(value) {
  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => {
        if (["value", "inputValue", "postData", "textValue"].includes(key)) {
          return [key, "[REDACTED]"];
        }
        return [key, sanitizeValue(nested)];
      }),
    );
  }
  return typeof value === "string" ? sanitizeText(value) : value;
}

function sanitizeText(value) {
  let output = String(value);
  for (const sensitiveValue of redactionValues) {
    output = output.split(sensitiveValue).join("[REDACTED]");
    output = output
      .split(encodeURIComponent(sensitiveValue))
      .join("[REDACTED]");
  }
  return output;
}

function classifyFailure(error) {
  if (error?.kind === "verification_failure") {
    return "verification_failure";
  }
  if (error?.kind === "policy_error") {
    return "policy_error";
  }
  if (
    error?.name === "TimeoutError" ||
    /timeout|timed out|exceeded/i.test(String(error?.message ?? error))
  ) {
    return "timeout";
  }
  return "tool_error";
}

function verificationError(message) {
  const error = new Error(message);
  error.kind = "verification_failure";
  return error;
}

function policyError(message) {
  const error = new Error(message);
  error.kind = "policy_error";
  return error;
}

function browserRevision(executablePath) {
  return /chromium-(\d+)/i.exec(executablePath)?.[1] ?? null;
}

function inferBrowserVersion(executablePath) {
  return path.basename(path.dirname(executablePath));
}

function safeOrigin(value) {
  if (!value) {
    return null;
  }
  try {
    return new URL(String(value)).origin;
  } catch {
    return null;
  }
}
