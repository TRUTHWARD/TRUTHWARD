/* SPDX-License-Identifier: Apache-2.0 */
import type { MouseEvent } from "react";
import type { Locale } from "../i18n";
import { t } from "../i18n";


export type EvidenceReferenceLike = {
  type?: unknown;
  ref?: unknown;
  id?: unknown;
  label?: unknown;
  title?: unknown;
  summary?: unknown;
  contentHash?: unknown;
  available?: unknown;
  unavailableReason?: unknown;
  unavailableReasonCode?: unknown;
  href?: unknown;
  redactionStatus?: unknown;
};

type Props = {
  refs: readonly EvidenceReferenceLike[];
  locale: Locale;
  label?: string;
  emptyLabel?: string;
  maxVisible?: number;
};

type PresentedReference = {
  type: string;
  typeLabel: string;
  ref: string;
  identifier: string;
  title: string;
  summary: string;
  contentHash: string | null;
  available: boolean;
  unavailableReason: string | null;
  href: string | null;
  redactionStatus: string | null;
};

const TYPE_LABELS: Record<string, [string, string]> = {
  artifact: ["Artifact", "证据制品"],
  audit_log: ["Audit event", "审计事件"],
  ceg_graph: ["Execution graph", "执行图"],
  ceg_graph_version: ["Execution graph version", "执行图版本"],
  ceg_node: ["Execution graph node", "执行图节点"],
  ceg_path: ["Execution path", "执行路径"],
  change_set: ["Change set", "变更集"],
  coverage_snapshot: ["Coverage snapshot", "覆盖快照"],
  evidence: ["Evidence record", "证据记录"],
  execution: ["Execution", "执行"],
  execution_task: ["Execution task", "执行任务"],
  finding: ["Finding", "问题发现"],
  gate_decision: ["Gate decision", "门禁决策"],
  impact_result: ["Impact result", "影响结果"],
  lesson_candidate: ["Lesson candidate", "经验候选"],
  redacted_diff: ["Redacted diff", "已脱敏差异"],
  regression_plan: ["Regression plan", "回归计划"],
  requirement: ["Requirement", "需求"],
  requirement_source: ["Requirement source", "需求来源"],
  requirement_version: ["Requirement version", "需求版本"],
  selective_replay_plan: ["Selective Replay plan", "选择性回放计划"],
  test: ["Test", "测试"],
  trace: ["Trace", "追踪记录"],
  traceability_snapshot: ["Traceability snapshot", "追溯快照"],
  raw_finding: ["Raw finding", "原始问题"],
  normalized_finding: ["Normalized finding", "归一化问题"],
  approval: ["Approval record", "审批记录"],
  admission_run: ["Admission run", "准入运行"],
  guardrail_event: ["Guardrail event", "护栏事件"],
  log: ["Execution log", "执行日志"],
  policy: ["Policy snapshot", "策略快照"],
  pr_context: ["PR context", "PR 上下文"],
  requirement_match_snapshot: ["Requirement match snapshot", "需求匹配快照"],
  replay: ["Replay record", "回放记录"],
  replay_export: ["Replay export", "回放导出"],
  tool_call: ["Tool call", "工具调用"],
  connector_call: ["Connector call", "连接器调用"],
};

const TYPE_SUMMARIES: Record<string, [string, string]> = {
  artifact: ["Stored output supporting this result.", "用于支撑此结果的已存储输出。"],
  ceg_graph_version: ["Frozen graph version used by this analysis.", "本次分析使用的冻结执行图版本。"],
  ceg_node: ["Graph observation supporting this affected item.", "用于支撑此受影响项的图观察。"],
  change_set: ["Persisted input changes used by this analysis.", "本次分析使用的已持久化输入变更。"],
  coverage_snapshot: ["Coverage facts used when calculating this result.", "计算此结果时使用的覆盖事实。"],
  evidence: ["Persisted evidence linked to this conclusion.", "与此结论关联的已持久化证据。"],
  execution_task: ["Execution task whose observed result supports this selection.", "其观测结果支撑本次选择的执行任务。"],
  regression_plan: ["Existing regression plan used as the conservative baseline.", "作为保守基线使用的现有回归计划。"],
  redacted_diff: ["Sanitized source changes stored as supporting evidence.", "作为支撑证据存储的已脱敏源码变更。"],
  requirement_version: ["Frozen requirement version used as a traceable input.", "作为可追溯输入使用的冻结需求版本。"],
  traceability_snapshot: ["Frozen relationships used to build this proof.", "生成此证明时使用的冻结追溯关系。"],
  normalized_finding: ["Normalized issue linked through the proof chain.", "通过证明链关联的归一化问题。"],
  admission_run: ["Admission run that gathered and evaluated this evidence.", "收集并评估此证据的准入运行。"],
  guardrail_event: ["Guardrail evaluation recorded for this run.", "本次运行记录的护栏评估。"],
  log: ["Sanitized execution log stored as supporting evidence.", "作为支撑证据存储的已脱敏执行日志。"],
  requirement_match_snapshot: ["Frozen requirement matching input for this run.", "本次运行使用的冻结需求匹配输入。"],
};

export function EvidenceReferenceList({ refs, locale, label, emptyLabel, maxVisible = 3 }: Props) {
  const items = refs.map((item) => presentEvidenceReference(item, locale));
  const visible = items.slice(0, maxVisible);
  const remaining = items.slice(maxVisible);

  return (
    <section className="evidence-reference-list" aria-label={label ?? t(locale, "evidenceRefs")}>
      {label ? <div className="evidence-reference-list__header"><strong>{label}</strong><span>{items.length}</span></div> : null}
      {items.length === 0 ? <p className="muted-text">{emptyLabel ?? t(locale, "none")}</p> : (
        <>
          <ul>{visible.map((item, index) => <EvidenceReferenceCard item={item} key={`${item.ref}:${index}`} locale={locale} />)}</ul>
          {remaining.length ? (
            <details className="evidence-reference-list__more">
              <summary>{formatShowMore(locale, remaining.length)}</summary>
              <ul>{remaining.map((item, index) => <EvidenceReferenceCard item={item} key={`${item.ref}:more:${index}`} locale={locale} />)}</ul>
            </details>
          ) : null}
        </>
      )}
    </section>
  );
}

function EvidenceReferenceCard({ item, locale }: { item: PresentedReference; locale: Locale }) {
  return (
    <li className={`evidence-reference-card${item.available ? "" : " evidence-reference-card--unavailable"}`}>
      <div className="evidence-reference-card__heading">
        <div>
          <span className="eyebrow">{item.typeLabel}</span>
          <strong>{item.title}</strong>
        </div>
        <code title={item.identifier}>{shortIdentifier(item.identifier)}</code>
      </div>
      <p>{item.available ? item.summary : item.unavailableReason ?? t(locale, "evidenceCitationUnavailable")}</p>
      <div className="evidence-reference-card__actions">
        {item.href && item.available ? <a aria-label={`${t(locale, "viewDetails")}: ${item.typeLabel} ${item.identifier}`} className="link-button" href={item.href} onClick={navigateWithinWorkspace}>{t(locale, "viewDetails")}</a> : <span>{t(locale, "evidencePreviewUnavailable")}</span>}
        <details>
          <summary>{t(locale, "evidenceReferenceMetadata")}</summary>
          <dl>
            <div><dt>{t(locale, "evidenceReferenceType")}</dt><dd>{item.type}</dd></div>
            <div><dt>{t(locale, "reference")}</dt><dd><code>{item.ref}</code></dd></div>
            {item.contentHash ? <div><dt>{t(locale, "evidenceContentHash")}</dt><dd><code>{item.contentHash}</code></dd></div> : null}
            {item.redactionStatus ? <div><dt>{t(locale, "status")}</dt><dd>{item.redactionStatus}</dd></div> : null}
          </dl>
        </details>
      </div>
    </li>
  );
}

function navigateWithinWorkspace(event: MouseEvent<HTMLAnchorElement>) {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.currentTarget.target === "_blank") return;
  const destination = new URL(event.currentTarget.href);
  if (destination.origin !== window.location.origin || destination.pathname === window.location.pathname) return;
  event.preventDefault();
  window.history.pushState(null, "", destination.pathname + destination.search + destination.hash);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function presentEvidenceReference(value: EvidenceReferenceLike, locale: Locale): PresentedReference {
  const ref = textValue(value.ref) || textValue(value.id) || "unknown";
  const parsed = parseReference(ref);
  const type = normalizeType(textValue(value.type) || parsed.scheme || "evidence");
  const typeLabel = typeLabelFor(locale, type);
  const identifier = parsed.identifier || ref;
  const explicitTitle = textValue(value.title) || textValue(value.label);
  const available = value.available !== false;
  const explicitUnavailableReason = textValue(value.unavailableReason) || textValue(value.unavailableReasonCode);

  return {
    type,
    typeLabel,
    ref,
    identifier,
    title: explicitTitle || `${typeLabel} · ${shortIdentifier(identifier)}`,
    summary: textValue(value.summary) || summaryFor(locale, type),
    contentHash: textValue(value.contentHash) || null,
    available,
    unavailableReason: explicitUnavailableReason || null,
    href: safeDetailHref(textValue(value.href)) ?? derivedDetailHref(type, identifier),
    redactionStatus: textValue(value.redactionStatus) || null,
  };
}

function parseReference(ref: string) {
  const match = ref.match(/^([a-z][a-z0-9+._-]*):\/\/(.+)$/i);
  return match ? { scheme: match[1], identifier: match[2] } : { scheme: "", identifier: ref };
}

function normalizeType(value: string) {
  const normalized = value.trim().toLowerCase().replaceAll("-", "_").replaceAll(" ", "_");
  const aliases: Record<string, string> = {
    code_change_set: "change_set",
    requirement_match: "requirement_match_snapshot",
  };
  return aliases[normalized] ?? normalized;
}

function typeLabelFor(locale: Locale, type: string) {
  const label = TYPE_LABELS[type];
  if (label) return locale === "zh-CN" ? label[1] : label[0];
  return humanize(type);
}

function summaryFor(locale: Locale, type: string) {
  const summary = TYPE_SUMMARIES[type];
  if (summary) return locale === "zh-CN" ? summary[1] : summary[0];
  return locale === "zh-CN" ? "与当前结果关联的只读追溯引用。" : "Read-only traceability reference linked to this result.";
}

function derivedDetailHref(type: string, identifier: string) {
  const routes: Record<string, [string, string]> = {
    change_set: ["/change-sets", "changeSetId"],
    execution: ["/executions", "executionId"],
    impact_result: ["/impact-analysis", "impactResultId"],
    admission_run: ["/admission-runs", "admissionRunId"],
    pr_context: ["/pr-contexts", "prContextId"],
    selective_replay_plan: ["/selective-replay-plans", "planId"],
  };
  const route = routes[type];
  if (!route || identifier === "unknown") return null;
  return `${route[0]}?${route[1]}=${encodeURIComponent(identifier)}`;
}

function safeDetailHref(value: string) {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.includes("\\") || hasControlCharacter(value)) return null;
  return value;
}

function shortIdentifier(value: string) {
  if (value.length <= 28) return value;
  return `${value.slice(0, 12)}…${value.slice(-8)}`;
}

function humanize(value: string) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function textValue(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

function hasControlCharacter(value: string) {
  return [...value].some((character) => character.charCodeAt(0) < 32);
}

function formatShowMore(locale: Locale, count: number) {
  return locale === "zh-CN" ? `查看其余 ${count} 条证据` : `Show ${count} more evidence reference${count === 1 ? "" : "s"}`;
}
