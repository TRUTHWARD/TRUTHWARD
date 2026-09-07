/* SPDX-License-Identifier: Apache-2.0 */
import type { Locale } from "../i18n";
import type { RuntimeReadinessCategory, RuntimeReadinessItem } from "./api";

const zhStatusLabels: Record<string, string> = {
  active: "活跃",
  allow: "允许",
  allowed: "允许",
  always: "始终",
  approved: "已批准",
  archived: "已归档",
  available: "可用",
  basic: "基础版",
  blocked: "阻断",
  cancelled: "已取消",
  completed: "已完成",
  complete: "已完成",
  current: "当前",
  degraded: "降级",
  denied: "已拒绝",
  deprecated: "已弃用",
  disabled: "已禁用",
  domain: "测试域",
  draft: "草稿",
  enterprise: "企业版",
  environment: "环境",
  failed: "失败",
  fail: "失败",
  generated: "已生成",
  granted: "已授权",
  governed: "受治理",
  global: "全局",
  healthy: "健康",
  high: "高",
  info: "信息",
  invalid: "无效",
  local_passed: "本地已通过",
  low: "低",
  medium: "中",
  not_applicable: "不适用",
  not_required: "无需执行",
  ok: "正常",
  partial: "部分完成",
  pass: "通过",
  passed: "通过",
  pending: "待处理",
  planned: "已规划",
  project: "项目",
  queued: "排队中",
  read_only: "只读",
  recommended: "建议执行",
  recorded: "已记录",
  redacted: "已脱敏",
  running: "运行中",
  stale: "已过期",
  stage: "阶段",
  unavailable: "不可用",
  unknown: "未知",
  urgent: "紧急",
  valid: "有效",
  warn: "警告",
  warning: "警告",
  workspace: "工作区",
};

const enStatusLabels: Record<string, string> = {
  not_applicable: "Not applicable",
  not_required: "Not required",
  read_only: "Read only",
  local_passed: "Locally passed",
};

const zhStageLabels: Record<string, string> = {
  requirement: "需求",
  plan: "计划",
  approval: "审批",
  execution: "执行",
  exploratory: "探索性测试",
  regression: "回归范围",
  gate: "门禁",
  replay: "回放",
  prepare: "准备",
  execute: "执行",
  observe: "观测",
  analyze: "分析",
  normalize: "归一化",
};

const zhStrategyLabels: Record<string, string> = {
  automated: "自动化执行",
  manual_simulation: "人工模拟",
  exploratory: "探索性测试",
  regression: "回归测试",
};

const zhDomainLabels: Record<string, string> = {
  functional: "功能",
  performance: "性能",
  security: "安全",
};

const zhArtifactLabels: Record<string, string> = {
  trace: "追踪记录",
  screenshot: "截图",
  logs: "日志",
  log: "日志",
};

const zhRemediationLabels: Record<string, string> = {
  locator_fix: "定位器修复",
  patch_proposal: "补丁建议",
  retry: "重试建议",
};

const zhMetricLabels: Record<string, string> = {
  "coverage rate": "覆盖率",
  "execution success rate": "执行成功率",
  "replay success rate": "回放成功率",
  "task success rate": "任务成功率",
  "agent success rate": "Agent 成功率",
  "skill success rate": "Skill 成功率",
  "model success rate": "模型成功率",
  "evidence link rate": "证据关联率",
  "model cost total": "模型总成本",
  "model latency p95": "模型延迟 P95",
  "gate pass rate": "门禁通过率",
  "memory hit rate": "记忆命中率",
  "agent loop rate": "Agent 循环率",
  "hallucination rate": "幻觉率",
};

const zhActionLabels: Record<string, string> = {
  "answer-clarification": "回答澄清问题",
  "review-approval": "复核审批",
  "open-requirement": "打开需求",
  "open-plan": "打开计划",
  "open-execution": "打开执行",
  "open-regression": "打开回归范围",
  "open-exploratory": "打开探索性测试会话",
  "create-or-link-exploratory": "创建或关联探索性测试",
  "open-gate": "打开门禁决策",
  "open-replay": "打开回放",
};

const zhReasonCodeLabels: Record<string, string> = {
  approval_required: "需要审批",
  available_from_main_flow: "可从主流程进入",
  execution_service_recommendation: "执行服务建议",
  completed: "已完成",
  no_execution: "尚无执行",
  no_plan: "尚无计划",
  pending: "待处理",
};

const zhFindingTitles: Record<string, string> = {
  "missing authorization check": "缺少授权检查",
};

const zhSignalLabels: Record<string, string> = {
  "task success rate": "任务成功率",
  "model success rate": "模型成功率",
  "gate pass rate": "门禁通过率",
  "memory hit rate": "记忆命中率",
  "agent loop rate": "Agent 循环率",
  "hallucination rate": "幻觉率",
};

const zhRuntimeCategoryLabels: Record<string, string> = {
  "queue-runtime": "Celery / Redis Worker 运行时",
  "storage-profile": "回放仓库存储配置",
  "connector-actual-validation": "Connector 实际验证",
  "migration-schema-static-checks": "迁移、Schema 与静态检查",
  "operational-hardening": "P27 运行安全加固",
};

const zhRuntimeItemLabels: Record<string, string> = {
  "celery-task-registration": "Celery 任务注册",
  "redis-worker-lifecycle": "Redis / Celery Worker 生命周期",
  "worker-backed-execution-smoke": "Worker 执行链路冒烟验证",
  "replay-storage-profile": "回放仓库存储配置",
  "external-storage-actual-validation": "外部存储实际验证",
  "github-connector-actual-validation": "GitHub Connector 实际验证",
  "issue-tracker-actual-validation": "Jira / 禅道实际验证",
  "migration-ledger": "数据库迁移账本可重复性",
  "static-check-entrypoints": "静态检查入口",
  "http-protection-contract": "HTTP 限制、超时与错误契约",
  "operational-metrics-alerts": "运行指标与去重告警投影",
  "controlled-autonomy-operational-guard": "受控自治开关与安全阈值",
};

const zhRuntimeSummaries: Record<string, string> = {
  "celery-task-registration:local_passed": "必需的队列任务均已注册。",
  "celery-task-registration:missing_dependency": "缺少必需的队列任务。",
  "redis-worker-lifecycle:local_passed": "当前队列模式的运行时要求已满足。",
  "redis-worker-lifecycle:deployment_specific_not_validated": "Redis 可访问；完整 Worker 生命周期仍需按部署环境验证。",
  "redis-worker-lifecycle:missing_dependency": "Redis 不可访问，Celery Worker 无法完成运行时验证。",
  "worker-backed-execution-smoke:local_passed": "已通过队列、任务输出、归一化、门禁和回放导出完成执行冒烟验证。",
  "worker-backed-execution-smoke:deployment_specific_not_validated": "当前运行环境尚未完成 Worker 执行链路冒烟验证。",
  "worker-backed-execution-smoke:missing_dependency": "缺少运行 Worker 执行链路冒烟验证所需的依赖。",
  "worker-backed-execution-smoke:unavailable": "Worker 执行链路冒烟验证失败。",
  "replay-storage-profile:local_passed": "当前 StorageAdapter 配置受支持。",
  "replay-storage-profile:missing_dependency": "当前 StorageAdapter 配置不受支持。",
  "external-storage-actual-validation:deployment_specific_not_validated": "外部对象存储实际验证需要显式启用，当前运行环境尚未执行。",
  "external-storage-actual-validation:missing_dependency": "已请求外部对象存储验证，但缺少或无法验证所需的引用配置。",
  "github-connector-actual-validation:deployment_specific_not_validated": "GitHub 实际验证需要显式启用，当前运行环境尚未执行。",
  "github-connector-actual-validation:missing_dependency": "已请求 GitHub 实际验证，但缺少所需的运行时配置。",
  "issue-tracker-actual-validation:deployment_specific_not_validated": "Issue Tracker 已完成本地契约或 Mock 验证；真实 Provider 仍需按部署环境验证。",
  "migration-ledger:local_passed": "数据库迁移账本与预期迁移保持一致。",
  "static-check-entrypoints:deployment_specific_not_validated": "静态检查入口均存在；当前就绪度投影不会代替 CI/CD 实际执行。",
  "http-protection-contract:local_passed": "已配置进程内请求大小、频率、超时和稳定错误响应保护。",
  "operational-metrics-alerts:local_passed": "聚合指标不包含请求正文、响应正文或凭据材料。",
  "controlled-autonomy-operational-guard:local_passed": "全局与范围开关、事务数量上限及回滚率自动暂停约束已启用。",
};

const zhExtensionPointLabels: Record<string, string> = {
  "PREPARE.test_plan": "测试计划生成",
  "PREPARE.test_case": "测试用例生成",
  "PREPARE.exploratory_charter": "探索性测试章程",
  "PREPARE.regression_scope": "回归范围规划",
  "EXECUTE.automated_execution": "自动化执行",
  "EXECUTE.manual_simulation": "人工模拟",
  "EXECUTE.exploratory_assist": "探索性测试辅助",
  OBSERVE: "执行观测",
  "OBSERVE.observation": "执行观测",
  "ANALYZE.finding_triage": "问题归因",
  "ANALYZE.performance_analysis": "性能分析",
  "ANALYZE.security_analysis": "安全分析",
  NORMALIZE: "问题归一化",
  "GATE.decision_write": "门禁决策写入",
  "Memory promotion": "记忆提升",
  "Approval decision": "审批决策",
  "Provider routing": "模型供应商路由",
  "Visual Grounding": "视觉定位",
};

const zhUnavailableReasons: Record<string, string> = {
  "execution-owned observation": "由执行服务托管",
  "service-owned canonicalization": "由服务托管归一化",
  "service-owned governance decision": "由服务托管治理决策",
  "memory promotion rules": "记忆提升规则",
  "approval flow": "审批流程",
  "model-gateway routing policy": "模型网关路由策略",
  "execution-service internal capability": "执行服务内部能力",
};

const zhEventKinds: Record<string, string> = {
  audit_log: "审计日志",
  audit: "审计日志",
  span: "Trace Span",
  skill: "Skill",
  replay_export: "回放导出",
  guardrail: "Guardrail",
  orchestration_checkpoint: "编排检查点",
};

const zhRepositorySectionLabels: Record<string, string> = {
  "manifest-source": "清单来源",
  summary: "摘要",
  timeline: "时间线",
  traces: "追踪记录",
  artifacts: "证据制品",
  "raw-findings": "原始问题",
  findings: "归一化问题",
  gate: "门禁决策",
  guardrails: "Guardrail 记录",
  approvals: "审批记录",
  "skill-invocations": "Skill 调用",
  "audit-logs": "审计日志",
  "coverage-snapshot": "覆盖快照",
  "visual-grounding": "视觉定位",
};

const zhRetentionActionLabels: Record<string, string> = {
  archive: "归档",
  purge: "清理",
  set_legal_hold: "设置法务保留",
  clear_legal_hold: "解除法务保留",
};

export function displayStatus(locale: Locale, value: unknown): string {
  if (value === null || value === undefined || String(value).trim() === "") {
    return locale === "zh-CN" ? "未知" : "Unknown";
  }
  const raw = String(value).trim();
  const normalized = normalizeKey(raw);
  if (locale === "zh-CN") {
    return zhStatusLabels[normalized] ?? raw;
  }
  return enStatusLabels[normalized] ?? humanizeStatus(raw);
}

export function displayStageLabel(locale: Locale, stageKey: string, fallback?: string): string {
  if (locale === "zh-CN") {
    return zhStageLabels[normalizeKey(stageKey)] ?? fallback ?? stageKey;
  }
  return fallback ?? humanizeStatus(stageKey);
}

export function displayStrategyLabel(locale: Locale, strategy: string, fallback?: string): string {
  if (locale === "zh-CN") {
    return zhStrategyLabels[normalizeKey(strategy)] ?? fallback ?? strategy;
  }
  return fallback ?? humanizeStatus(strategy);
}

export function displayDomainLabel(locale: Locale, domain: string): string {
  return locale === "zh-CN" ? zhDomainLabels[normalizeKey(domain)] ?? domain : humanizeStatus(domain);
}

export function displayArtifactLabel(locale: Locale, artifactType: string): string {
  return locale === "zh-CN" ? zhArtifactLabels[normalizeKey(artifactType)] ?? artifactType : humanizeStatus(artifactType);
}

export function displayRemediationLabel(locale: Locale, remediationType: string): string {
  return locale === "zh-CN" ? zhRemediationLabels[normalizeKey(remediationType)] ?? remediationType : humanizeStatus(remediationType);
}

export function displayRemediationSummary(locale: Locale, summary: string): string {
  if (locale !== "zh-CN") {
    return summary;
  }
  const patchTarget = summary.match(/^Provide patch suggestion for (.+)$/i);
  return patchTarget ? `为 ${patchTarget[1]} 提供补丁建议` : summary;
}

export function displayLogMessage(locale: Locale, message: string): string {
  if (locale !== "zh-CN") {
    return message;
  }
  if (message.trim().toLowerCase() === "task completed") {
    return "任务已完成";
  }
  return message;
}

export function displayMetricLabel(locale: Locale, name: string): string {
  return locale === "zh-CN" ? zhMetricLabels[name.trim().toLowerCase()] ?? name : name;
}

export function displaySignalLabel(locale: Locale, name: unknown): string {
  const raw = String(name ?? "");
  return locale === "zh-CN" ? zhSignalLabels[raw.trim().toLowerCase()] ?? displayMetricLabel(locale, raw) : raw;
}

export function displayFindingTitle(locale: Locale, title: string): string {
  return locale === "zh-CN" ? zhFindingTitles[title.trim().toLowerCase()] ?? title : title;
}

export function displayWorkflowActionLabel(locale: Locale, actionId: string, fallback: string): string {
  return locale === "zh-CN" ? zhActionLabels[actionId] ?? fallback : fallback;
}

export function displayReasonCode(locale: Locale, reasonCode: string): string {
  return locale === "zh-CN" ? zhReasonCodeLabels[normalizeKey(reasonCode)] ?? reasonCode : humanizeStatus(reasonCode);
}

export function displayRuntimeCategoryTitle(locale: Locale, category: RuntimeReadinessCategory): string {
  return locale === "zh-CN" ? zhRuntimeCategoryLabels[category.id] ?? category.title : category.title;
}

export function displayRuntimeItemLabel(locale: Locale, item: RuntimeReadinessItem): string {
  if (locale === "zh-CN" && item.id === "static-check-entrypoints" && item.details.entrypointSet === "community-runtime") {
    return "Community 运行验证入口";
  }
  return locale === "zh-CN" ? zhRuntimeItemLabels[item.id] ?? item.label : item.label;
}

export function displayRuntimeItemSummary(locale: Locale, item: RuntimeReadinessItem): string {
  if (locale !== "zh-CN") {
    return item.summary;
  }
  if (item.id === "static-check-entrypoints" && item.details.entrypointSet === "community-runtime") {
    return item.status === "missing_dependency"
      ? "缺少 Community 源码包必需的运行或迁移验证入口。"
      : "Community 运行与迁移验证入口均存在；源码发行不要求维护者专用 CI 入口。";
  }
  return zhRuntimeSummaries[`${item.id}:${item.status}`] ?? item.summary;
}

export function displayExtensionPointLabel(locale: Locale, extensionPointId: string, fallback: string): string {
  return locale === "zh-CN" ? zhExtensionPointLabels[extensionPointId] ?? fallback : fallback;
}

export function displayUnavailableReason(locale: Locale, reason: string): string {
  return locale === "zh-CN" ? zhUnavailableReasons[reason.trim().toLowerCase()] ?? reason : reason;
}

export function displayEventKind(locale: Locale, value: unknown): string {
  const raw = String(value ?? "");
  return locale === "zh-CN" ? zhEventKinds[normalizeKey(raw)] ?? raw : humanizeStatus(raw);
}

export function displayRepositorySectionLabel(locale: Locale, sectionName: string): string {
  return locale === "zh-CN" ? zhRepositorySectionLabels[sectionName] ?? sectionName : humanizeStatus(sectionName);
}

export function displayRetentionAction(locale: Locale, action: string): string {
  return locale === "zh-CN" ? zhRetentionActionLabels[action] ?? action : humanizeStatus(action);
}

export function displayLogLevel(locale: Locale, value: unknown): string {
  return displayStatus(locale, value);
}

export function summarizeTechnicalRefs(value: unknown, maxItems = 8): string {
  const flattened = flattenScalars(value).filter((item) => item !== "");
  if (flattened.length === 0) {
    return "-";
  }
  const unique = [...new Set(flattened)].slice(0, maxItems);
  const suffix = flattened.length > maxItems ? ` +${flattened.length - maxItems}` : "";
  return `${unique.map(shortTechnicalValue).join(" / ")}${suffix}`;
}

function flattenScalars(value: unknown, depth = 0): string[] {
  if (value === null || value === undefined || depth > 4) {
    return [];
  }
  if (["string", "number", "boolean"].includes(typeof value)) {
    return [String(value)];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item) => flattenScalars(item, depth + 1));
  }
  if (typeof value === "object") {
    return Object.values(value as Record<string, unknown>).flatMap((item) => flattenScalars(item, depth + 1));
  }
  return [];
}

function shortTechnicalValue(value: string) {
  return value.length > 28 ? `${value.slice(0, 25)}…` : value;
}

function normalizeKey(value: string) {
  return value.trim().toLowerCase().replace(/[\s-]+/g, "_");
}

function humanizeStatus(value: string) {
  const spaced = value.replace(/[_-]+/g, " ").trim();
  return spaced.length > 0 ? `${spaced[0].toUpperCase()}${spaced.slice(1)}` : value;
}
