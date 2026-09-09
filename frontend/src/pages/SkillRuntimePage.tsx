/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useMemo, useState } from "react";

import { Locale, t } from "../i18n";
import {
  ApiRequestError,
  changeCommunityBindingLifecycle,
  fetchCommunityLocalSkillManifests,
  fetchSkillProductFeatures,
  fetchSkillRuntimeAdapters,
  fetchSkillVersions,
  registerCommunityLocalSkillManifest,
  type CapabilityBindingMutationPayload,
  type CapabilityBindingMutationResult,
  type CommunityLocalSkillManifest,
  type CurrentUser,
  type EnvironmentItem,
  type ProjectItem,
  type SkillProductFeature,
  type SkillRuntimeAdapter,
  type SkillVersionItem,
} from "../lib/api";
import { displayExtensionPointLabel, displayStageLabel, displayStatus, displayUnavailableReason } from "../lib/presentation";
import type {
  ApprovalItem,
  CapabilityBindingItem,
  GuardrailEventItem,
  WorkflowCapabilityNode,
  ReplayItem,
  SkillInvocationItem,
  SkillItem,
} from "../store/platform";
import type { FormEvent, ReactNode } from "react";

type SkillRuntimePageProps = {
  approvals: ApprovalItem[];
  capabilityBindings: CapabilityBindingItem[];
  currentUser: CurrentUser | null;
  guardrailEvents: GuardrailEventItem[];
  governancePanel?: ReactNode;
  locale: Locale;
  onCreateBinding: (payload: CapabilityBindingMutationPayload) => Promise<CapabilityBindingMutationResult>;
  onRefreshSkills?: () => Promise<void>;
  onUpdateBinding: (bindingId: string, payload: Partial<CapabilityBindingMutationPayload>) => Promise<CapabilityBindingMutationResult>;
  projects?: ProjectItem[];
  environments?: EnvironmentItem[];
  selectedProjectId?: string | null;
  replay: ReplayItem | null;
  skillInvocations: SkillInvocationItem[];
  skills: SkillItem[];
  workflowCapabilityGraph: WorkflowCapabilityNode[];
};

const BINDING_STATUSES = ["draft", "active", "disabled", "deprecated", "archived"];
const SCOPE_TYPES = ["global", "workspace", "project", "environment", "stage", "domain"];
const COMMUNITY_SCOPE_TYPES = ["project", "environment"];
const COMMUNITY_EXTENSION_POINT = "PREPARE.regression_scope";

function capabilityBindingErrorMessage(locale: Locale, error: unknown, fallbackKey: "capabilityBindingSaveFailed" | "capabilityBindingUpdateFailed") {
  if (!(error instanceof ApiRequestError)) {
    return error instanceof Error ? error.message : t(locale, fallbackKey);
  }
  const reasonCode = error.code ?? (typeof error.detail === "string" ? error.detail.split(":", 1)[0] : null);
  if (reasonCode === "COMMUNITY_SKILL_PROJECT_SCOPE_REQUIRED") {
    return t(locale, "communityBindingProjectRequired");
  }
  if (reasonCode === "COMMUNITY_SKILL_ENVIRONMENT_SCOPE_REQUIRED") {
    return t(locale, "communityBindingEnvironmentRequired");
  }
  if (reasonCode === "COMMUNITY_SKILL_SCOPE_ID_INVALID") {
    return t(locale, "communityBindingScopeInvalid");
  }
  if (reasonCode === "COMMUNITY_SKILL_LOCAL_REGISTRATION_REQUIRED") {
    return t(locale, "communityBindingLocalRegistrationRequired");
  }
  if (["COMMUNITY_SKILL_ACTIVE_BINDING_CONFLICT", "SKILL_BINDING_CONCURRENT_MODIFICATION"].includes(reasonCode ?? "")) {
    return t(locale, "communityBindingConflict");
  }
  return t(locale, fallbackKey);
}

export function SkillRuntimePage({
  approvals,
  capabilityBindings,
  currentUser,
  guardrailEvents,
  governancePanel,
  locale,
  onCreateBinding,
  onRefreshSkills,
  onUpdateBinding,
  projects = [],
  environments = [],
  selectedProjectId = null,
  replay,
  skillInvocations,
  skills,
  workflowCapabilityGraph,
}: SkillRuntimePageProps) {
  const isCommunity = currentUser?.edition === "community";
  const visibleWorkflowCapabilityGraph = useMemo(
    () => isCommunity
      ? workflowCapabilityGraph.filter((node) => node.extensionPointId === COMMUNITY_EXTENSION_POINT)
      : workflowCapabilityGraph,
    [isCommunity, workflowCapabilityGraph],
  );
  const visibleSkills = useMemo(
    () => isCommunity
      ? skills.filter((skill) => skill.extensionPoints.includes(COMMUNITY_EXTENSION_POINT))
      : skills,
    [isCommunity, skills],
  );
  const firstBindableNode = visibleWorkflowCapabilityGraph.find((node) => node.bindable)
    ?? visibleWorkflowCapabilityGraph[0]
    ?? null;
  const [selectedExtensionPointId, setSelectedExtensionPointId] = useState<string | null>(
    firstBindableNode?.extensionPointId ?? null,
  );
  const [selectedSkillId, setSelectedSkillId] = useState<string>("");
  const [scopeType, setScopeType] = useState("global");
  const [scopeId, setScopeId] = useState("");
  const [projectId, setProjectId] = useState("");
  const [environment, setEnvironment] = useState("");
  const [stage, setStage] = useState("");
  const [domain, setDomain] = useState("");
  const [status, setStatus] = useState("draft");
  const [priority, setPriority] = useState(100);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [lastLifecycleResult, setLastLifecycleResult] = useState<CapabilityBindingMutationResult | null>(null);
  const [selectedInvocationId, setSelectedInvocationId] = useState<string | null>(skillInvocations[0]?.id ?? null);
  const [localManifests, setLocalManifests] = useState<CommunityLocalSkillManifest[]>([]);
  const [localManifestDirectory, setLocalManifestDirectory] = useState<string>("");
  const [registeringManifest, setRegisteringManifest] = useState<string | null>(null);
  const [productFeatures, setProductFeatures] = useState<SkillProductFeature[]>([]);
  const [runtimeAdapters, setRuntimeAdapters] = useState<SkillRuntimeAdapter[]>([]);
  const [skillVersions, setSkillVersions] = useState<SkillVersionItem[]>([]);
  const [selectedSkillVersionId, setSelectedSkillVersionId] = useState("");
  const canRegisterLocalSkills = currentUser?.capabilities.includes("community_skills.manage") ?? false;
  const allowedScopeTypes = isCommunity ? COMMUNITY_SCOPE_TYPES : SCOPE_TYPES;
  const showScopeId = scopeType !== "project" && scopeType !== "environment";
  const visibleProductFeatures = useMemo(
    () => isCommunity
      ? productFeatures.filter((feature) => feature.ossIncluded && feature.availableInCurrentEdition)
      : productFeatures,
    [isCommunity, productFeatures],
  );
  const communityProjectValid = !isCommunity || (
    Boolean(projectId) && projects.some((project) => project.id === projectId)
  );
  const communityEnvironmentValid = !isCommunity || scopeType !== "environment" || (
    Boolean(environment)
    && environments.some((item) => item.id === environment && item.projectId === projectId)
  );
  const communityBindingFormInvalid = !communityProjectValid || !communityEnvironmentValid;

  useEffect(() => {
    if (!isCommunity) return;
    setScopeType((current) => allowedScopeTypes.includes(current) ? current : "project");
    if (selectedProjectId && selectedProjectId !== "all-projects") {
      setProjectId(selectedProjectId);
    } else if (!projectId && projects[0]) {
      setProjectId(projects[0].id);
    }
  }, [allowedScopeTypes, isCommunity, projectId, projects, selectedProjectId]);

  useEffect(() => {
    if (!canRegisterLocalSkills) return;
    void fetchCommunityLocalSkillManifests()
      .then((catalog) => {
        setLocalManifests(catalog.items);
        setLocalManifestDirectory(catalog.configuredDirectory);
      })
      .catch((error) => setFormError(error instanceof Error ? error.message : String(error)));
  }, [canRegisterLocalSkills]);

  useEffect(() => {
    if (!currentUser?.capabilities.includes("skills.catalog.read")) return;
    void Promise.all([fetchSkillProductFeatures(), fetchSkillRuntimeAdapters()])
      .then(([features, adapters]) => {
        setProductFeatures(features.features);
        setRuntimeAdapters(adapters.items);
      })
      .catch((error) => setFormError(error instanceof Error ? error.message : String(error)));
  }, [currentUser]);

  useEffect(() => {
    if (!selectedExtensionPointId && firstBindableNode) {
      setSelectedExtensionPointId(firstBindableNode.extensionPointId);
    }
  }, [firstBindableNode, selectedExtensionPointId]);

  const selectedNode = useMemo(
    () => visibleWorkflowCapabilityGraph.find((node) => node.extensionPointId === selectedExtensionPointId) ?? firstBindableNode,
    [firstBindableNode, selectedExtensionPointId, visibleWorkflowCapabilityGraph],
  );

  const compatibleSkills = useMemo(() => {
    if (!selectedNode) {
      return [];
    }
    return visibleSkills.filter(
      (skill) => skill.governanceStatus !== "draft" && skill.extensionPoints.includes(selectedNode.extensionPointId),
    );
  }, [selectedNode, visibleSkills]);

  useEffect(() => {
    if (!compatibleSkills.some((skill) => skill.skillId === selectedSkillId)) {
      setSelectedSkillId(compatibleSkills[0]?.skillId ?? "");
    }
  }, [compatibleSkills, selectedSkillId]);

  const selectedSkill = compatibleSkills.find((skill) => skill.skillId === selectedSkillId) ?? null;
  useEffect(() => {
    if (!selectedSkill) {
      setSkillVersions([]);
      setSelectedSkillVersionId("");
      return;
    }
    let cancelled = false;
    void fetchSkillVersions(selectedSkill.skillId)
      .then((result) => {
        if (cancelled) return;
        setSkillVersions(result.items);
        const active = result.items.find(
          (item) => item.version === selectedSkill.version && item.manifestHash === selectedSkill.manifestHash,
        );
        setSelectedSkillVersionId(active?.id ?? result.items.find((item) => item.governanceStatus === "active")?.id ?? "");
      })
      .catch((error) => {
        if (!cancelled) setFormError(error instanceof Error ? error.message : String(error));
      });
    return () => { cancelled = true; };
  }, [selectedSkill]);
  const selectableSkillVersions = skillVersions.filter((item) => item.governanceStatus === "active");
  const selectedSkillVersion = selectableSkillVersions.find((item) => item.id === selectedSkillVersionId) ?? null;
  const visibleBindings = selectedNode
    ? capabilityBindings.filter((binding) => binding.extensionPointId === selectedNode.extensionPointId)
    : capabilityBindings;
  const visibleInvocations = selectedNode
    ? skillInvocations.filter((invocation) => invocation.extensionPointId === selectedNode.extensionPointId)
    : skillInvocations;
  const selectedInvocation =
    visibleInvocations.find((invocation) => invocation.id === selectedInvocationId)
    ?? visibleInvocations[0]
    ?? skillInvocations[0]
    ?? null;
  const linkedGuardrails = selectedInvocation
    ? guardrailEvents.filter((event) => event.skillInvocationId === selectedInvocation.id)
    : guardrailEvents.filter((event) => event.skillInvocationId);
  const skillApprovals = approvals.filter(
    (approval) =>
      approval.type === "other"
      && ["skill.invoke", "capability_binding.lifecycle_change"].includes(String(approval.payload.action ?? "")),
  );
  const bindingLifecycleApprovals = approvals.filter(
    (approval) => approval.type === "other" && String(approval.payload.action ?? "") === "capability_binding.lifecycle_change",
  );
  const bindingLifecycleGuardrails = guardrailEvents.filter((event) => event.ruleId === "capability_binding.lifecycle_preflight");
  const canManageBindings = currentUser?.capabilities.includes("capability_bindings.write") ?? false;
  const readOnlyNotice =
    isCommunity
      ? t(locale, "communityCapabilityBindingReadonly")
      : currentUser?.edition === "basic"
      ? t(locale, "capabilityBindingReadonlyBasic")
      : t(locale, "capabilityBindingRequiresEnterprise");

  const submitBinding = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedNode?.bindable || !selectedSkill || !canManageBindings) {
      return;
    }
    if (!communityProjectValid) {
      setFormError(t(locale, "communityBindingProjectRequired"));
      return;
    }
    if (!communityEnvironmentValid) {
      setFormError(t(locale, "communityBindingEnvironmentRequired"));
      return;
    }
    setSaving(true);
    setFormError(null);
    try {
      const result = await onCreateBinding({
        bindingConfig: {},
        domain: normalizeOptional(domain),
        environment: normalizeOptional(environment),
        extensionPointId: selectedNode.extensionPointId,
        manifestHash: selectedSkillVersion?.manifestHash ?? selectedSkill.manifestHash,
        priority,
        projectId: normalizeOptional(projectId),
        scopeId: showScopeId ? normalizeOptional(scopeId) : null,
        scopeType,
        skillId: selectedSkill.skillId,
        stage: normalizeOptional(stage),
        status,
        version: selectedSkillVersion?.version ?? selectedSkill.version,
      });
      setLastLifecycleResult(result);
      setScopeId("");
      if (!isCommunity) {
        setProjectId("");
        setEnvironment("");
      }
      setStage("");
      setDomain("");
    } catch (error) {
      setFormError(capabilityBindingErrorMessage(locale, error, "capabilityBindingSaveFailed"));
    } finally {
      setSaving(false);
    }
  };

  const updateBindingStatus = async (binding: CapabilityBindingItem, nextStatus: string) => {
    if (!canManageBindings) {
      return;
    }
    setSaving(true);
    setFormError(null);
    try {
      const result = isCommunity
        ? await changeCommunityBindingLifecycle(binding, nextStatus === "active" ? "enable" : "disable")
        : await onUpdateBinding(binding.id, { status: nextStatus });
      setLastLifecycleResult(result);
      if (isCommunity) await onRefreshSkills?.();
    } catch (error) {
      setFormError(capabilityBindingErrorMessage(locale, error, "capabilityBindingUpdateFailed"));
    } finally {
      setSaving(false);
    }
  };

  const registerLocalManifest = async (manifest: CommunityLocalSkillManifest) => {
    if (!manifest.valid) return;
    setRegisteringManifest(manifest.fileName);
    setFormError(null);
    try {
      await registerCommunityLocalSkillManifest(manifest.fileName);
      await onRefreshSkills?.();
    } catch (error) {
      setFormError(capabilityBindingErrorMessage(locale, error, "capabilityBindingSaveFailed"));
    } finally {
      setRegisteringManifest(null);
    }
  };

  return (
    <div className="page-shell" data-route="/capability-bindings">
      <div className="page-toolbar">
        <div>
          <span className="eyebrow">{t(locale, "systemSettings")}</span>
          <h1>{t(locale, "capabilityBindings")}</h1>
        </div>
      </div>

      <div className="stats-grid stats-grid--compact">
        <div className="stat-tile">
          <span>{t(locale, "skillCatalog")}</span>
          <strong>{visibleSkills.length}</strong>
          <p>{t(locale, "controlledManifests")}</p>
        </div>
        <div className="stat-tile">
          <span>{t(locale, "extensionPoints")}</span>
          <strong>{visibleWorkflowCapabilityGraph.filter((node) => node.bindable).length}</strong>
          <p>{t(locale, "bindableWorkflowNodes")}</p>
        </div>
        <div className="stat-tile">
          <span>{t(locale, "bindings")}</span>
          <strong>{capabilityBindings.length}</strong>
          <p>{t(locale, "serviceResolvedCapabilityMappings")}</p>
        </div>
        <div className="stat-tile">
          <span>{t(locale, "invocations")}</span>
          <strong>{skillInvocations.length}</strong>
          <p>{t(locale, "serviceOwnedCallRecords")}</p>
        </div>
      </div>

      {canRegisterLocalSkills ? (
        <section className="section-card">
          <div className="section-card__header">
            <span>{t(locale, "communityLocalDirectory")}</span>
            <h2>{t(locale, "trustedLocalSkillManifests")}</h2>
            <p>{localManifestDirectory}</p>
          </div>
          <p className="muted-copy">
            {t(locale, "communitySkillManifestBoundary")}
          </p>
          <div className="stack-list">
            {localManifests.map((manifest) => (
              <div className="stack-row stack-row--dense" key={manifest.fileName}>
                <div><strong>{manifest.displayName ?? manifest.fileName}</strong><p>{manifest.skillId ?? manifest.error} · {manifest.version ?? "-"}</p></div>
                <button disabled={!manifest.valid || registeringManifest === manifest.fileName} onClick={() => void registerLocalManifest(manifest)} type="button">
                  {registeringManifest === manifest.fileName ? t(locale, "registering") : t(locale, "register")}
                </button>
              </div>
            ))}
            {localManifests.length === 0 ? <p className="empty-copy">{t(locale, "noJsonManifests")}</p> : null}
          </div>
        </section>
      ) : null}

      <section className="section-card">
        <div className="section-card__header">
          <span>{t(locale, "skillSupplyBoundary")}</span>
          <h2>{t(locale, isCommunity ? "registeredRuntimeAdapters" : "skillProductFeatureMap")}</h2>
        </div>
        <p className="muted-copy">{t(locale, "skillNoDirectExecution")}</p>
        {!isCommunity ? (
          <div className="stack-list">
            {visibleProductFeatures.map((feature) => (
              <div className="stack-row stack-row--dense" key={feature.id}>
                <div>
                  <strong className="technical-value">{feature.id}</strong>
                  <p>{feature.executionSemantics}</p>
                </div>
                <div className="chip-row">
                  <span className="tag">{feature.ossIncluded ? t(locale, "ossIncluded") : t(locale, "fullOnly")}</span>
                  <span className="tag">{feature.availableInCurrentEdition ? t(locale, "available") : t(locale, "unavailable")}</span>
                </div>
              </div>
            ))}
          </div>
        ) : null}
        <div className="detail-stack">
          {!isCommunity ? <h3>{t(locale, "registeredRuntimeAdapters")}</h3> : null}
          {runtimeAdapters.map((adapter) => (
            <div className="inline-status" key={adapter.adapterId}>
              <div><strong>{adapter.adapterId}</strong><span>{adapter.resultKind}</span></div>
              <span>{t(locale, "deployedAdapterOnly")}</span>
            </div>
          ))}
        </div>
      </section>

      {governancePanel}

      <div className="page-columns page-columns--capability-catalog">
        <section className="section-card">
          <div className="section-card__header">
            <span>{t(locale, "workflow")}</span>
            <h2>{t(locale, "capabilityGraph")}</h2>
          </div>
          <div className="stack-list">
            {visibleWorkflowCapabilityGraph.map((node) => (
              <button
                className={`stack-row stack-row--button ${selectedNode?.extensionPointId === node.extensionPointId ? "stack-row--selected" : ""}`}
                key={node.extensionPointId}
                onClick={() => {
                  setSelectedExtensionPointId(node.extensionPointId);
                  setSelectedInvocationId(null);
                }}
                type="button"
              >
                <div>
                  <strong>{displayExtensionPointLabel(locale, node.extensionPointId, node.label)}</strong>
                  <p className="technical-value">{node.extensionPointId}</p>
                </div>
                <span>{node.bindable ? t(locale, "bindable") : node.unavailableReason ? displayUnavailableReason(locale, node.unavailableReason) : t(locale, "locked")}</span>
              </button>
            ))}
            {visibleWorkflowCapabilityGraph.length === 0 ? <p className="empty-copy">{t(locale, "noWorkflowGraph")}</p> : null}
          </div>
        </section>

        <section className="section-card">
          <div className="section-card__header">
            <span>{t(locale, "catalog")}</span>
            <h2>
              {selectedNode
                ? displayExtensionPointLabel(locale, selectedNode.extensionPointId, selectedNode.label)
                : t(locale, "noExtensionPoint")}
            </h2>
            {selectedNode ? <p className="technical-value">{selectedNode.extensionPointId}</p> : null}
          </div>
          <div className="detail-stack">
            <div className="chip-row">
              <span className="tag">
                {selectedNode ? displayStageLabel(locale, selectedNode.lifecycleStage) : t(locale, "unknown")}
              </span>
              <span className="tag">{displayStatus(locale, selectedNode?.requiredEdition ?? t(locale, "basic"))}</span>
              <span className="tag">{selectedNode?.requiredCapability ?? t(locale, "readOnly")}</span>
            </div>
            {compatibleSkills.length === 0 ? (
              <p className="empty-copy">{t(locale, "noCompatibleSkills")}</p>
            ) : (
              compatibleSkills.map((skill) => (
                <div className="stack-row stack-row--dense" key={skill.id}>
                  <div>
                    <strong>{displayExtensionPointLabel(locale, selectedNode?.extensionPointId ?? "", skill.displayName)}</strong>
                    <p>{skill.skillId}</p>
                  </div>
                  <span>{skill.version}</span>
                </div>
              ))
            )}
            {selectedNode?.currentBindingSummary ? (
              <CompactJson title={t(locale, "currentBinding")} value={selectedNode.currentBindingSummary} />
            ) : null}
            {selectedSkill?.runtime ? (
              <CompactJson title={t(locale, "runtime")} value={selectedSkill.runtime} />
            ) : null}
            {skillVersions.length > 0 ? (
              <div className="detail-stack skill-version-history">
                <h3>{t(locale, "skillVersionHistory")}</h3>
                {skillVersions.map((version) => (
                  <div className="stack-row stack-row--dense" key={version.id}>
                    <div>
                      <strong>{version.version}</strong>
                      <p className="skill-version-history__metadata">
                        {isCommunity ? (
                          <>
                            {skillVersionSourceLabel(locale, version.provenance.sourceType)}
                            {" · "}
                            {t(locale, "createdAt")} {formatSkillVersionTimestamp(version.createdAt, locale)}
                          </>
                        ) : (
                          <>{version.provenance.sourceType} · {version.changesFromPrevious.changedFields.join(", ") || "-"}</>
                        )}
                      </p>
                    </div>
                    <div className="chip-row">
                      <span className="tag">{displayStatus(locale, version.governanceStatus)}</span>
                      <span className="tag">{version.manifestHash.slice(0, 18)}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        </section>
      </div>

      <div className="page-columns page-columns--runtime-detail">
        <section className="section-card">
          <div className="section-card__header">
            <span>{t(locale, "binding")}</span>
            <h2>{t(locale, "capabilityBindings")}</h2>
          </div>
          <div className="detail-stack">
            {canManageBindings && selectedNode?.bindable ? (
              <form className="control-form" onSubmit={submitBinding}>
                <label className="policy-field">
                  <span>{t(locale, "skill")}</span>
                  <select value={selectedSkillId} onChange={(event) => setSelectedSkillId(event.target.value)}>
                    {compatibleSkills.map((skill) => (
                      <option key={skill.id} value={skill.skillId}>
                        {displayExtensionPointLabel(locale, selectedNode?.extensionPointId ?? "", skill.displayName)} ({skill.version})
                      </option>
                    ))}
                  </select>
                </label>
                <label className="policy-field">
                  <span>{t(locale, "skillVersion")}</span>
                  <select value={selectedSkillVersionId} onChange={(event) => setSelectedSkillVersionId(event.target.value)}>
                    {selectableSkillVersions.map((version) => (
                      <option key={version.id} value={version.id}>
                        {version.version} · {version.manifestHash.slice(0, 18)}
                      </option>
                    ))}
                  </select>
                </label>
                <div className="detail-grid">
                  <label className="policy-field">
                    <span>{t(locale, "scope")}</span>
                    <select value={scopeType} onChange={(event) => setScopeType(event.target.value)}>
                      {allowedScopeTypes.map((option) => (
                        <option key={option} value={option}>
                          {displayStatus(locale, option)}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="policy-field">
                    <span>{t(locale, "status")}</span>
                    <select value={status} onChange={(event) => setStatus(event.target.value)}>
                      {(isCommunity ? ["draft"] : BINDING_STATUSES).map((option) => (
                        <option key={option} value={option}>
                          {displayStatus(locale, option)}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="policy-field">
                    <span>{t(locale, "priority")}</span>
                    <input
                      className="text-input"
                      min={0}
                      onChange={(event) => setPriority(Number(event.target.value))}
                      type="number"
                      value={priority}
                    />
                  </label>
                  {showScopeId ? (
                    <label className="policy-field">
                      <span>{t(locale, "scopeId")}</span>
                      <input className="text-input" onChange={(event) => setScopeId(event.target.value)} value={scopeId} />
                    </label>
                  ) : null}
                  <label className="policy-field">
                    <span>{t(locale, "project")}</span>
                    {isCommunity ? (
                      <select
                        aria-invalid={!communityProjectValid}
                        onChange={(event) => { setProjectId(event.target.value); setEnvironment(""); }}
                        required
                        value={projectId}
                      >
                        <option value="">{t(locale, "selectProject")}</option>
                        {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
                      </select>
                    ) : <input className="text-input" onChange={(event) => setProjectId(event.target.value)} value={projectId} />}
                  </label>
                  <label className="policy-field">
                    <span>{t(locale, "environment")}</span>
                    {isCommunity ? (
                      <select
                        aria-invalid={!communityEnvironmentValid}
                        disabled={scopeType !== "environment" || !communityProjectValid}
                        onChange={(event) => setEnvironment(event.target.value)}
                        required={scopeType === "environment"}
                        value={environment}
                      >
                        <option value="">{t(locale, "selectEnvironment")}</option>
                        {environments.filter((item) => item.projectId === projectId).map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
                      </select>
                    ) : <input className="text-input" onChange={(event) => setEnvironment(event.target.value)} value={environment} />}
                  </label>
                  {!isCommunity ? (
                    <>
                      <label className="policy-field">
                        <span>{t(locale, "stage")}</span>
                        <input className="text-input" onChange={(event) => setStage(event.target.value)} value={stage} />
                      </label>
                      <label className="policy-field">
                        <span>{t(locale, "domain")}</span>
                        <input className="text-input" onChange={(event) => setDomain(event.target.value)} value={domain} />
                      </label>
                    </>
                  ) : null}
                </div>
                {isCommunity && !communityProjectValid ? (
                  <p className="empty-copy">{t(locale, "communityBindingProjectRequired")}</p>
                ) : null}
                {isCommunity && communityProjectValid && !communityEnvironmentValid ? (
                  <p className="empty-copy">{t(locale, "communityBindingEnvironmentRequired")}</p>
                ) : null}
                {formError ? <div className="error-banner">{formError}</div> : null}
                {!isCommunity && lastLifecycleResult?.approvalRequired ? (
                  <div className="inline-status">
                    <div>
                      <strong>{t(locale, "bindingApprovalRequested")}</strong>
                      <span>{String(lastLifecycleResult.approvalEnvelope?.approvalId ?? "")}</span>
                    </div>
                    <span>{t(locale, "pendingApproval")}</span>
                  </div>
                ) : null}
                <div className="button-row">
                  <button className="primary-button" disabled={saving || compatibleSkills.length === 0 || communityBindingFormInvalid} type="submit">
                    {t(locale, isCommunity ? "communitySkillCreateDraft" : "requestBindingChange")}
                  </button>
                </div>
              </form>
            ) : (
              <div className="inline-status">
                <div>
                  <strong>{t(locale, "readOnly")}</strong>
                  <span>
                    {selectedNode?.bindable
                      ? readOnlyNotice
                      : selectedNode?.unavailableReason
                        ? displayUnavailableReason(locale, selectedNode.unavailableReason)
                        : t(locale, "nodeNotBindable")}
                  </span>
                </div>
                <span>{displayStatus(locale, currentUser?.edition ?? t(locale, "unknown"))}</span>
              </div>
            )}

            {visibleBindings.map((binding) => (
              <div className="stack-row stack-row--dense" key={binding.id}>
                <div>
                  <strong>{binding.skillId}</strong>
                  <p>{displayStatus(locale, binding.scopeType)}{binding.scopeId ? `:${binding.scopeId}` : ""}</p>
                  {!isCommunity && binding.approvalRequired ? (
                    <p>{t(locale, "pendingApproval")}: {String(binding.approvalEnvelope?.approvalId ?? "")}</p>
                  ) : null}
                  {!isCommunity && binding.pendingChange?.operation ? (
                    <p>{t(locale, "pendingBindingChange")}: {String(binding.pendingChange.operation ?? "")}</p>
                  ) : null}
                </div>
                <div className="chip-row">
                  <span className="tag">{displayStatus(locale, binding.status)}</span>
                  {!isCommunity ? <span className="tag">{t(locale, "approvalRefs")}: {binding.approvalRefs.length}</span> : null}
                  <span className="tag">{t(locale, "guardrailRefs")}: {binding.guardrailEventRefs.length}</span>
                  <span className="tag">{t(locale, "auditRefs")}: {binding.auditRefs.length}</span>
                </div>
                {canManageBindings && isCommunity ? (
                  <div className="chip-row">
                    <button className="ghost-button" disabled={saving || !binding.stateHash || !binding.communityLifecycle?.canEnable}
                      onClick={() => void updateBindingStatus(binding, "active")} type="button">
                      {t(locale, "communitySkillEnable")}
                    </button>
                    <button className="ghost-button" disabled={saving || !binding.stateHash || !binding.communityLifecycle?.canDisable}
                      onClick={() => void updateBindingStatus(binding, "disabled")} type="button">
                      {t(locale, "communitySkillDisable")}
                    </button>
                    {binding.communityLifecycle?.unavailableReason ? <p title={binding.communityLifecycle.unavailableReason}>{t(locale, "communitySkillEnablementUnavailable")}</p> : null}
                  </div>
                ) : canManageBindings ? (
                  <select
                    aria-label={t(locale, "bindingLifecycleStatus")}
                    disabled={saving || binding.approvalRequired}
                    onChange={(event) => updateBindingStatus(binding, event.target.value)}
                    value={binding.status}
                  >
                    {BINDING_STATUSES.map((option) => (
                      <option key={option} value={option}>
                        {displayStatus(locale, option)}
                      </option>
                    ))}
                  </select>
                ) : null}
                {!isCommunity && binding.activationReadiness ? (
                  <div className="chip-row">
                    <span className="tag">{t(locale, "validation")}: {displayStatus(locale, binding.activationReadiness.contractValidation)}</span>
                    <span className="tag">{t(locale, "evaluation")}: {displayStatus(locale, binding.activationReadiness.datasetEvaluation)}</span>
                    <span className="tag">Shadow: {displayStatus(locale, binding.activationReadiness.shadowComparison)}</span>
                  </div>
                ) : null}
              </div>
            ))}
            {visibleBindings.length === 0 ? <p className="empty-copy">{t(locale, "noBindingsForNode")}</p> : null}
          </div>
        </section>

        <section className="section-card">
          <div className="section-card__header">
            <span>{t(locale, "observation")}</span>
            <h2>{t(locale, "skillInvocations")}</h2>
          </div>
          <div className="timeline-list">
            {visibleInvocations.slice(0, 12).map((invocation) => (
              <button
                className={`timeline-item timeline-item--skill_invocation ${selectedInvocation?.id === invocation.id ? "stack-row--selected" : ""}`}
                key={invocation.id}
                onClick={() => setSelectedInvocationId(invocation.id)}
                type="button"
              >
                <strong>{invocation.skillId}</strong>
                <span>{displayStatus(locale, invocation.status)}</span>
                <span>{new Date(invocation.createdAt).toLocaleTimeString()}</span>
              </button>
            ))}
            {visibleInvocations.length === 0 ? <p className="empty-copy">{t(locale, "noInvocationsForNode")}</p> : null}
          </div>
        </section>
      </div>

      <div className="page-columns">
        <section className="section-card">
          <div className="section-card__header">
            <span>{t(locale, "resolution")}</span>
            <h2>{selectedInvocation?.skillId ?? t(locale, "noInvocationSelected")}</h2>
          </div>
          {selectedInvocation ? (
            <div className="detail-stack">
              <div className="chip-row">
                <span className="tag">{displayStatus(locale, selectedInvocation.status)}</span>
                <span className="tag">{selectedInvocation.version}</span>
                <span className="tag">{selectedInvocation.manifestHash.slice(0, 18)}</span>
              </div>
              <InvocationResolution invocation={selectedInvocation} locale={locale} />
            </div>
          ) : (
            <p className="empty-copy">{t(locale, "noInvocationSelected")}</p>
          )}
        </section>

        <section className="section-card">
          <div className="section-card__header">
            <span>{t(locale, "trace")}</span>
            <h2>{t(locale, "runtimeClosure")}</h2>
          </div>
          <div className="detail-stack">
            <div className="inline-status">
              <div>
                <strong>{t(locale, "replaySkillRecords")}</strong>
                <span>{replay?.skillInvocations.length ?? 0} {t(locale, "capturedInReplay")}</span>
              </div>
              <span>{replay?.gate?.overall ? displayStatus(locale, replay.gate.overall) : t(locale, "none")}</span>
            </div>
            {linkedGuardrails.slice(0, 6).map((event) => (
              <div className="timeline-item timeline-item--guardrail" key={event.id}>
                <strong>{event.ruleId}</strong>
              <span>{displayStatus(locale, event.decision)}</span>
                <span>{new Date(event.createdAt).toLocaleTimeString()}</span>
              </div>
            ))}
            {!isCommunity ? skillApprovals.slice(0, 4).map((approval) => (
              <div className="stack-row stack-row--dense" key={approval.id}>
                <div>
                  <strong>{approval.summary}</strong>
                  <p>{String(approval.payload.skillId ?? approval.payload.bindingId ?? approval.resourceId)}</p>
                </div>
                <span>{displayStatus(locale, approval.status)}</span>
              </div>
            )) : null}
            {!isCommunity && bindingLifecycleApprovals.length > 0 ? (
              <CompactJson title={t(locale, "bindingLifecycleApprovals")} value={bindingLifecycleApprovals.slice(0, 6)} />
            ) : null}
            {bindingLifecycleGuardrails.length > 0 ? (
              <CompactJson title={t(locale, "bindingLifecycleGuardrails")} value={bindingLifecycleGuardrails.slice(0, 6)} />
            ) : null}
            {linkedGuardrails.length === 0 && (isCommunity || skillApprovals.length === 0) && bindingLifecycleGuardrails.length === 0 ? (
              <p className="empty-copy">{t(locale, "noLinkedGuardrailApprovals")}</p>
            ) : null}
          </div>
        </section>
      </div>
    </div>
  );
}

function InvocationResolution({ invocation, locale }: { invocation: SkillInvocationItem; locale: Locale }) {
  const snapshot = invocation.resolutionSnapshot ?? {};
  const source = firstDisplayValue(snapshot.source, invocation.sourceWorkflow, t(locale, "none"));
  const bindingId = firstDisplayValue(snapshot.bindingId, invocation.bindingId, t(locale, "unbound"));
  const extensionPointId = firstDisplayValue(snapshot.extensionPointId, invocation.extensionPointId, t(locale, "none"));
  const resolvedSkill = firstDisplayValue(snapshot.skillId, invocation.skillId, t(locale, "none"));
  const resolvedVersion = firstDisplayValue(snapshot.version, invocation.version, t(locale, "none"));

  return (
    <div className="invocation-resolution">
      <section aria-labelledby="binding-resolution-summary" className="resolution-panel">
        <div className="resolution-panel__heading">
          <div>
            <h3 id="binding-resolution-summary">{t(locale, "bindingResolution")}</h3>
            <p>{t(locale, "bindingResolutionSummary")}</p>
          </div>
          <span className="status-pill">{source}</span>
        </div>
        <dl className="resolution-summary-grid">
          <ResolutionField label={t(locale, "resolutionSource")} value={source} />
          <ResolutionField label={t(locale, "extensionPoint")} value={extensionPointId} />
          <ResolutionField label={t(locale, "binding")} value={bindingId} />
          <ResolutionField label={t(locale, "scope")} value={formatResolutionValue(snapshot.scope, locale)} />
          <ResolutionField label={t(locale, "resolvedSkill")} value={`${resolvedSkill} · ${resolvedVersion}`} />
          <ResolutionField label={t(locale, "execution")} value={invocation.executionId ?? t(locale, "none")} />
        </dl>
      </section>

      <section aria-labelledby="invocation-reference-summary" className="resolution-panel">
        <div className="resolution-panel__heading">
          <div>
            <h3 id="invocation-reference-summary">{t(locale, "invocationReferences")}</h3>
            <p>{t(locale, "invocationReferencesSummary")}</p>
          </div>
        </div>
        <div className="resolution-reference-grid">
          <ReferenceCollection locale={locale} title={t(locale, "approvalRefs")} values={invocation.approvalRefs} />
          <ReferenceCollection locale={locale} title={t(locale, "artifactRefs")} values={invocation.artifactRefs} />
          <ReferenceCollection locale={locale} title={t(locale, "toolRefs")} values={invocation.toolCallRefs} />
          <ReferenceCollection locale={locale} title={t(locale, "connectorRefs")} values={invocation.connectorCallRefs} />
        </div>
      </section>

      <details className="resolution-raw-data">
        <summary>
          <span>{t(locale, "rawResolutionData")}</span>
          <span className="tag">{Object.keys(snapshot).length} {t(locale, "fields")}</span>
        </summary>
        <pre aria-label={t(locale, "rawResolutionData")} className="snapshot-json" tabIndex={0}>
          {JSON.stringify(snapshot, null, 2)}
        </pre>
      </details>
    </div>
  );
}

function ResolutionField({ label, value }: { label: string; value: string }) {
  return (
    <div className="resolution-summary-field">
      <dt>{label}</dt>
      <dd title={value}>{value}</dd>
    </div>
  );
}

function ReferenceCollection({ locale, title, values }: { locale: Locale; title: string; values: Array<Record<string, unknown>> }) {
  return (
    <section className="resolution-reference-card">
      <div className="resolution-reference-card__heading">
        <h4>{title}</h4>
        <span className="tag">{values.length}</span>
      </div>
      {values.length === 0 ? (
        <p className="resolution-reference-empty">{t(locale, "noReferenceRecords")}</p>
      ) : (
        <div className="resolution-reference-list">
          {values.map((value, index) => (
            <details className="resolution-reference-item" key={`${referenceIdentity(value, index)}-${index}`}>
              <summary>
                <span>{referenceIdentity(value, index)}</span>
                <span>{t(locale, "viewDetails")}</span>
              </summary>
              <dl>
                {Object.entries(value).map(([key, item]) => (
                  <div key={key}>
                    <dt>{key}</dt>
                    <dd>{formatResolutionValue(item, locale)}</dd>
                  </div>
                ))}
              </dl>
            </details>
          ))}
        </div>
      )}
    </section>
  );
}

function firstDisplayValue(...values: unknown[]) {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value;
    if (typeof value === "number" || typeof value === "boolean") return String(value);
  }
  return "";
}

function formatResolutionValue(value: unknown, locale: Locale): string {
  if (value === null || value === undefined || value === "") return t(locale, "none");
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.length > 0 ? value.map((item) => formatResolutionValue(item, locale)).join(" · ") : t(locale, "none");
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return t(locale, "none");
    return entries.map(([key, item]) => `${key}: ${formatResolutionValue(item, locale)}`).join(" · ");
  }
  return String(value);
}

function referenceIdentity(value: Record<string, unknown>, index: number) {
  for (const key of ["id", "approvalId", "artifactId", "toolCallId", "connectorCallId", "ref", "uri"]) {
    const candidate = value[key];
    if (typeof candidate === "string" && candidate.trim()) return candidate;
  }
  return `#${index + 1}`;
}

function CompactJson({ title, value }: { title: string; value: unknown }) {
  return (
    <div>
      <h3>{title}</h3>
      <pre aria-label={title} className="snapshot-json" tabIndex={0}>
        {JSON.stringify(value ?? {}, null, 2)}
      </pre>
    </div>
  );
}

function normalizeOptional(value: string) {
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function skillVersionSourceLabel(locale: Locale, sourceType: string) {
  if (sourceType === "trusted_local_manifest") return t(locale, "skillVersionSourceTrustedLocal");
  if (sourceType === "builtin_or_migration") return t(locale, "skillVersionSourceBuiltin");
  if (sourceType === "managed_manifest_draft") return t(locale, "skillVersionSourceManagedDraft");
  return sourceType.replaceAll("_", " ");
}

function formatSkillVersionTimestamp(value: string, locale: Locale) {
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? value : timestamp.toLocaleString(locale);
}
