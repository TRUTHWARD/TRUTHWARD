/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useMemo, useState, type FormEvent } from "react";

import { SectionCard } from "../components/SectionCard";
import { t, type Locale } from "../i18n";
import {
  createCommunityModel,
  deleteCommunityModel,
  runCommunityModelCapabilityScan,
  runCommunityModelHealthCheck,
  updateCommunityModel,
  type EnvironmentItem,
  type ModelMutationPayload,
  type ModelProvider,
  type ModelRole,
  type ProjectItem,
} from "../lib/api";
import type { ModelItem } from "../store/platform";

type CommunityModelsPageProps = {
  canManageModels: boolean;
  locale: Locale;
  models: ModelItem[];
  onRefreshModels: () => Promise<void>;
  projects?: ProjectItem[];
  environments?: EnvironmentItem[];
  selectedProjectId?: string | null;
};

const providers: ModelProvider[] = ["openai", "anthropic", "openai_compatible", "ollama", "vllm", "custom"];
const roles: ModelRole[] = ["PRIMARY", "CHALLENGER", "JUDGE", "LOCAL_FALLBACK"];

function initialDraft(projectId: string | null): ModelMutationPayload {
  return {
    name: "",
    projectId,
    environmentId: null,
    provider: "openai_compatible",
    model: "",
    baseUrl: null,
    apiKeyRef: null,
    roles: ["PRIMARY"],
    priority: 100,
    enabled: true,
    capabilities: { tools: false, vision: false, json: true, longContext: false, streaming: false, local: false },
    config: { timeoutMs: 30000, maxRetries: 2, temperature: 0.2 },
  };
}

export function CommunityModelsPage({
  canManageModels,
  locale,
  models,
  onRefreshModels,
  projects = [],
  environments = [],
  selectedProjectId = null,
}: CommunityModelsPageProps) {
  const effectiveProjectId = selectedProjectId && selectedProjectId !== "all-projects"
    ? selectedProjectId
    : projects[0]?.id ?? null;
  const [draft, setDraft] = useState<ModelMutationPayload>(() => initialDraft(effectiveProjectId));
  const [editingId, setEditingId] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!editingId && effectiveProjectId) {
      setDraft((current) => ({ ...current, projectId: effectiveProjectId, environmentId: null }));
    }
  }, [editingId, effectiveProjectId]);

  const availableEnvironments = useMemo(
    () => environments.filter((environment) => environment.projectId === draft.projectId),
    [draft.projectId, environments],
  );
  const visibleModels = useMemo(
    () => effectiveProjectId ? models.filter((model) => model.projectId === effectiveProjectId) : models,
    [effectiveProjectId, models],
  );

  const reset = () => {
    setEditingId(null);
    setDraft(initialDraft(effectiveProjectId));
  };

  const toggleRole = (role: ModelRole) => {
    setDraft((current) => ({
      ...current,
      roles: current.roles.includes(role)
        ? current.roles.filter((item) => item !== role)
        : [...current.roles, role],
    }));
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setMessage(null);
    if (!draft.projectId || !draft.name.trim() || !draft.model.trim() || draft.roles.length === 0) {
      setMessage(t(locale, "communityModelFormRequired"));
      return;
    }
    try {
      if (editingId) {
        await updateCommunityModel(editingId, draft);
      } else {
        await createCommunityModel(draft);
      }
      await onRefreshModels();
      reset();
      setMessage(t(locale, "modelConfigurationSaved"));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : t(locale, "modelSaveFailed"));
    }
  };

  const edit = (model: ModelItem) => {
    setEditingId(model.id);
    setMessage(null);
    setDraft({
      name: model.name,
      projectId: model.projectId,
      environmentId: model.environmentId,
      provider: model.provider as ModelProvider,
      model: model.model,
      baseUrl: model.baseUrl,
      apiKeyRef: null,
      roles: model.roles as ModelRole[],
      priority: model.priority,
      enabled: model.enabled,
      capabilities: {
        tools: Boolean(model.capabilities.tools),
        vision: Boolean(model.capabilities.vision),
        json: Boolean(model.capabilities.json),
        longContext: Boolean(model.capabilities.longContext),
        streaming: Boolean(model.capabilities.streaming),
        local: Boolean(model.capabilities.local),
      },
      config: {
        timeoutMs: Number(model.config.timeoutMs ?? 30000),
        maxRetries: Number(model.config.maxRetries ?? 2),
        temperature: Number(model.config.temperature ?? 0.2),
      },
    });
  };

  const runAction = async (model: ModelItem, action: "health" | "scan" | "delete") => {
    if (action === "delete" && !window.confirm(t(locale, "deleteModelConfirmation"))) return;
    setBusyId(model.id);
    setMessage(null);
    try {
      if (action === "health") {
        const result = await runCommunityModelHealthCheck(model.id);
        setMessage(`${t(locale, "connectionTest")}: ${result.status}`);
      } else if (action === "scan") {
        await runCommunityModelCapabilityScan(model.id);
        setMessage(t(locale, "capabilityDeclarationRecorded"));
      } else {
        await deleteCommunityModel(model.id);
        if (editingId === model.id) reset();
        setMessage(t(locale, "modelConfigurationDeleted"));
      }
      await onRefreshModels();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : t(locale, "operationFailed"));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="page-shell" data-route="/model-config">
      <div className="page-columns">
        <SectionCard title={t(locale, "communityMultiModelBindings")} eyebrow={t(locale, "communityConfiguration")}>
          <p className="muted-copy">
            {t(locale, "communityModelResolutionBoundary")}
          </p>
          {message ? <p className="inline-notice">{message}</p> : null}
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>{t(locale, "name")}</th><th>{t(locale, "model")}</th><th>{t(locale, "roles")}</th><th>{t(locale, "environment")}</th><th>{t(locale, "status")}</th><th>{t(locale, "actions")}</th></tr></thead>
              <tbody>
                {visibleModels.map((model) => (
                  <tr key={model.id}>
                    <td>{model.name}</td><td>{model.provider} / {model.model}</td><td>{model.roles.join(", ")}</td>
                    <td>{model.environmentId ? environments.find((item) => item.id === model.environmentId)?.name ?? model.environmentId.slice(0, 8) : t(locale, "projectDefault")}</td>
                    <td>{model.healthStatus}</td>
                    <td><div className="table-actions"><button disabled={busyId === model.id} onClick={() => edit(model)} type="button">{t(locale, "edit")}</button><button disabled={busyId === model.id} onClick={() => void runAction(model, "health")} type="button">{t(locale, "test")}</button><button disabled={busyId === model.id} onClick={() => void runAction(model, "scan")} type="button">{t(locale, "capabilities")}</button><button disabled={busyId === model.id} onClick={() => void runAction(model, "delete")} type="button">{t(locale, "delete")}</button></div></td>
                  </tr>
                ))}
                {visibleModels.length === 0 ? <tr><td colSpan={6}>{t(locale, "noCommunityModels")}</td></tr> : null}
              </tbody>
            </table>
          </div>
        </SectionCard>

        <SectionCard title={editingId ? t(locale, "editModel") : t(locale, "addModel")} eyebrow={t(locale, "controlledCredentialReference")}>
          <form className="stacked-form" onSubmit={(event) => void submit(event)}>
            <label>{t(locale, "project")}<select disabled={Boolean(editingId)} value={draft.projectId ?? ""} onChange={(event) => setDraft({ ...draft, projectId: event.target.value || null, environmentId: null })}><option value="">{t(locale, "select")}</option>{projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label>
            <label>{t(locale, "environmentOptional")}<select value={draft.environmentId ?? ""} onChange={(event) => setDraft({ ...draft, environmentId: event.target.value || null })}><option value="">{t(locale, "projectDefault")}</option>{availableEnvironments.map((environment) => <option key={environment.id} value={environment.id}>{environment.name}</option>)}</select></label>
            <label>{t(locale, "configurationName")}<input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} /></label>
            <label>{t(locale, "provider")}<select value={draft.provider} onChange={(event) => setDraft({ ...draft, provider: event.target.value as ModelProvider })}>{providers.map((provider) => <option key={provider} value={provider}>{provider}</option>)}</select></label>
            <label>{t(locale, "modelIdentifier")}<input value={draft.model} onChange={(event) => setDraft({ ...draft, model: event.target.value })} /></label>
            <label>{t(locale, "baseUrl")}<input placeholder="http://localhost:11434" value={draft.baseUrl ?? ""} onChange={(event) => setDraft({ ...draft, baseUrl: event.target.value || null })} /></label>
            <label>{t(locale, "apiKeyReference")}<input placeholder="env://OPENAI_API_KEY" value={draft.apiKeyRef ?? ""} onChange={(event) => setDraft({ ...draft, apiKeyRef: event.target.value || null })} /></label>
            <fieldset><legend>{t(locale, "boundRoles")}</legend>{roles.map((role) => <label className="check-row" key={role}><input checked={draft.roles.includes(role)} onChange={() => toggleRole(role)} type="checkbox" />{role}</label>)}</fieldset>
            <label>{t(locale, "priority")}<input min={0} type="number" value={draft.priority} onChange={(event) => setDraft({ ...draft, priority: Number(event.target.value) })} /></label>
            <label className="check-row"><input checked={draft.enabled} onChange={(event) => setDraft({ ...draft, enabled: event.target.checked })} type="checkbox" />{t(locale, "enabled")}</label>
            <div className="form-actions"><button disabled={!canManageModels} type="submit">{editingId ? t(locale, "save") : t(locale, "add")}</button>{editingId ? <button onClick={reset} type="button">{t(locale, "cancel")}</button> : null}</div>
          </form>
        </SectionCard>
      </div>
    </div>
  );
}
