/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useMemo, useState } from "react";

import type {
  ConnectorBindingItem,
  ConnectorBindingMutationPayload,
  ConnectorBindingUpdatePayload,
  CurrentUser,
  EnvironmentItem,
  ProjectItem,
} from "../lib/api";
import { Locale, t } from "../i18n";

type ConnectorSettingsPageProps = {
  connectorBindings: ConnectorBindingItem[];
  currentUser: CurrentUser | null;
  environments: EnvironmentItem[];
  locale: Locale;
  onArchiveConnectorBinding: (bindingId: string) => Promise<void>;
  onCreateConnectorBinding: (payload: ConnectorBindingMutationPayload) => Promise<void>;
  onRefreshConnectorBindings: () => Promise<void>;
  onUpdateConnectorBinding: (bindingId: string, payload: ConnectorBindingUpdatePayload) => Promise<void>;
  projects: ProjectItem[];
  selectedProjectId: string;
};

const CONNECTOR_STATUS_OPTIONS = ["active", "disabled", "archived"];
const CONNECTOR_NAME_OPTIONS = [
  "github",
  "mock-requirement-docs",
  "lark-requirement-docs",
  "zentao-requirement-docs",
  "mock-issue-tracker",
  "jira",
  "zentao",
];
const COMMUNITY_CONNECTOR_NAME_OPTIONS = ["github", "gitlab", "mock-scm"];

function hasCapability(user: CurrentUser | null, capability: string) {
  return user?.capabilities.includes(capability) ?? false;
}

export function ConnectorSettingsPage({
  connectorBindings,
  currentUser,
  environments,
  locale,
  onArchiveConnectorBinding,
  onCreateConnectorBinding,
  onRefreshConnectorBindings,
  onUpdateConnectorBinding,
  projects,
  selectedProjectId,
}: ConnectorSettingsPageProps) {
  const isCommunity = currentUser?.edition === "community";
  const canManageConnectorBindings = hasCapability(currentUser, "capability_bindings.admin")
    || hasCapability(currentUser, "connector_bindings.manage");
  const connectorNameOptions = isCommunity ? COMMUNITY_CONNECTOR_NAME_OPTIONS : CONNECTOR_NAME_OPTIONS;
  const selectedProject = projects.find((project) => project.id === selectedProjectId) ?? projects[0] ?? null;
  const projectEnvironments = selectedProject ? environments.filter((environment) => environment.projectId === selectedProject.id) : environments;
  const visibleBindings = useMemo(() => {
    if (!selectedProject) {
      return connectorBindings;
    }
    return connectorBindings.filter((binding) => !binding.projectId || binding.projectId === selectedProject.id);
  }, [connectorBindings, selectedProject]);
  const [selectedBindingId, setSelectedBindingId] = useState<string | null>(null);
  const selectedBinding = visibleBindings.find((binding) => binding.id === selectedBindingId) ?? visibleBindings[0] ?? null;
  const [form, setForm] = useState({
    connectorName: "github",
    secretRef: isCommunity ? "env://COMMUNITY_GITHUB_WEBHOOK_SECRET" : "secret://workspace/github",
    credentialRef: "",
    baseUrl: "",
    projectId: selectedProject?.id ?? "",
    environmentId: "",
    status: "active",
  });
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (isCommunity && selectedProject?.id) {
      setForm((current) => current.projectId === selectedProject.id
        ? current
        : { ...current, projectId: selectedProject.id, environmentId: "" });
    }
  }, [isCommunity, selectedProject?.id]);

  const buildScope = () => {
    const scope: Record<string, unknown> = {};
    if (form.projectId) {
      scope.projectId = form.projectId;
    }
    if (form.environmentId) {
      scope.environmentId = form.environmentId;
    }
    if (form.baseUrl) {
      scope.baseUrl = form.baseUrl;
    }
    return scope;
  };

  const submitCreate = async () => {
    if (!canManageConnectorBindings) {
      return;
    }
    setSaving(true);
    setMessage(null);
    try {
      await onCreateConnectorBinding({
        connectorName: form.connectorName,
        secretRef: form.secretRef,
        credentialRef: form.credentialRef || null,
        scope: buildScope(),
        status: form.status,
      });
      setMessage(t(locale, "connectorBindingSaved"));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : t(locale, "connectorBindingSaveFailed"));
    } finally {
      setSaving(false);
    }
  };

  const submitUpdate = async () => {
    if (!canManageConnectorBindings || !selectedBinding) {
      return;
    }
    setSaving(true);
    setMessage(null);
    try {
      const update: ConnectorBindingUpdatePayload = { status: form.status };
      if (form.secretRef.trim()) update.secretRef = form.secretRef.trim();
      if (form.credentialRef.trim()) update.credentialRef = form.credentialRef.trim();
      if (form.baseUrl.trim() || form.projectId !== (selectedBinding.projectId ?? "") || form.environmentId !== (selectedBinding.environmentId ?? "")) {
        update.scope = buildScope();
      }
      await onUpdateConnectorBinding(selectedBinding.id, update);
      setMessage(t(locale, "connectorBindingSaved"));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : t(locale, "connectorBindingSaveFailed"));
    } finally {
      setSaving(false);
    }
  };

  const loadSelectedBinding = (binding: ConnectorBindingItem) => {
    setSelectedBindingId(binding.id);
    setForm({
      connectorName: binding.connectorName,
      secretRef: "",
      credentialRef: "",
      baseUrl: stringScopeValue(binding.scope, "baseUrl"),
      projectId: binding.projectId ?? "",
      environmentId: binding.environmentId ?? "",
      status: binding.status,
    });
  };

  return (
    <div className="page-shell" data-route="/connector-settings">
      <div className="page-toolbar">
        <div>
          <span className="eyebrow">{t(locale, "connectorBindingBoundary")}</span>
          <h1>{t(locale, "connectorSettings")}</h1>
        </div>
        <div className="badge-row">
          <span className={canManageConnectorBindings ? "status-pill status-pill--covered" : "status-pill status-pill--unknown"}>
            {isCommunity ? "connector_bindings.manage" : "capability_bindings.admin"}
          </span>
          <span className="status-pill">{t(locale, "secretRefOnly")}</span>
        </div>
      </div>

      {!canManageConnectorBindings ? <div className="notice-banner">{t(locale, "connectorBindingRestricted")}</div> : null}
      {canManageConnectorBindings ? <div className="notice-banner">{t(locale, "requirementDocumentConnectorConfigNotice")}</div> : null}
      {message ? <div className="notice-banner">{message}</div> : null}

      <section className="panel">
        <div className="panel__header">
          <span className="eyebrow">{t(locale, "projectScoped")}</span>
          <h2>{t(locale, "connectorBindings")}</h2>
        </div>
        <div className="button-row">
          <button disabled={!canManageConnectorBindings} onClick={() => void onRefreshConnectorBindings()} type="button">
            {t(locale, "refresh")}
          </button>
        </div>
        <div className="table-wrap">
          <table className="data-table data-table--compact">
            <thead>
              <tr>
                <th>{t(locale, "connectorName")}</th>
                <th>{t(locale, "scope")}</th>
                <th>{t(locale, "secretRef")}</th>
                <th>{t(locale, "status")}</th>
                <th>{t(locale, "actions")}</th>
              </tr>
            </thead>
            <tbody>
              {canManageConnectorBindings && visibleBindings.map((binding) => (
                <tr className={binding.id === selectedBinding?.id ? "data-table__row--selected" : ""} key={binding.id}>
                  <td>{binding.connectorName}</td>
                  <td>
                    <strong>{projectName(projects, binding.projectId) ?? t(locale, "globalScope")}</strong>
                    <p>{environmentName(environments, binding.environmentId) ?? t(locale, "allEnvironments")}</p>
                  </td>
                  <td>{binding.secretConfigured ? t(locale, "secretRefOnly") : t(locale, "notConfigured")}</td>
                  <td>{binding.status}</td>
                  <td>
                    <div className="button-row">
                      <button className="link-button" onClick={() => loadSelectedBinding(binding)} type="button">
                        {t(locale, "select")}
                      </button>
                      <button
                        className="link-button link-button--danger"
                        disabled={saving}
                        onClick={() => void onArchiveConnectorBinding(binding.id)}
                        type="button"
                      >
                        {t(locale, "archive")}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {canManageConnectorBindings && visibleBindings.length === 0 ? (
                <tr>
                  <td colSpan={5}>{t(locale, "noConnectorBindings")}</td>
                </tr>
              ) : null}
              {!canManageConnectorBindings ? (
                <tr>
                  <td colSpan={5}>{t(locale, "protectedDataNotRequested")}</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <div className="panel__header">
          <span className="eyebrow">{t(locale, "auditTraceNotice")}</span>
          <h2>{t(locale, "connectorBindingDetails")}</h2>
        </div>
        <div className="control-form control-form--inline">
          <label className="form-field">
            {t(locale, "connectorName")}
            <select
              disabled={!canManageConnectorBindings}
              onChange={(event) => setForm((current) => ({ ...current, connectorName: event.target.value }))}
              value={form.connectorName}
            >
              {connectorNameOptions.map((connectorName) => (
                <option key={connectorName} value={connectorName}>
                  {connectorName}
                </option>
              ))}
            </select>
          </label>
          <label className="form-field">
            {t(locale, "secretRef")}
            <input
              className="text-input"
              disabled={!canManageConnectorBindings}
              onChange={(event) => setForm((current) => ({ ...current, secretRef: event.target.value }))}
              value={form.secretRef}
            />
          </label>
          <label className="form-field">
            {t(locale, "credentialRef")}
            <input
              className="text-input"
              disabled={!canManageConnectorBindings}
              onChange={(event) => setForm((current) => ({ ...current, credentialRef: event.target.value }))}
              value={form.credentialRef}
            />
          </label>
          <label className="form-field">
            {t(locale, "connectorBaseUrl")}
            <input
              className="text-input"
              disabled={!canManageConnectorBindings}
              onChange={(event) => setForm((current) => ({ ...current, baseUrl: event.target.value }))}
              value={form.baseUrl}
            />
          </label>
          <label className="form-field">
            {t(locale, "project")}
            <select
              disabled={!canManageConnectorBindings}
              onChange={(event) => setForm((current) => ({ ...current, projectId: event.target.value, environmentId: "" }))}
              value={form.projectId}
            >
              {!isCommunity ? <option value="">{t(locale, "globalScope")}</option> : null}
              {projects.map((project) => (
                <option key={project.id} value={project.id}>
                  {project.name}
                </option>
              ))}
            </select>
          </label>
          <label className="form-field">
            {t(locale, "environment")}
            <select
              disabled={!canManageConnectorBindings || !form.projectId}
              onChange={(event) => setForm((current) => ({ ...current, environmentId: event.target.value }))}
              value={form.environmentId}
            >
              <option value="">{t(locale, "allEnvironments")}</option>
              {projectEnvironments.map((environment) => (
                <option key={environment.id} value={environment.id}>
                  {environment.name}
                </option>
              ))}
            </select>
          </label>
          <label className="form-field">
            {t(locale, "status")}
            <select disabled={!canManageConnectorBindings} onChange={(event) => setForm((current) => ({ ...current, status: event.target.value }))} value={form.status}>
              {CONNECTOR_STATUS_OPTIONS.map((statusOption) => (
                <option key={statusOption} value={statusOption}>
                  {statusOption}
                </option>
              ))}
            </select>
          </label>
          <div className="button-row">
            <button disabled={!canManageConnectorBindings || saving} onClick={submitCreate} type="button">
              {t(locale, "createConnectorBinding")}
            </button>
            <button disabled={!canManageConnectorBindings || !selectedBinding || saving} onClick={submitUpdate} type="button">
              {t(locale, "updateConnectorBinding")}
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}

function projectName(projects: ProjectItem[], projectId: string | null) {
  return projects.find((project) => project.id === projectId)?.name ?? null;
}

function environmentName(environments: EnvironmentItem[], environmentId: string | null) {
  return environments.find((environment) => environment.id === environmentId)?.name ?? null;
}

function stringScopeValue(scope: Record<string, unknown>, key: string) {
  const value = scope[key];
  return typeof value === "string" ? value : "";
}
