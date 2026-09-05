/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useMemo, useState } from "react";

import type { CurrentUser, EnvironmentItem, EnvironmentMutationPayload, ProjectItem } from "../lib/api";
import { Locale, t } from "../i18n";

type EnvironmentSettingsPageProps = {
  currentUser: CurrentUser | null;
  environments: EnvironmentItem[];
  locale: Locale;
  onArchiveEnvironment: (environmentId: string) => Promise<void>;
  onCreateEnvironment: (projectId: string, payload: EnvironmentMutationPayload) => Promise<void>;
  onSelectProject: (projectId: string) => void;
  onUpdateEnvironment: (environmentId: string, payload: Partial<EnvironmentMutationPayload>) => Promise<void>;
  projects: ProjectItem[];
  selectedProjectId: string;
};

const ENVIRONMENT_STATUS_OPTIONS = ["active", "disabled", "archived"];

function hasCapability(user: CurrentUser | null, capability: string) {
  return user?.capabilities.includes(capability) ?? false;
}

export function EnvironmentSettingsPage({
  currentUser,
  environments,
  locale,
  onArchiveEnvironment,
  onCreateEnvironment,
  onSelectProject,
  onUpdateEnvironment,
  projects,
  selectedProjectId,
}: EnvironmentSettingsPageProps) {
  const canManageEnvironments = hasCapability(currentUser, "environment.settings.manage");
  const selectedProject = useMemo(
    () => projects.find((project) => project.id === selectedProjectId) ?? projects[0] ?? null,
    [projects, selectedProjectId],
  );
  const visibleEnvironments = selectedProject ? environments.filter((environment) => environment.projectId === selectedProject.id) : [];
  const [selectedEnvironmentId, setSelectedEnvironmentId] = useState<string | null>(null);
  const selectedEnvironment = visibleEnvironments.find((environment) => environment.id === selectedEnvironmentId) ?? visibleEnvironments[0] ?? null;
  const [form, setForm] = useState({ key: "", name: "", description: "", baseUrl: "", status: "active" });
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const actionRequirementId = "environment-action-requirement";
  const updateRequirementId = "environment-update-requirement";

  useEffect(() => {
    if (selectedEnvironment) {
      setForm({
        key: selectedEnvironment.key,
        name: selectedEnvironment.name,
        description: selectedEnvironment.description ?? "",
        baseUrl: selectedEnvironment.baseUrl ?? "",
        status: selectedEnvironment.status,
      });
    } else {
      setForm({ key: "", name: "", description: "", baseUrl: "", status: "active" });
    }
  }, [selectedEnvironment]);

  const submitCreate = async () => {
    if (!canManageEnvironments) {
      setMessage(t(locale, "settingsReadOnlyNotice"));
      return;
    }
    if (!selectedProject) {
      setMessage(t(locale, "environmentProjectRequired"));
      return;
    }
    setSaving(true);
    setMessage(null);
    try {
      await onCreateEnvironment(selectedProject.id, {
        key: form.key,
        name: form.name,
        description: form.description || null,
        baseUrl: form.baseUrl || null,
        status: form.status,
        variables: {},
        metadata: {},
      });
      setMessage(t(locale, "environmentSaved"));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : t(locale, "environmentSaveFailed"));
    } finally {
      setSaving(false);
    }
  };

  const submitUpdate = async () => {
    if (!canManageEnvironments) {
      setMessage(t(locale, "settingsReadOnlyNotice"));
      return;
    }
    if (!selectedEnvironment) {
      setMessage(t(locale, "environmentSelectionRequired"));
      return;
    }
    setSaving(true);
    setMessage(null);
    try {
      await onUpdateEnvironment(selectedEnvironment.id, {
        key: form.key,
        name: form.name,
        description: form.description || null,
        baseUrl: form.baseUrl || null,
        status: form.status,
        variables: selectedEnvironment.variables,
        metadata: selectedEnvironment.metadata,
      });
      setMessage(t(locale, "environmentSaved"));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : t(locale, "environmentSaveFailed"));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="page-shell" data-route="/environment-settings">
      <div className="page-toolbar">
        <div>
          <span className="eyebrow">{t(locale, "backendCapabilityChecks")}</span>
          <h1>{t(locale, "environmentSettings")}</h1>
        </div>
        <div className="badge-row">
          <span className={canManageEnvironments ? "status-pill status-pill--covered" : "status-pill status-pill--unknown"}>
            environment.settings.manage
          </span>
        </div>
      </div>

      {!canManageEnvironments ? <div className="notice-banner" id={actionRequirementId}>{t(locale, "settingsReadOnlyNotice")}</div> : null}
      {canManageEnvironments && !selectedProject ? (
        <div className="notice-banner" id={actionRequirementId} role="status">{t(locale, "environmentProjectRequired")}</div>
      ) : null}
      {message ? <div className="notice-banner" role="status">{message}</div> : null}

      <section className="panel">
        <div className="panel__header">
          <span className="eyebrow">{t(locale, "realProjectSource")}</span>
          <h2>{t(locale, "project")}</h2>
        </div>
        <div className="control-form control-form--inline">
          <label className="form-field">
            {t(locale, "project")}
            <select
              aria-describedby={!selectedProject ? actionRequirementId : undefined}
              disabled={projects.length === 0}
              value={selectedProject?.id ?? ""}
              onChange={(event) => onSelectProject(event.target.value)}
            >
              {projects.map((project) => (
                <option key={project.id} value={project.id}>
                  {project.name}
                </option>
              ))}
            </select>
          </label>
          <span className="status-pill">{selectedProject?.status ?? t(locale, "none")}</span>
          <span className="status-pill">
            {t(locale, "environments")}: {visibleEnvironments.length}
          </span>
        </div>
      </section>

      <div className="page-columns">
        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "projectScoped")}</span>
            <h2>{t(locale, "environments")}</h2>
          </div>
          <div className="table-wrap">
            <table className="data-table data-table--compact">
              <thead>
                <tr>
                  <th>{t(locale, "environmentKey")}</th>
                  <th>{t(locale, "environmentName")}</th>
                  <th>{t(locale, "baseUrl")}</th>
                  <th>{t(locale, "status")}</th>
                  <th>{t(locale, "actions")}</th>
                </tr>
              </thead>
              <tbody>
                {visibleEnvironments.map((environment) => (
                  <tr className={environment.id === selectedEnvironment?.id ? "data-table__row--selected" : ""} key={environment.id}>
                    <td>{environment.key}</td>
                    <td>
                      <strong>{environment.name}</strong>
                      <p>{environment.description ?? t(locale, "none")}</p>
                    </td>
                    <td>{environment.baseUrl ?? t(locale, "none")}</td>
                    <td>{environment.status}</td>
                    <td>
                      <div className="button-row">
                        <button className="link-button" onClick={() => setSelectedEnvironmentId(environment.id)} type="button">
                          {t(locale, "select")}
                        </button>
                        <button
                          className="link-button link-button--danger"
                          disabled={!canManageEnvironments || saving}
                          onClick={() => void onArchiveEnvironment(environment.id)}
                          type="button"
                        >
                          {t(locale, "archive")}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {visibleEnvironments.length === 0 ? (
                  <tr>
                    <td colSpan={5}>{t(locale, "noEnvironments")}</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "auditTraceNotice")}</span>
            <h2>{t(locale, "environmentDetails")}</h2>
          </div>
          <div className="control-form">
            <label className="form-field">
              {t(locale, "environmentKey")}
              <input
                className="text-input"
                disabled={!canManageEnvironments}
                onChange={(event) => setForm((current) => ({ ...current, key: event.target.value }))}
                value={form.key}
              />
            </label>
            <label className="form-field">
              {t(locale, "environmentName")}
              <input
                className="text-input"
                disabled={!canManageEnvironments}
                onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
                value={form.name}
              />
            </label>
            <label className="form-field">
              {t(locale, "description")}
              <input
                className="text-input"
                disabled={!canManageEnvironments}
                onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))}
                value={form.description}
              />
            </label>
            <label className="form-field">
              {t(locale, "baseUrl")}
              <input
                className="text-input"
                disabled={!canManageEnvironments}
                onChange={(event) => setForm((current) => ({ ...current, baseUrl: event.target.value }))}
                value={form.baseUrl}
              />
            </label>
            <label className="form-field">
              {t(locale, "status")}
              <select disabled={!canManageEnvironments} onChange={(event) => setForm((current) => ({ ...current, status: event.target.value }))} value={form.status}>
                {ENVIRONMENT_STATUS_OPTIONS.map((statusOption) => (
                  <option key={statusOption} value={statusOption}>
                    {statusOption}
                  </option>
                ))}
              </select>
            </label>
            <div className="button-row">
              <button
                aria-describedby={!canManageEnvironments || !selectedProject ? actionRequirementId : undefined}
                className="primary-button"
                data-mutation-control
                disabled={!canManageEnvironments || !selectedProject || saving}
                onClick={submitCreate}
                type="button"
              >
                {t(locale, "createEnvironment")}
              </button>
              <button
                aria-describedby={
                  !canManageEnvironments || !selectedProject
                    ? actionRequirementId
                    : !selectedEnvironment ? updateRequirementId : undefined
                }
                className="secondary-button"
                data-mutation-control
                disabled={!canManageEnvironments || !selectedEnvironment || saving}
                onClick={submitUpdate}
                type="button"
              >
                {t(locale, "updateEnvironment")}
              </button>
            </div>
            {canManageEnvironments && selectedProject && !selectedEnvironment ? (
              <p className="control-requirement" id={updateRequirementId}>{t(locale, "environmentSelectionRequired")}</p>
            ) : null}
          </div>
        </section>
      </div>
    </div>
  );
}
