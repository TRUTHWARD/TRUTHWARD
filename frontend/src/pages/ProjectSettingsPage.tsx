/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useMemo, useState } from "react";

import { createCommunityUser, fetchCommunityUsers, type CommunityUserItem, type CurrentUser, type ProjectItem, type ProjectMemberItem, type ProjectMemberMutationPayload, type ProjectMutationPayload } from "../lib/api";
import { Locale, t } from "../i18n";
import { IS_OSS_PROFILE } from "../productProfile";

type ProjectSettingsPageProps = {
  currentUser: CurrentUser | null;
  locale: Locale;
  members: ProjectMemberItem[];
  onArchiveProject: (projectId: string) => Promise<void>;
  onCreateMember: (projectId: string, payload: ProjectMemberMutationPayload) => Promise<void>;
  onCreateProject: (payload: ProjectMutationPayload) => Promise<void>;
  onLoadMembers: (projectId: string) => Promise<void>;
  onSelectProject: (projectId: string) => void;
  onUpdateMember: (memberId: string, payload: Partial<Omit<ProjectMemberMutationPayload, "userId">>) => Promise<void>;
  onUpdateProject: (projectId: string, payload: Partial<ProjectMutationPayload>) => Promise<void>;
  projects: ProjectItem[];
  selectedProjectId: string;
};

const PROJECT_STATUS_OPTIONS = ["active", "archived"];
const MEMBER_ROLE_OPTIONS = ["owner", "admin", "member", "viewer"];
const MEMBER_STATUS_OPTIONS = ["active", "inactive"];

function hasCapability(user: CurrentUser | null, capability: string) {
  return user?.capabilities.includes(capability) ?? false;
}

export function ProjectSettingsPage({
  currentUser,
  locale,
  members,
  onArchiveProject,
  onCreateMember,
  onCreateProject,
  onLoadMembers,
  onSelectProject,
  onUpdateMember,
  onUpdateProject,
  projects,
  selectedProjectId,
}: ProjectSettingsPageProps) {
  const canManageProjects = hasCapability(currentUser, "project.settings.manage");
  const canManageMembers = hasCapability(currentUser, "project.members.manage");
  const selectedProject = useMemo(
    () => projects.find((project) => project.id === selectedProjectId) ?? projects[0] ?? null,
    [projects, selectedProjectId],
  );
  const [projectForm, setProjectForm] = useState({ key: "", name: "", description: "", status: "active" });
  const [memberForm, setMemberForm] = useState({ userId: currentUser?.id ?? "", role: "viewer", status: "active" });
  const [communityUsers, setCommunityUsers] = useState<CommunityUserItem[]>([]);
  const [userForm, setUserForm] = useState({ username: "", email: "", displayName: "", password: "" });
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (selectedProject) {
      setProjectForm({
        key: selectedProject.key,
        name: selectedProject.name,
        description: selectedProject.description ?? "",
        status: selectedProject.status,
      });
      void onLoadMembers(selectedProject.id);
    }
  }, [selectedProject?.id]);

  useEffect(() => {
    if (!IS_OSS_PROFILE || !canManageMembers) return;
    void fetchCommunityUsers().then((result) => {
      setCommunityUsers(result.items);
      setMemberForm((current) => ({ ...current, userId: current.userId || result.items[0]?.id || "" }));
    }).catch(() => setCommunityUsers([]));
  }, [canManageMembers]);

  const submitNewProject = async () => {
    if (!canManageProjects) {
      return;
    }
    setSaving(true);
    setMessage(null);
    try {
      await onCreateProject({
        key: projectForm.key,
        name: projectForm.name,
        description: projectForm.description || null,
        status: projectForm.status,
        metadata: {},
      });
      setMessage(t(locale, "projectSaved"));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : t(locale, "projectSaveFailed"));
    } finally {
      setSaving(false);
    }
  };

  const submitProjectUpdate = async () => {
    if (!canManageProjects || !selectedProject) {
      return;
    }
    setSaving(true);
    setMessage(null);
    try {
      await onUpdateProject(selectedProject.id, {
        key: projectForm.key,
        name: projectForm.name,
        description: projectForm.description || null,
        status: projectForm.status,
        metadata: selectedProject.metadata,
      });
      setMessage(t(locale, "projectSaved"));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : t(locale, "projectSaveFailed"));
    } finally {
      setSaving(false);
    }
  };

  const submitMember = async () => {
    if (!canManageMembers || !selectedProject) {
      return;
    }
    setSaving(true);
    setMessage(null);
    try {
      await onCreateMember(selectedProject.id, {
        userId: memberForm.userId,
        role: memberForm.role,
        status: memberForm.status,
        metadata: {},
      });
      setMessage(t(locale, "memberSaved"));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : t(locale, "memberSaveFailed"));
    } finally {
      setSaving(false);
    }
  };

  const submitCommunityUser = async () => {
    if (!canManageMembers) return;
    setSaving(true);
    setMessage(null);
    try {
      const created = await createCommunityUser(userForm);
      setCommunityUsers((current) => [...current, created]);
      setMemberForm((current) => ({ ...current, userId: created.id }));
      setUserForm({ username: "", email: "", displayName: "", password: "" });
      setMessage(t(locale, "memberSaved"));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : t(locale, "projectSaveFailed"));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="page-shell" data-route="/project-settings">
      <div className="page-toolbar">
        <div>
          <span className="eyebrow">{t(locale, "backendCapabilityChecks")}</span>
          <h1>{t(locale, "projectSettings")}</h1>
        </div>
        <div className="badge-row">
          <span className={canManageProjects ? "status-pill status-pill--covered" : "status-pill status-pill--unknown"}>
            project.settings.manage
          </span>
          <span className={canManageMembers ? "status-pill status-pill--covered" : "status-pill status-pill--unknown"}>
            project.members.manage
          </span>
        </div>
      </div>

      {!canManageProjects ? <div className="notice-banner">{t(locale, "settingsReadOnlyNotice")}</div> : null}
      {message ? <div className="notice-banner">{message}</div> : null}

      <div className="page-columns">
        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "realProjectSource")}</span>
            <h2>{t(locale, "projects")}</h2>
          </div>
          <div aria-label={t(locale, "projects")} className="table-wrap" tabIndex={0}>
            <table className="data-table data-table--compact">
              <thead>
                <tr>
                  <th>{t(locale, "projectKey")}</th>
                  <th>{t(locale, "projectName")}</th>
                  <th>{t(locale, "status")}</th>
                  <th>{t(locale, "plans")}</th>
                  <th>{t(locale, "members")}</th>
                  <th>{t(locale, "actions")}</th>
                </tr>
              </thead>
              <tbody>
                {projects.map((project) => (
                  <tr className={project.id === selectedProject?.id ? "data-table__row--selected" : ""} key={project.id}>
                    <td>{project.key}</td>
                    <td>
                      <strong>{project.name}</strong>
                      <p>{project.description ?? t(locale, "none")}</p>
                    </td>
                    <td>{project.status}</td>
                    <td>{project.planCount}</td>
                    <td>{project.memberCount}</td>
                    <td>
                      <div className="button-row">
                        <button className="link-button" onClick={() => onSelectProject(project.id)} type="button">
                          {t(locale, "select")}
                        </button>
                        <button
                          className="link-button link-button--danger"
                          disabled={!canManageProjects || saving}
                          onClick={() => void onArchiveProject(project.id)}
                          type="button"
                        >
                          {t(locale, "archive")}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {projects.length === 0 ? (
                  <tr>
                    <td colSpan={6}>{t(locale, "noProjects")}</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "auditTraceNotice")}</span>
            <h2>{t(locale, "projectDetails")}</h2>
          </div>
          <div className="control-form">
            <label className="form-field">
              {t(locale, "projectKey")}
              <input
                className="text-input"
                disabled={!canManageProjects}
                onChange={(event) => setProjectForm((current) => ({ ...current, key: event.target.value }))}
                value={projectForm.key}
              />
            </label>
            <label className="form-field">
              {t(locale, "projectName")}
              <input
                className="text-input"
                disabled={!canManageProjects}
                onChange={(event) => setProjectForm((current) => ({ ...current, name: event.target.value }))}
                value={projectForm.name}
              />
            </label>
            <label className="form-field">
              {t(locale, "description")}
              <input
                className="text-input"
                disabled={!canManageProjects}
                onChange={(event) => setProjectForm((current) => ({ ...current, description: event.target.value }))}
                value={projectForm.description}
              />
            </label>
            <label className="form-field">
              {t(locale, "status")}
              <select
                disabled={!canManageProjects}
                onChange={(event) => setProjectForm((current) => ({ ...current, status: event.target.value }))}
                value={projectForm.status}
              >
                {PROJECT_STATUS_OPTIONS.map((statusOption) => (
                  <option key={statusOption} value={statusOption}>
                    {statusOption}
                  </option>
                ))}
              </select>
            </label>
            <div className="button-row">
              <button disabled={!canManageProjects || saving} onClick={submitNewProject} type="button">
                {t(locale, "createProject")}
              </button>
              <button disabled={!canManageProjects || !selectedProject || saving} onClick={submitProjectUpdate} type="button">
                {t(locale, "updateProject")}
              </button>
            </div>
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="panel__header">
          <span className="eyebrow">{t(locale, "projectRoleBoundary")}</span>
          <h2>{t(locale, "members")}</h2>
        </div>
        <div aria-label={t(locale, "members")} className="table-wrap" tabIndex={0}>
          <table className="data-table data-table--compact">
            <thead>
              <tr>
                <th>{t(locale, "user")}</th>
                <th>{t(locale, "role")}</th>
                <th>{t(locale, "status")}</th>
                <th>{t(locale, "actions")}</th>
              </tr>
            </thead>
            <tbody>
              {members.map((member) => (
                <tr key={member.id}>
                  <td>
                    <strong>{member.userName ?? member.userId ?? t(locale, "none")}</strong>
                    <p>{member.userEmail ?? member.userId ?? t(locale, "none")}</p>
                  </td>
                  <td>{member.role}</td>
                  <td>{member.status}</td>
                  <td>
                    <div className="button-row">
                      {MEMBER_ROLE_OPTIONS.map((role) => (
                        <button
                          className="link-button"
                          disabled={!canManageMembers || member.role === role || saving}
                          key={role}
                          onClick={() => void onUpdateMember(member.id, { role })}
                          type="button"
                        >
                          {role}
                        </button>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
              {members.length === 0 ? (
                <tr>
                  <td colSpan={4}>{t(locale, "noMembers")}</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
        <div className="control-form control-form--inline">
          <label className="form-field">
            {t(locale, "userId")}
            <select
              disabled={!canManageMembers}
              onChange={(event) => setMemberForm((current) => ({ ...current, userId: event.target.value }))}
              value={memberForm.userId}
            >
              <option value="">{t(locale, "select")}</option>
              {communityUsers.map((communityUser) => (
                <option key={communityUser.id} value={communityUser.id}>{communityUser.displayName} ({communityUser.username})</option>
              ))}
            </select>
          </label>
          <label className="form-field">
            {t(locale, "role")}
            <select
              disabled={!canManageMembers}
              onChange={(event) => setMemberForm((current) => ({ ...current, role: event.target.value }))}
              value={memberForm.role}
            >
              {MEMBER_ROLE_OPTIONS.map((role) => (
                <option key={role} value={role}>
                  {role}
                </option>
              ))}
            </select>
          </label>
          <label className="form-field">
            {t(locale, "status")}
            <select
              disabled={!canManageMembers}
              onChange={(event) => setMemberForm((current) => ({ ...current, status: event.target.value }))}
              value={memberForm.status}
            >
              {MEMBER_STATUS_OPTIONS.map((statusOption) => (
                <option key={statusOption} value={statusOption}>
                  {statusOption}
                </option>
              ))}
            </select>
          </label>
          <button disabled={!canManageMembers || !selectedProject || !memberForm.userId || saving} onClick={submitMember} type="button">
            {t(locale, "addMember")}
          </button>
        </div>
        {IS_OSS_PROFILE && canManageMembers ? (
          <div className="control-form control-form--inline">
            <label className="form-field">{t(locale, "username")}<input value={userForm.username} onChange={(event) => setUserForm((current) => ({ ...current, username: event.target.value }))} /></label>
            <label className="form-field">{t(locale, "email")}<input type="email" value={userForm.email} onChange={(event) => setUserForm((current) => ({ ...current, email: event.target.value }))} /></label>
            <label className="form-field">{t(locale, "displayName")}<input value={userForm.displayName} onChange={(event) => setUserForm((current) => ({ ...current, displayName: event.target.value }))} /></label>
            <label className="form-field">{t(locale, "initialPassword")}<input minLength={12} type="password" value={userForm.password} onChange={(event) => setUserForm((current) => ({ ...current, password: event.target.value }))} /></label>
            <button disabled={saving || !userForm.username || !userForm.email || !userForm.displayName || userForm.password.length < 12} onClick={() => void submitCommunityUser()} type="button">{t(locale, "createLocalUser")}</button>
          </div>
        ) : null}
      </section>
    </div>
  );
}
