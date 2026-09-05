/* SPDX-License-Identifier: Apache-2.0 */
import { Locale, t } from "../i18n";
import { IS_OSS_PROFILE } from "../productProfile";

export type ProjectOption = {
  id: string;
  key: string;
  name: string;
  planCount: number;
  executionCount: number;
  environments: string[];
  environmentCount: number;
  memberCount: number;
  status: string;
};

type ProjectSwitcherProps = {
  locale: Locale;
  onSelectProject: (projectId: string) => void;
  projects: ProjectOption[];
  selectedProjectId: string;
};

export function ProjectSwitcher({ locale, onSelectProject, projects, selectedProjectId }: ProjectSwitcherProps) {
  const currentProject = projects.find((project) => project.id === selectedProjectId) ?? projects[0] ?? null;

  if (IS_OSS_PROFILE && projects.length === 0) {
    return (
      <div className="project-switcher project-switcher--empty">
        <span>{t(locale, "projectScope")}</span>
        <strong>{t(locale, "noProjects")}</strong>
      </div>
    );
  }

  if (IS_OSS_PROFILE && projects.length === 1) {
    return (
      <div className="project-switcher project-switcher--static">
        <span>{t(locale, "projectScope")}</span>
        <strong>{projects[0].name}</strong>
      </div>
    );
  }

  return (
    <div className="project-switcher">
      <label className="project-switcher__field">
        <span>{t(locale, "projectScope")}</span>
        <span className="project-switcher__control">
          <span aria-hidden="true" className="project-switcher__indicator" />
          <select onChange={(event) => onSelectProject(event.target.value)} value={currentProject?.id ?? selectedProjectId}>
            {projects.map((project) => (
              <option key={project.id} value={project.id}>
                {project.name}
              </option>
            ))}
          </select>
          <span aria-hidden="true" className="project-switcher__chevron" />
        </span>
      </label>
    </div>
  );
}
