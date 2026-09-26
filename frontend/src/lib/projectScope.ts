/* SPDX-License-Identifier: Apache-2.0 */
export const ALL_PROJECTS_ID = "all-projects";

type ProjectIdentity = {
  id: string;
};

export function resolveAvailableProjectId(
  selectedProjectId: string,
  projects: ProjectIdentity[],
  requireSpecificProject: boolean,
) {
  if (projects.some((project) => project.id === selectedProjectId)) {
    return selectedProjectId;
  }

  if (requireSpecificProject && projects.length > 0) {
    return projects[0].id;
  }

  return ALL_PROJECTS_ID;
}
