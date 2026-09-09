/* SPDX-License-Identifier: Apache-2.0 */
/* eslint-disable react-refresh/only-export-components, @typescript-eslint/no-unused-vars --
 * This profile adapter intentionally co-locates null page components with a
 * fail-closed API facade so the shared shell has one compile-time boundary.
 */
import type { ComponentType } from "react";
import type {
  CapabilityBindingMutationPayload,
  ConnectorBindingMutationPayload,
  ConnectorBindingUpdatePayload,
  EnvironmentMutationPayload,
  ProjectMemberMutationPayload,
  ProjectMutationPayload,
} from "../lib/api";
import {
  archiveCommunityEnvironment,
  archiveCommunityConnectorBinding,
  archiveCommunityProject,
  createCommunityConnectorBinding,
  createCommunityCapabilityBinding,
  createCommunityEnvironment,
  createCommunityProject,
  createCommunityProjectMember,
  fetchCommunityModels,
  fetchCommunityConnectorBindings,
  updateCommunityEnvironment,
  updateCommunityConnectorBinding,
  updateCommunityProject,
  updateCommunityProjectMember,
} from "../lib/api";
import { EnvironmentSettingsPage as CommunityEnvironmentSettingsPage } from "../pages/EnvironmentSettingsPage";
import { CommunityModelsPage } from "../pages/CommunityModelsPage";
import { ConnectorSettingsPage as CommunityConnectorSettingsPage } from "../pages/ConnectorSettingsPage";
import { ProjectSettingsPage as CommunityProjectSettingsPage } from "../pages/ProjectSettingsPage";


// Enterprise sections are excluded from OSS navigation before rendering. These
// null components are a compile-time boundary only: they keep the shared App
// type-safe without importing or bundling proprietary page implementations.
const UnavailableEnterprisePage: ComponentType<Record<string, unknown>> = () => null;

export const AccessControlPage = UnavailableEnterprisePage;
export const AdvancedVisualizationPage = UnavailableEnterprisePage;
export const ConnectorSettingsPage = CommunityConnectorSettingsPage;
export const CorrectionGovernancePage = UnavailableEnterprisePage;
export const EnterpriseModulesPage = UnavailableEnterprisePage;
export const EnvironmentSettingsPage = CommunityEnvironmentSettingsPage;
export const GraphCorrectionsPage = UnavailableEnterprisePage;
export const ImprovementProposalsPage = UnavailableEnterprisePage;
export const InteractiveGovernancePage = UnavailableEnterprisePage;
export const KnowledgeGovernancePage = UnavailableEnterprisePage;
export const LessonsCenterPage = UnavailableEnterprisePage;
export const ModelsPage = CommunityModelsPage;
export const ProjectSettingsPage = CommunityProjectSettingsPage;
export const ReplayRepositoryPage = UnavailableEnterprisePage;
export const SkillGovernancePanel = UnavailableEnterprisePage;

function unavailableEnterpriseOperation(operation: string): Promise<never> {
  return Promise.reject(new Error(`Enterprise operation is unavailable in the OSS profile: ${operation}`));
}

// The shared shell never invokes these methods in the OSS profile. The
// explicit fail-closed adapter keeps the compile-time contract stable without
// bundling endpoint paths or silently reporting success.
export const enterpriseApi = {
  createCapabilityBinding: (payload: CapabilityBindingMutationPayload) =>
    createCommunityCapabilityBinding(payload),
  createConnectorBinding: (payload: ConnectorBindingMutationPayload) =>
    createCommunityConnectorBinding(payload),
  createProject: (payload: ProjectMutationPayload) => createCommunityProject(payload),
  createProjectEnvironment: (projectId: string, payload: EnvironmentMutationPayload) =>
    createCommunityEnvironment(projectId, payload),
  createProjectMember: (projectId: string, payload: ProjectMemberMutationPayload) =>
    createCommunityProjectMember(projectId, payload),
  deleteConnectorBinding: (bindingId: string) => archiveCommunityConnectorBinding(bindingId),
  deleteEnvironment: (environmentId: string) => archiveCommunityEnvironment(environmentId),
  deleteProject: (projectId: string) => archiveCommunityProject(projectId),
  fetchConnectorBindings: (filters: Record<string, unknown> = {}) =>
    fetchCommunityConnectorBindings({
      connectorName: typeof filters.connectorName === "string" ? filters.connectorName : undefined,
      environmentId: typeof filters.environmentId === "string" ? filters.environmentId : undefined,
      projectId: typeof filters.projectId === "string" ? filters.projectId : undefined,
      status: typeof filters.status === "string" ? filters.status : undefined,
    }),
  fetchModels: () => fetchCommunityModels(),
  updateCapabilityBinding: (_bindingId: string, _payload: Partial<CapabilityBindingMutationPayload>) =>
    unavailableEnterpriseOperation("updateCapabilityBinding"),
  updateConnectorBinding: (bindingId: string, payload: ConnectorBindingUpdatePayload) =>
    updateCommunityConnectorBinding(bindingId, payload),
  updateEnvironment: (environmentId: string, payload: Partial<EnvironmentMutationPayload>) =>
    updateCommunityEnvironment(environmentId, payload),
  updateProject: (projectId: string, payload: Partial<ProjectMutationPayload>) =>
    updateCommunityProject(projectId, payload),
  updateProjectMember: (
    _memberId: string,
    _payload: Partial<Omit<ProjectMemberMutationPayload, "userId">>,
  ) => updateCommunityProjectMember(_memberId, _payload),
};
