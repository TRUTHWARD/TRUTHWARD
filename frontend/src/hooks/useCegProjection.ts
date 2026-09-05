/* SPDX-License-Identifier: Apache-2.0 */
import { useCallback, useEffect, useState } from "react";

import {
  ApiRequestError,
  fetchCegEvidence,
  fetchCegGraphSummary,
  fetchCegPathDetail,
  fetchCegPaths,
  type CegEvidenceProjection,
  type CegGraphSummaryProjection,
  type CegNodeDetailProjection,
  type CegPathProjection,
} from "../lib/api";


export type CegLoadState = "unavailable" | "restricted" | "loading" | "ready" | "empty" | "error";

export type CegDeepLink = {
  graphId: string | null;
  versionId: string | null;
  pathId: string | null;
};

export function readCegDeepLink(): CegDeepLink {
  const query = new URLSearchParams(window.location.search);
  return {
    graphId: query.get("graphId"),
    versionId: query.get("versionId"),
    pathId: query.get("pathId"),
  };
}

export function useCegProjection(
  projectId: string | null,
  canRead: boolean,
  deepLink: CegDeepLink,
) {
  const [state, setState] = useState<CegLoadState>("unavailable");
  const [summary, setSummary] = useState<CegGraphSummaryProjection | null>(null);
  const [paths, setPaths] = useState<CegPathProjection | null>(null);
  const [detail, setDetail] = useState<CegNodeDetailProjection | null>(null);
  const [evidence, setEvidence] = useState<CegEvidenceProjection | null>(null);
  const [selectedGraphId, setSelectedGraphId] = useState<string | null>(deepLink.graphId);
  const [selectedVersionId, setSelectedVersionId] = useState<string | null>(deepLink.versionId);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(deepLink.pathId);
  const [search, setSearch] = useState("");
  const [identity, setIdentity] = useState("");
  const [riskLevel, setRiskLevel] = useState("");
  const [coverageStatus, setCoverageStatus] = useState("");

  const resetLowerLevels = useCallback((level: "graph" | "path") => {
    if (level === "graph") {
      setPaths(null);
      setSelectedPathId(null);
    }
    setDetail(null);
    setEvidence(null);
  }, []);

  const selectGraph = useCallback((graphId: string, versionId: string) => {
    setSelectedGraphId(graphId);
    setSelectedVersionId(versionId);
    resetLowerLevels("graph");
  }, [resetLowerLevels]);

  const selectPath = useCallback((pathId: string) => {
    if (pathId === selectedPathId) return;
    setSelectedPathId(pathId);
    resetLowerLevels("path");
  }, [resetLowerLevels, selectedPathId]);

  const loadSummary = useCallback(async () => {
    if (!projectId || !canRead) return;
    setState("loading");
    try {
      const projection = await fetchCegGraphSummary(projectId, {
        search: search || undefined,
        identity: identity || undefined,
        pageSize: 100,
      });
      setSummary(projection);
      setSelectedGraphId((current) => {
        const selected = projection.items.find((item) => item.graphId === current && item.graphVersionId)
          ?? projection.items.find((item) => item.graphVersionId);
        const nextGraphId = selected?.graphId ?? null;
        setSelectedVersionId(selected?.graphVersionId ?? null);
        if (!nextGraphId || nextGraphId !== current) {
          setPaths(null);
          setSelectedPathId(null);
          setDetail(null);
          setEvidence(null);
        }
        return nextGraphId;
      });
      setState(projection.items.length ? "ready" : "empty");
    } catch (error) {
      setSummary(null);
      if (error instanceof ApiRequestError && error.status === 403) setState("restricted");
      else if (error instanceof ApiRequestError && [404, 409, 410, 503].includes(error.status)) setState("unavailable");
      else setState("error");
    }
  }, [canRead, identity, projectId, search]);

  const loadPaths = useCallback(async (cursor?: string) => {
    if (!projectId || !selectedGraphId || !selectedVersionId) return;
    try {
      const projection = await fetchCegPaths(projectId, selectedGraphId, selectedVersionId, {
        search: search || undefined,
        identity: identity || undefined,
        riskLevel: riskLevel || undefined,
        coverageStatus: coverageStatus || undefined,
        pageSize: 50,
        cursor,
      });
      setPaths((current) => cursor && current ? { ...projection, items: [...current.items, ...projection.items] } : projection);
      if (!cursor) {
        setSelectedPathId((current) => {
          if (current && projection.items.some((item) => item.pathId === current)) return current;
          const nextPathId = projection.items[0]?.pathId ?? null;
          setDetail(null);
          setEvidence(null);
          return nextPathId;
        });
      }
    } catch (error) {
      if (error instanceof ApiRequestError && [403, 404, 409, 410, 503].includes(error.status)) {
        setPaths(null);
        if (error.status === 403) setState("restricted");
        else setState("unavailable");
      } else setState("error");
    }
  }, [coverageStatus, identity, projectId, riskLevel, search, selectedGraphId, selectedVersionId]);

  const loadDetailAndEvidence = useCallback(async () => {
    if (!projectId || !selectedGraphId || !selectedVersionId || !selectedPathId) return;
    try {
      const [detailProjection, evidenceProjection] = await Promise.all([
        fetchCegPathDetail(projectId, selectedGraphId, selectedVersionId, selectedPathId),
        fetchCegEvidence(projectId, selectedGraphId, selectedVersionId, { pathId: selectedPathId, pageSize: 100 }),
      ]);
      setDetail(detailProjection);
      setEvidence(evidenceProjection);
    } catch (error) {
      setDetail(null);
      setEvidence(null);
      if (error instanceof ApiRequestError && error.status === 403) setState("restricted");
      else if (error instanceof ApiRequestError && [404, 409, 410, 503].includes(error.status)) setState("unavailable");
      else setState("error");
    }
  }, [projectId, selectedGraphId, selectedPathId, selectedVersionId]);

  useEffect(() => {
    setSummary(null);
    setPaths(null);
    setDetail(null);
    setEvidence(null);
    setSelectedGraphId(deepLink.graphId);
    setSelectedVersionId(deepLink.versionId);
    setSelectedPathId(deepLink.pathId);
    if (!projectId) setState("unavailable");
    else if (!canRead) setState("restricted");
    else setState("loading");
  }, [canRead, deepLink.graphId, deepLink.pathId, deepLink.versionId, projectId]);

  useEffect(() => {
    if (projectId && canRead) void loadSummary();
  }, [canRead, loadSummary, projectId]);

  useEffect(() => {
    if (state === "ready" && selectedGraphId && selectedVersionId) void loadPaths();
  }, [loadPaths, selectedGraphId, selectedVersionId, state]);

  useEffect(() => {
    if (state === "ready" && selectedPathId) void loadDetailAndEvidence();
  }, [loadDetailAndEvidence, selectedPathId, state]);

  return {
    state,
    summary,
    paths,
    detail,
    evidence,
    selectedGraphId,
    selectedVersionId,
    selectedPathId,
    search,
    identity,
    riskLevel,
    coverageStatus,
    setSearch,
    setIdentity,
    setRiskLevel,
    setCoverageStatus,
    selectGraph,
    selectPath,
    loadMorePaths: () => loadPaths(paths?.page.nextCursor ?? undefined),
    refresh: loadSummary,
  };
}
