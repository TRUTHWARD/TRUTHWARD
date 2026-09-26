/* SPDX-License-Identifier: Apache-2.0 */
import { useCallback, useEffect, useState } from "react";

import { ApiRequestError, fetchCandidateBuild, fetchCandidateBuilds, type CandidateBuildDetail, type CandidateBuildList, type CandidateBuildSummary } from "../lib/api";
import { readRouteSelection } from "../lib/routeSelection";


export type CandidateBuildLoadState = "unavailable" | "restricted" | "loading" | "ready" | "empty" | "error";

export function useCandidateBuilds(projectId: string | null, canRead: boolean) {
  const [state, setState] = useState<CandidateBuildLoadState>(
    projectId ? (canRead ? "loading" : "restricted") : "unavailable",
  );
  const [items, setItems] = useState<CandidateBuildSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CandidateBuildDetail | null>(null);
  const [detailState, setDetailState] = useState<"idle" | "loading" | "ready" | "restricted" | "error">("idle");
  const [observationPolicy, setObservationPolicy] = useState<CandidateBuildList["observationPolicy"] | null>(null);
  const [revision, setRevision] = useState(0);
  const reload = useCallback(() => setRevision((value) => value + 1), []);

  useEffect(() => {
    let cancelled = false;
    setItems([]);
    setSelectedId(null);
    setDetail(null);
    setDetailState("idle");
    setObservationPolicy(null);
    if (!projectId) {
      setState("unavailable");
      return () => { cancelled = true; };
    }
    if (!canRead) {
      setState("restricted");
      return () => { cancelled = true; };
    }
    setState("loading");
    void fetchCandidateBuilds(projectId)
      .then((result) => {
        if (cancelled) return;
        setItems(result.items);
        const requestedBuildId = readRouteSelection("buildId");
        setSelectedId(result.items.some((item) => item.buildId === requestedBuildId) ? requestedBuildId : result.items[0]?.buildId ?? null);
        setObservationPolicy(result.observationPolicy);
        setState(result.total === 0 ? "empty" : "ready");
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        if (error instanceof ApiRequestError && error.status === 403) {
          setState("restricted");
          return;
        }
        if (error instanceof ApiRequestError && [404, 409, 410, 503].includes(error.status)) {
          setState("unavailable");
          return;
        }
        setState("error");
      });
    return () => { cancelled = true; };
  }, [canRead, projectId, revision]);

  useEffect(() => {
    let cancelled = false;
    setDetail(null);
    if (!projectId || !canRead || !selectedId) {
      setDetailState("idle");
      return () => { cancelled = true; };
    }
    setDetailState("loading");
    void fetchCandidateBuild(projectId, selectedId)
      .then((result) => {
        if (cancelled) return;
        setDetail(result);
        setDetailState("ready");
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setDetailState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
      });
    return () => { cancelled = true; };
  }, [canRead, projectId, selectedId]);

  return { state, items, observationPolicy, reload, selectedId, select: setSelectedId, detail, detailState };
}
