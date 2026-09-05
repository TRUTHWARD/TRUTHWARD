/* SPDX-License-Identifier: Apache-2.0 */
import { useCallback, useEffect, useState } from "react";

import {
  ApiRequestError,
  fetchAdmissionReview,
  fetchAdmissionRun,
  fetchAdmissionRuns,
  fetchAdmissionTimeline,
  type AdmissionReviewProjection,
  type AdmissionRunProjection,
  type AdmissionTimelineProjection,
} from "../lib/api";


export type AdmissionGovernanceState = "loading" | "ready" | "empty" | "unavailable" | "restricted" | "error";

export function useAdmissionGovernance(projectId: string | null, canRead: boolean) {
  const [state, setState] = useState<AdmissionGovernanceState>("unavailable");
  const [items, setItems] = useState<AdmissionRunProjection[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<AdmissionRunProjection | null>(null);
  const [timeline, setTimeline] = useState<AdmissionTimelineProjection | null>(null);
  const [review, setReview] = useState<AdmissionReviewProjection | null>(null);
  const [refreshToken, setRefreshToken] = useState(0);

  const refresh = useCallback(() => setRefreshToken((value) => value + 1), []);

  useEffect(() => {
    let active = true;
    setItems([]);
    setSelectedId(null);
    setDetail(null);
    setTimeline(null);
    setReview(null);
    if (!projectId) {
      setState("unavailable");
      return () => { active = false; };
    }
    if (!canRead) {
      setState("restricted");
      return () => { active = false; };
    }
    setState("loading");
    void fetchAdmissionRuns(projectId).then((response) => {
      if (!active) return;
      setItems(response.items);
      setSelectedId((current) => current && response.items.some((item) => item.admissionRunId === current) ? current : response.items[0]?.admissionRunId ?? null);
      setState(response.items.length ? "ready" : "empty");
    }).catch((error) => {
      if (!active) return;
      setState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    });
    return () => { active = false; };
  }, [canRead, projectId, refreshToken]);

  useEffect(() => {
    let active = true;
    setDetail(null);
    setTimeline(null);
    setReview(null);
    if (!projectId || !selectedId || !canRead) return () => { active = false; };
    void Promise.all([
      fetchAdmissionRun(projectId, selectedId),
      fetchAdmissionTimeline(projectId, selectedId),
      fetchAdmissionReview(projectId, selectedId),
    ]).then(([nextDetail, nextTimeline, nextReview]) => {
      if (!active) return;
      setDetail(nextDetail);
      setTimeline(nextTimeline);
      setReview(nextReview);
    }).catch((error) => {
      if (!active) return;
      setState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    });
    return () => { active = false; };
  }, [canRead, projectId, refreshToken, selectedId]);

  return { detail, items, refresh, review, select: setSelectedId, selectedId, state, timeline };
}
