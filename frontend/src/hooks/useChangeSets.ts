/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useState } from "react";

import { ApiRequestError, fetchChangeSet, fetchChangeSets, fetchRequirementContentPreview, type ChangeSetDetail, type ChangeSetSummary, type RequirementContentPreview } from "../lib/api";
import { readRouteSelection } from "../lib/routeSelection";


export type ChangeSetViewState = "loading" | "ready" | "empty" | "unavailable" | "restricted" | "error";

export function useChangeSets(projectId: string | null, canRead: boolean, canReadRequirements = false) {
  const [state, setState] = useState<ChangeSetViewState>("loading");
  const [items, setItems] = useState<ChangeSetSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(() => readRouteSelection("changeSetId"));
  const [detail, setDetail] = useState<ChangeSetDetail | null>(null);
  const [contentPreview, setContentPreview] = useState<RequirementContentPreview | null>(null);
  const [contentPreviewState, setContentPreviewState] = useState<"loading" | "ready" | "restricted" | "error">("loading");
  const [readOnly, setReadOnly] = useState(true);
  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    let active = true;
    setItems([]);
    setDetail(null);
    const requestedChangeSetId = readRouteSelection("changeSetId");
    setSelectedId(requestedChangeSetId);
    if (!projectId) {
      setState("unavailable");
      return () => { active = false; };
    }
    if (!canRead) {
      setState("restricted");
      return () => { active = false; };
    }
    setState("loading");
    void fetchChangeSets(projectId).then((response) => {
      if (!active) return;
      setItems(response.items);
      setReadOnly(response.readOnly);
      setSelectedId((current) => current ?? response.items[0]?.changeSetId ?? null);
      setState((current) => current === "error" || current === "restricted"
        ? current
        : response.items.length || requestedChangeSetId ? "ready" : "empty");
    }).catch((error) => {
      if (!active) return;
      setState((current) => current === "ready" && requestedChangeSetId
        ? current
        : error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    });
    return () => { active = false; };
  }, [canRead, projectId, reloadToken]);

  useEffect(() => {
    let active = true;
    setDetail(null);
    if (!projectId || !selectedId || !canRead) return () => { active = false; };
    void fetchChangeSet(projectId, selectedId).then((response) => {
      if (active) {
        setDetail(response);
        setState("ready");
      }
    }).catch((error) => {
      if (active) setState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    });
    return () => { active = false; };
  }, [canRead, projectId, selectedId]);

  useEffect(() => {
    let active = true;
    setContentPreview(null);
    if (!projectId || !canRead || !canReadRequirements || detail?.changeSetType !== "requirement") {
      setContentPreviewState("restricted");
      return () => { active = false; };
    }
    setContentPreviewState("loading");
    void fetchRequirementContentPreview(projectId, detail.changeSetId).then((response) => {
      if (active) {
        setContentPreview(response);
        setContentPreviewState("ready");
      }
    }).catch((error) => {
      if (active) setContentPreviewState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    });
    return () => { active = false; };
  }, [canRead, canReadRequirements, detail, projectId]);

  return {
    detail,
    contentPreview,
    contentPreviewState,
    items,
    readOnly,
    reload: () => setReloadToken((value) => value + 1),
    selectedId,
    select: setSelectedId,
    state,
  };
}
