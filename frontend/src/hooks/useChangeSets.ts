/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useState } from "react";

import { ApiRequestError, fetchChangeSet, fetchChangeSets, type ChangeSetDetail, type ChangeSetSummary } from "../lib/api";


export type ChangeSetViewState = "loading" | "ready" | "empty" | "unavailable" | "restricted" | "error";

export function useChangeSets(projectId: string | null, canRead: boolean) {
  const [state, setState] = useState<ChangeSetViewState>("loading");
  const [items, setItems] = useState<ChangeSetSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ChangeSetDetail | null>(null);
  const [readOnly, setReadOnly] = useState(true);

  useEffect(() => {
    let active = true;
    setItems([]);
    setDetail(null);
    setSelectedId(null);
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
      setSelectedId(response.items[0]?.changeSetId ?? null);
      setState(response.items.length ? "ready" : "empty");
    }).catch((error) => {
      if (!active) return;
      setState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    });
    return () => { active = false; };
  }, [canRead, projectId]);

  useEffect(() => {
    let active = true;
    setDetail(null);
    if (!projectId || !selectedId || !canRead) return () => { active = false; };
    void fetchChangeSet(projectId, selectedId).then((response) => {
      if (active) setDetail(response);
    }).catch((error) => {
      if (active) setState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    });
    return () => { active = false; };
  }, [canRead, projectId, selectedId]);

  return { detail, items, readOnly, selectedId, select: setSelectedId, state };
}
