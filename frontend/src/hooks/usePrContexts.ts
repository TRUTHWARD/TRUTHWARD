/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useState } from "react";

import { ApiRequestError, fetchPrContext, fetchPrContexts, type PrContextDetail, type PrContextSummary } from "../lib/api";


export type PrContextViewState = "loading" | "ready" | "empty" | "unavailable" | "restricted" | "error";

export function usePrContexts(projectId: string | null, canRead: boolean) {
  const [state, setState] = useState<PrContextViewState>("loading");
  const [items, setItems] = useState<PrContextSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<PrContextDetail | null>(null);

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
    void fetchPrContexts(projectId).then((response) => {
      if (!active) return;
      setItems(response.items);
      setSelectedId(response.items[0]?.contextId ?? null);
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
    void fetchPrContext(projectId, selectedId).then((response) => {
      if (active) setDetail(response);
    }).catch((error) => {
      if (active) setState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    });
    return () => { active = false; };
  }, [canRead, projectId, selectedId]);

  return { detail, items, selectedId, select: setSelectedId, state };
}
