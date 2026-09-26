/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useState } from "react";

import { ApiRequestError, fetchImpactResults, type ImpactResult } from "../lib/api";
import { readRouteSelection } from "../lib/routeSelection";


export type ImpactResultViewState = "loading" | "ready" | "empty" | "unavailable" | "restricted" | "error";

export function useImpactResults(projectId: string | null, canRead: boolean) {
  const [state, setState] = useState<ImpactResultViewState>("loading");
  const [items, setItems] = useState<ImpactResult[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [backendComputed, setBackendComputed] = useState(false);
  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    let active = true;
    setItems([]);
    setSelectedId(null);
    setBackendComputed(false);
    if (!projectId) {
      setState("unavailable");
      return () => { active = false; };
    }
    if (!canRead) {
      setState("restricted");
      return () => { active = false; };
    }
    setState("loading");
    void fetchImpactResults(projectId).then((response) => {
      if (!active) return;
      setItems(response.items);
      const requestedImpactResultId = readRouteSelection("impactResultId");
      setSelectedId(response.items.some((item) => item.impactResultId === requestedImpactResultId) ? requestedImpactResultId : response.items[0]?.impactResultId ?? null);
      setBackendComputed(response.backendComputed);
      setState(response.items.length ? "ready" : "empty");
    }).catch((error) => {
      if (!active) return;
      setState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    });
    return () => { active = false; };
  }, [canRead, projectId, reloadToken]);

  return {
    items,
    backendComputed,
    reload: () => setReloadToken((value) => value + 1),
    selectedId,
    selected: items.find((item) => item.impactResultId === selectedId) ?? null,
    select: setSelectedId,
    state,
  };
}
