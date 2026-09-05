/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useState } from "react";

import { ApiRequestError, fetchCandidateBuilds, type CandidateBuildSummary } from "../lib/api";


export type CandidateBuildLoadState = "unavailable" | "restricted" | "loading" | "ready" | "empty" | "error";

export function useCandidateBuilds(projectId: string | null, canRead: boolean) {
  const [state, setState] = useState<CandidateBuildLoadState>(
    projectId ? (canRead ? "loading" : "restricted") : "unavailable",
  );
  const [items, setItems] = useState<CandidateBuildSummary[]>([]);

  useEffect(() => {
    let cancelled = false;
    setItems([]);
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
  }, [canRead, projectId]);

  return { state, items };
}
