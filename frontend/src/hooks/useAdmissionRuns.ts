/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useState } from "react";

import { ApiRequestError, fetchAdmissionRuns, type AdmissionRunProjection } from "../lib/api";


export type AdmissionRunViewState = "loading" | "ready" | "empty" | "unavailable" | "restricted" | "error";

export function useAdmissionRuns(projectId: string | null, prContextVersionId: string | null, canRead: boolean) {
  const [state, setState] = useState<AdmissionRunViewState>("unavailable");
  const [items, setItems] = useState<AdmissionRunProjection[]>([]);

  useEffect(() => {
    let active = true;
    setItems([]);
    if (!projectId || !prContextVersionId) {
      setState("unavailable");
      return () => { active = false; };
    }
    if (!canRead) {
      setState("restricted");
      return () => { active = false; };
    }
    setState("loading");
    void fetchAdmissionRuns(projectId, prContextVersionId).then((response) => {
      if (!active) return;
      setItems(response.items);
      setState(response.items.length ? "ready" : "empty");
    }).catch((error) => {
      if (!active) return;
      setState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    });
    return () => { active = false; };
  }, [canRead, prContextVersionId, projectId]);

  return { items, state };
}
