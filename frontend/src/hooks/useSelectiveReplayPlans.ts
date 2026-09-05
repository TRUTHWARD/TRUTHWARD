/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useState } from "react";

import {
  ApiRequestError,
  fetchSelectiveReplayConfirmation,
  fetchSelectiveReplayPlans,
  type SelectiveReplayConfirmation,
  type SelectiveReplayPlan,
} from "../lib/api";


export type SelectiveReplayViewState = "loading" | "ready" | "empty" | "unavailable" | "restricted" | "error";

export function useSelectiveReplayPlans(projectId: string | null, canRead: boolean) {
  const [state, setState] = useState<SelectiveReplayViewState>("loading");
  const [items, setItems] = useState<SelectiveReplayPlan[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [confirmation, setConfirmation] = useState<SelectiveReplayConfirmation | null>(null);
  const [confirmationState, setConfirmationState] = useState<"idle" | "loading" | "ready" | "restricted" | "error">("idle");

  useEffect(() => {
    let active = true;
    setItems([]);
    setSelectedId(null);
    setConfirmation(null);
    setConfirmationState("idle");
    if (!projectId) {
      setState("unavailable");
      return () => { active = false; };
    }
    if (!canRead) {
      setState("restricted");
      return () => { active = false; };
    }
    setState("loading");
    void fetchSelectiveReplayPlans(projectId).then((response) => {
      if (!active) return;
      setItems(response.items);
      setSelectedId(response.items[0]?.planId ?? null);
      setState(response.items.length ? "ready" : "empty");
    }).catch((error) => {
      if (!active) return;
      setState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    });
    return () => { active = false; };
  }, [canRead, projectId]);

  const loadConfirmation = async () => {
    if (!projectId || !selectedId) return;
    setConfirmationState("loading");
    setConfirmation(null);
    try {
      setConfirmation(await fetchSelectiveReplayConfirmation(projectId, selectedId));
      setConfirmationState("ready");
    } catch (error) {
      setConfirmationState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    }
  };

  return {
    items,
    selectedId,
    selected: items.find((item) => item.planId === selectedId) ?? null,
    select: (planId: string) => { setSelectedId(planId); setConfirmation(null); setConfirmationState("idle"); },
    state,
    confirmation,
    confirmationState,
    loadConfirmation,
  };
}
