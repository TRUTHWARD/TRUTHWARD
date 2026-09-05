/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useState } from "react";

import {
  ApiRequestError,
  fetchExecutionDecisionTimeline,
  type DecisionTimelineProjection,
} from "../lib/api";

const INITIAL_TIMELINE_PAGE_SIZE = 20;
const TIMELINE_PAGE_SIZE = 200;
const MAX_TIMELINE_PAGES = 50;


export type ExecutionExplanationLoadState =
  | "unavailable"
  | "restricted"
  | "loading"
  | "ready"
  | "empty"
  | "error";

export function useExecutionExplanationTimeline(
  executionId: string | null,
  canRead: boolean,
) {
  const [state, setState] = useState<ExecutionExplanationLoadState>(
    executionId ? (canRead ? "loading" : "restricted") : "unavailable",
  );
  const [projection, setProjection] = useState<DecisionTimelineProjection | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setProjection(null);
    setError(null);
    setLoadingMore(false);
    if (!executionId) {
      setState("unavailable");
      return () => {
        cancelled = true;
      };
    }
    if (!canRead) {
      setState("restricted");
      return () => {
        cancelled = true;
      };
    }
    setState("loading");
    let firstPageRendered = false;
    void fetchCompleteExecutionDecisionTimeline(executionId, (data, complete) => {
      if (cancelled) return;
      firstPageRendered = true;
      setProjection(data);
      setState(data.pagination.totalEvents === 0 ? "empty" : "ready");
      setLoadingMore(!complete);
    })
      .then((data) => {
        if (cancelled) return;
        setProjection(data);
        setState(data.pagination.totalEvents === 0 ? "empty" : "ready");
        setLoadingMore(false);
      })
      .catch((requestError: unknown) => {
        if (cancelled) return;
        setLoadingMore(false);
        if (firstPageRendered) {
          setError(requestError instanceof Error ? requestError.message : null);
          return;
        }
        if (requestError instanceof ApiRequestError && requestError.status === 403) {
          setState("restricted");
          setError(null);
          return;
        }
        if (
          requestError instanceof ApiRequestError
          && [404, 409, 410, 503].includes(requestError.status)
        ) {
          setState("unavailable");
          setError(null);
          return;
        }
        setState("error");
        setError(requestError instanceof Error ? requestError.message : null);
      });
    return () => {
      cancelled = true;
    };
  }, [canRead, executionId]);

  return { state, projection, error, loadingMore };
}

async function fetchCompleteExecutionDecisionTimeline(
  executionId: string,
  onProgress: (projection: DecisionTimelineProjection, complete: boolean) => void,
): Promise<DecisionTimelineProjection> {
  let projection = await fetchExecutionDecisionTimeline(executionId, { pageSize: INITIAL_TIMELINE_PAGE_SIZE });
  onProgress(projection, !projection.pagination.hasMore);
  const seenCursors = new Set<string>();
  let pageCount = 1;

  while (projection.pagination.hasMore && projection.pagination.nextCursor) {
    const cursor = projection.pagination.nextCursor;
    if (seenCursors.has(cursor) || pageCount >= MAX_TIMELINE_PAGES) {
      throw new Error("Decision timeline pagination did not complete safely.");
    }
    seenCursors.add(cursor);
    const nextPage = await fetchExecutionDecisionTimeline(executionId, {
      cursor,
      pageSize: TIMELINE_PAGE_SIZE,
    });
    projection = mergeTimelinePages(projection, nextPage);
    pageCount += 1;
    onProgress(projection, !projection.pagination.hasMore);
  }

  return projection;
}

function mergeTimelinePages(
  accumulated: DecisionTimelineProjection,
  nextPage: DecisionTimelineProjection,
): DecisionTimelineProjection {
  const nextGroups = new Map(nextPage.stageGroups.map((group) => [group.lifecycleStage, group]));
  const stageGroups = accumulated.stageGroups.map((group) => {
    const incoming = nextGroups.get(group.lifecycleStage);
    if (!incoming) {
      return group;
    }
    const eventsById = new Map(group.events.map((event) => [event.eventId, event]));
    incoming.events.forEach((event) => eventsById.set(event.eventId, event));
    const events = [...eventsById.values()].sort((left, right) => left.sortKey.localeCompare(right.sortKey));
    return {
      ...group,
      eventCount: Math.max(group.eventCount, incoming.eventCount),
      pageEventCount: events.length,
      events,
      unavailableReason: group.unavailableReason ?? incoming.unavailableReason,
    };
  });

  return {
    ...accumulated,
    stageGroups,
    unavailableReasons: dedupeUnavailableReasons([
      ...accumulated.unavailableReasons,
      ...nextPage.unavailableReasons,
    ]),
    pagination: {
      ...nextPage.pagination,
      totalEvents: Math.max(accumulated.pagination.totalEvents, nextPage.pagination.totalEvents),
      returnedEvents: stageGroups.reduce((total, group) => total + group.events.length, 0),
    },
  };
}

function dedupeUnavailableReasons(reasons: DecisionTimelineProjection["unavailableReasons"]) {
  const unique = new Map<string, DecisionTimelineProjection["unavailableReasons"][number]>();
  reasons.forEach((reason) => {
    const key = [
      reason.code,
      reason.lifecycleStage,
      reason.sourceType,
      reason.referenceType,
      reason.referenceId,
      reason.detailKey,
    ].join(":");
    unique.set(key, reason);
  });
  return [...unique.values()];
}
