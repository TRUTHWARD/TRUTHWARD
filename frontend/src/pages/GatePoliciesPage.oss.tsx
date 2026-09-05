/* SPDX-License-Identifier: Apache-2.0 */
import { useCallback, useEffect, useState } from "react";

import { ApiRequestError, fetchGatePolicies, type CurrentUser, type GatePolicyProjection } from "../lib/api";
import { type Locale, t } from "../i18n";

type Props = { currentUser: CurrentUser | null; locale: Locale; projectId: string | null };

export function GatePoliciesPage({ currentUser, locale, projectId }: Props) {
  const canRead = currentUser?.capabilities.includes("gate_policy.read") ?? false;
  const [policies, setPolicies] = useState<GatePolicyProjection[]>([]);
  const [state, setState] = useState<"idle" | "loading" | "restricted" | "unavailable" | "error">("idle");
  const [errorStatus, setErrorStatus] = useState<number | null>(null);

  const refresh = useCallback(async () => {
    if (!projectId || !canRead) return;
    setState("loading");
    try {
      const result = await fetchGatePolicies(projectId);
      setPolicies(result.items);
      setErrorStatus(null);
      setState("idle");
    } catch (error) {
      const status = error instanceof ApiRequestError ? error.status : null;
      setErrorStatus(status);
      setState(status === 403 ? "restricted" : status === 503 ? "unavailable" : "error");
    }
  }, [canRead, projectId]);

  useEffect(() => {
    setPolicies([]);
    if (!projectId) setState("unavailable");
    else if (!canRead) setState("restricted");
    else void refresh();
  }, [canRead, projectId, refresh]);

  return <div className="page-shell" data-route="/gate-policies">
    <div className="page-heading"><div><span className="eyebrow">{t(locale, "gatePolicyGovernance")}</span><h2>{t(locale, "gatePolicies")}</h2><p>{t(locale, "gatePolicyReadOnly")}</p></div></div>
    {!projectId || state === "unavailable" ? <div className="empty-state">{t(locale, "gatePolicyProjectUnavailable")}</div> : null}
    {state === "restricted" ? <div className="notice notice--warning">{t(locale, "gatePolicyRestricted")}</div> : null}
    {state === "error" ? <div className="error-banner">{t(locale, "gatePolicyRequestFailed")} {errorStatus ? `(${errorStatus})` : ""}</div> : null}
    {state === "loading" ? <div className="notice notice--info">{t(locale, "loading")}</div> : null}
    {projectId && canRead && state === "idle" ? <section className="panel">
      <h3>{t(locale, "gatePolicyList")}</h3>
      {policies.length === 0 ? <p>{t(locale, "gatePolicyEmpty")}</p> : <div className="diff-list">{policies.map((policy) => <div className="list-row" key={policy.policyId}>
        <strong>{policy.name}</strong>
        <span>{policy.status}</span>
        <span>{policy.versions[0]?.versionId ?? "-"}</span>
      </div>)}</div>}
    </section> : null}
  </div>;
}
