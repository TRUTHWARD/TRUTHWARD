/* SPDX-License-Identifier: Apache-2.0 */
import { type FormEvent, type ReactNode, useEffect, useState } from "react";

import {
  ApiRequestError,
  bootstrapCommunity,
  clearCommunityAuthToken,
  fetchCommunityBootstrapStatus,
  fetchCurrentUser,
  getStoredAuthToken,
  loginCommunity,
  storeCommunityAuthToken,
} from "../lib/api";
import { t } from "../i18n";
import { IS_OSS_PROFILE } from "../productProfile";

type AuthMode = "checking" | "ready" | "bootstrap" | "login";

export function CommunityAuthBoundary({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<AuthMode>(IS_OSS_PROFILE ? "checking" : "ready");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [bootstrapForm, setBootstrapForm] = useState({ username: "admin", email: "admin@example.com", displayName: "Community Admin", password: "" });
  const [loginForm, setLoginForm] = useState({ identity: "admin", password: "" });
  const locale = typeof window !== "undefined" && window.localStorage.getItem("agentic-qa.locale") === "zh-CN" ? "zh-CN" : "en-US";
  const genericError = t(locale, "communityAuthRequestFailed");

  useEffect(() => {
    if (!IS_OSS_PROFILE) return;
    let cancelled = false;
    void fetchCommunityBootstrapStatus()
      .then(async (status) => {
        if (cancelled) return;
        if (status.bootstrapRequired) {
          setMode("bootstrap");
          return;
        }
        if (!getStoredAuthToken()) {
          setMode("login");
          return;
        }
        try {
          await fetchCurrentUser();
          if (!cancelled) setMode("ready");
        } catch (requestError) {
          if (requestError instanceof ApiRequestError && requestError.status === 401) {
            clearCommunityAuthToken();
            if (!cancelled) setMode("login");
            return;
          }
          throw requestError;
        }
      })
      .catch((requestError) => {
        if (!cancelled) {
          setError(requestError instanceof Error ? requestError.message : genericError);
          setMode("login");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [genericError]);

  const submitBootstrap = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await bootstrapCommunity(bootstrapForm);
      storeCommunityAuthToken(response.token);
      setMode("ready");
    } catch (requestError) {
      if (requestError instanceof ApiRequestError && requestError.status === 409) {
        if (requestError.code === "COMMUNITY_IDENTITY_ALREADY_EXISTS") {
          setError(t(locale, "communityBootstrapIdentityConflict"));
          return;
        }

        try {
          const status = await fetchCommunityBootstrapStatus();
          if (!status.bootstrapRequired) {
            setMode("login");
            setError(t(locale, "communityBootstrapAlreadyCompleted"));
            return;
          }
        } catch {
          // Preserve the bootstrap form when the state refresh is unavailable.
        }
        setError(t(locale, "communityBootstrapConflict"));
        return;
      }
      setError(requestError instanceof Error ? requestError.message : genericError);
    } finally {
      setBusy(false);
    }
  };

  const submitLogin = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await loginCommunity({ ...loginForm, tokenName: "community-web" });
      storeCommunityAuthToken(response.token);
      setMode("ready");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : genericError);
    } finally {
      setBusy(false);
    }
  };

  if (mode === "ready") return <>{children}</>;

  return (
    <main className="community-auth-shell">
      <section className="community-auth-card">
        <div className="community-auth-brand">
          <strong>{t(locale, "brandName")}</strong>
          <span>{t(locale, "productDescriptor")}</span>
        </div>
        {mode === "checking" ? <p>{t(locale, "communityInitializationChecking")}</p> : null}
        {mode === "bootstrap" ? (
          <form className="control-form" onSubmit={submitBootstrap}>
            <h1>{t(locale, "communityBootstrapTitle")}</h1>
            <label className="form-field">{t(locale, "username")}<input required value={bootstrapForm.username} onChange={(event) => setBootstrapForm((current) => ({ ...current, username: event.target.value }))} /></label>
            <label className="form-field">{t(locale, "email")}<input required type="email" value={bootstrapForm.email} onChange={(event) => setBootstrapForm((current) => ({ ...current, email: event.target.value }))} /></label>
            <label className="form-field">{t(locale, "displayName")}<input required value={bootstrapForm.displayName} onChange={(event) => setBootstrapForm((current) => ({ ...current, displayName: event.target.value }))} /></label>
            <label className="form-field">{t(locale, "passwordMinimum12")}<input minLength={12} required type="password" value={bootstrapForm.password} onChange={(event) => setBootstrapForm((current) => ({ ...current, password: event.target.value }))} /></label>
            <button disabled={busy} type="submit">{t(locale, "createAdministratorAndSignIn")}</button>
          </form>
        ) : null}
        {mode === "login" ? (
          <form className="control-form" onSubmit={submitLogin}>
            <h1>{t(locale, "communityLoginTitle")}</h1>
            <label className="form-field">{t(locale, "usernameOrEmail")}<input required value={loginForm.identity} onChange={(event) => setLoginForm((current) => ({ ...current, identity: event.target.value }))} /></label>
            <label className="form-field">{t(locale, "passwordMinimum12")}<input required type="password" value={loginForm.password} onChange={(event) => setLoginForm((current) => ({ ...current, password: event.target.value }))} /></label>
            <button disabled={busy} type="submit">{t(locale, "signIn")}</button>
          </form>
        ) : null}
        {error ? <div className="error-banner"><strong>{error}</strong></div> : null}
      </section>
    </main>
  );
}
