/* SPDX-License-Identifier: Apache-2.0 */
import { t, type Locale } from "../i18n";
import { sanitizeJsonForDisplay, type SafeJsonViewerLimits } from "../lib/safeJson";

export function SafeJsonViewer({
  value,
  locale,
  limits,
}: {
  value: unknown;
  locale: Locale;
  limits?: SafeJsonViewerLimits;
}) {
  const display = sanitizeJsonForDisplay(value, limits);
  return (
    <div className="safe-json-viewer">
      {display.truncated ? (
        <p className="state-banner state-banner--warning" role="status">
          {t(locale, "executionExplanationJsonTruncated")}
        </p>
      ) : null}
      <pre className="snapshot-json" tabIndex={0}>{display.text}</pre>
    </div>
  );
}
