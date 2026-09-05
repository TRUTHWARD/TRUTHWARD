/* SPDX-License-Identifier: Apache-2.0 */
const plaintextPrefixes = ["ghp_", "github_pat_", "sk-", "xoxb-", "xoxp-", "glpat-", "eyJ"];
const referenceKeys = new Set(["secretref", "credentialref", "apikeyref"]);
const sensitiveFragments = [
  "apikey",
  "accesstoken",
  "authorization",
  "clientsecret",
  "cookie",
  "credential",
  "dsn",
  "headers",
  "keymaterial",
  "passphrase",
  "passwd",
  "password",
  "privatekey",
  "refreshtoken",
  "secretvalue",
  "session",
  "token",
  "tokenvalue",
];
const redaction = "[REDACTED]";
const freeTextPatterns = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]{6,}/giu,
  /(?:ghp_|github_pat_|sk-|xoxb-|xoxp-|glpat-)[A-Za-z0-9._-]{6,}/gu,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/gu,
  /\b(?:vault|cred|credential|secret|aws-sm|gcp-sm|azure-kv|env|mcp-secret):\/\/[^\s"'<>]+/giu,
  /\b([a-z][a-z0-9+.-]*:\/\/)[^\s/:@]+:[^\s/@]+@/giu,
  /([?&](?:access[_-]?token|refresh[_-]?token|api[_-]?key|token|password|secret|credential|client[_-]?secret)=)[^&#\s]+/giu,
  /[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/gu,
  /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3}[\s.-]\d{3}[\s.-]\d{4}/gu,
  /(?:\d{3}-\d{2}-\d{4}|\d{17}[\dXx])/gu,
];
const secretAssignmentPattern =
  /(\b(?:password|passwd|pwd|token|credential|secret|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|passphrase|private[_ -]?key)\b|密码|口令|凭据|密钥|令牌)\s*([:=：])\s*([^\s,;，；]+)/giu;

export function redactSensitiveText(value: string) {
  const trimmed = value.trim();
  if (trimmed.length <= 65_536 && (trimmed.startsWith("{") || trimmed.startsWith("["))) {
    try {
      const decoded = JSON.parse(trimmed) as unknown;
      if (decoded !== null && typeof decoded === "object") return JSON.stringify(redactSnapshotValue(decoded));
    } catch {
      // Invalid encoded structures continue through free-text redaction.
    }
  }
  const assigned = value.replace(secretAssignmentPattern, `$1$2${redaction}`);
  return freeTextPatterns.reduce((result, pattern) => result.replace(pattern, redaction), assigned);
}

export function maskReference(value: string) {
  void value;
  return "[REDACTED]";
}

export function redactSnapshotValue(value: unknown, key?: string): unknown {
  const normalizedKey = (key ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");
  if (key && (referenceKeys.has(normalizedKey) || sensitiveFragments.some((fragment) => normalizedKey.includes(fragment)))) {
    return "[REDACTED]";
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSnapshotValue(item));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([itemKey, itemValue]) => [
        redactSensitiveText(itemKey),
        redactSnapshotValue(itemValue, itemKey),
      ]),
    );
  }
  if (typeof value === "string") {
    if (referenceKeys.has(normalizedKey)) {
      return maskReference(value);
    }
    if (sensitiveFragments.some((fragment) => normalizedKey.includes(fragment))) {
      return "[REDACTED]";
    }
    if (plaintextPrefixes.some((prefix) => value.startsWith(prefix))) {
      return "[REDACTED]";
    }
    return redactSensitiveText(value);
  }
  return value;
}
