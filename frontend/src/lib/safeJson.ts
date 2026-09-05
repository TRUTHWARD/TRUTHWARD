/* SPDX-License-Identifier: Apache-2.0 */
const DANGEROUS_KEYS = new Set(["__proto__", "prototype", "constructor"]);

export type SafeJsonViewerLimits = {
  maxDepth?: number;
  maxNodes?: number;
  maxStringLength?: number;
  maxCharacters?: number;
};

export type SafeJsonDisplay = {
  text: string;
  truncated: boolean;
};

export function sanitizeJsonForDisplay(
  value: unknown,
  limits: SafeJsonViewerLimits = {},
): SafeJsonDisplay {
  const maxDepth = limits.maxDepth ?? 10;
  const maxNodes = limits.maxNodes ?? 1_500;
  const maxStringLength = limits.maxStringLength ?? 8_192;
  const maxCharacters = limits.maxCharacters ?? 120_000;
  const seen = new WeakSet<object>();
  let nodes = 0;
  let truncated = false;

  const visit = (input: unknown, depth: number): unknown => {
    nodes += 1;
    if (nodes > maxNodes) {
      truncated = true;
      return "[Node limit reached]";
    }
    if (depth > maxDepth) {
      truncated = true;
      return "[Depth limit reached]";
    }
    if (typeof input === "string") {
      if (input.length <= maxStringLength) return input;
      truncated = true;
      return `${input.slice(0, maxStringLength)}…`;
    }
    if (input === null || typeof input !== "object") {
      if (typeof input === "bigint") return input.toString();
      if (typeof input === "symbol" || typeof input === "function") return String(input);
      return input;
    }
    if (seen.has(input)) {
      truncated = true;
      return "[Circular]";
    }
    seen.add(input);
    if (Array.isArray(input)) {
      return input.map((item) => visit(item, depth + 1));
    }
    const safeRecord: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const [key, item] of Object.entries(input)) {
      const displayKey = DANGEROUS_KEYS.has(key) ? `[blocked:${key}]` : key;
      if (DANGEROUS_KEYS.has(key)) truncated = true;
      safeRecord[displayKey] = visit(item, depth + 1);
    }
    return safeRecord;
  };

  let text = JSON.stringify(visit(value, 0), null, 2) ?? "null";
  if (text.length > maxCharacters) {
    text = `${text.slice(0, maxCharacters)}\n…`;
    truncated = true;
  }
  return { text, truncated };
}
