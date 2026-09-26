/* SPDX-License-Identifier: Apache-2.0 */
import type { EvidenceReferenceLike } from "../components/EvidenceReferenceList";


type FindingEvidenceSource = {
  evidence?: Array<Record<string, unknown>>;
  evidenceRef?: string | null;
  rawRef?: string | null;
};

export function findingEvidenceReferences(finding: FindingEvidenceSource): EvidenceReferenceLike[] {
  const refs: EvidenceReferenceLike[] = [];

  for (const item of finding.evidence ?? []) {
    const ref = firstText(item.ref, item.uri, item.artifactRef, item.evidenceRef, item.id);
    if (!ref) continue;
    refs.push({
      type: firstText(item.type, item.artifactType, item.kind),
      ref,
      title: firstText(item.title, item.label),
      summary: firstText(item.summary, item.description, item.message),
      contentHash: firstText(item.contentHash, item.content_hash),
      redactionStatus: firstText(item.redactionStatus, item.redaction_status),
      available: item.available,
      unavailableReason: firstText(item.unavailableReason, item.unavailable_reason),
    });
  }

  if (finding.evidenceRef) refs.push({ type: "evidence", ref: finding.evidenceRef });
  if (finding.rawRef) refs.push({ type: "raw_finding", ref: finding.rawRef });

  const seen = new Set<string>();
  return refs.filter((item) => {
    const ref = typeof item.ref === "string" ? item.ref : "";
    if (!ref || seen.has(ref)) return false;
    seen.add(ref);
    return true;
  });
}

function firstText(...values: unknown[]) {
  return values.find((value): value is string => typeof value === "string" && value.trim().length > 0)?.trim() ?? "";
}
