# Apache-2.0 license boundary

Status: Apache-2.0 public source distribution authorized on 2026-09-01; no
external repository publication or artifact upload was performed by this workflow.

This document defines how the private TRUTHWARD source repository may produce
a separately licensed Apache-2.0 source distribution. It is release governance,
not a statement that the current repository or every OSS-visible feature is
open source.

## Scope model

The repository root is proprietary by default. Runtime settings, edition
labels, navigation visibility, and capability grants do not change that
classification.

`candidateApachePaths` identifies files evaluated for a public distribution. It
grants no license. `approvedPaths` freezes the files the exporter may copy, but
those files remain governed by the private repository license in this source of
record. The Apache-2.0 grant applies only to the contents of a separately
generated, finally authorized export.

The OSS exporter places the canonical Apache-2.0 text at root `LICENSE`, the
distribution-only attribution text at root `NOTICE`, the release-specific
dependency review at `THIRD_PARTY_LICENSES.json`, and immutable file hashes at
`OSS_SOURCE_PROVENANCE.json`. An approved source distribution also carries the
release-specific SPDX 2.3 JSON document at `SBOM.spdx.json`.

## Publication gates

Every gate is independent and fail-closed:

1. The owner approves and freezes the exact source scope.
2. Every approved path is already a reviewed candidate and no approved path
   overlaps a proprietary pattern.
3. The export contains the canonical Apache-2.0 text and a minimal NOTICE that
   describes only the exported work.
4. Comment-capable first-party source files carry the approved Apache-2.0 SPDX
   marker; formats that cannot carry comments are covered by the distribution
   license and provenance manifest.
5. The exact dependency locks and all bundled third-party content receive a
   release-specific license and notice review; all `NOASSERTION` SBOM license
   entries are either resolved or explicitly reviewed.
6. The export is generated from a clean commit and passes secret scanning,
   proprietary-marker/path scanning, an isolated clean build, and provenance
   verification.

Changing `publishable`, deleting a blocking reason, or enabling the OSS runtime
profile cannot bypass these gates. `tools/build_oss_source.py` requires the
machine-readable policy to be approved before it can authorize an archive.

## Source versus binary distributions

The current policy authorizes only the approved source export. It does not authorize
a wheel, executable, container image, prebuilt frontend bundle, browser binary,
model, OCR asset, database image, or other binary package. Those artifacts can
bundle third-party code and notices that are absent from the source archive and
therefore require their own content inventory, LICENSE, NOTICE, SBOM, and owner
approval.

The exact source-export SBOM contains 446 locked Python/npm packages. All 95
formerly unresolved declared-license records have evidence-backed SPDX
expressions, so the source SBOM has zero declared-license `NOASSERTION` entries.
This source review does not authorize bundled binaries. In particular,
pypdfium2/PDFium, psycopg-binary, wheels, containers, and prebuilt frontend
artifacts still require distribution-specific content and notice review.

## Maintainer workflow

1. Keep the ready review dependency closure disjoint from proprietary paths and
   rerun the source graph for the exact release commit.
2. Update `release/oss/third_party_licenses.json` from the exact dependency
   locks and resolve every manual-review item.
3. Add approved SPDX markers only after the owner approves the public scope.
4. Freeze `approvedPaths`, owner evidence, dependency evidence, and clean-build
   evidence in `release/oss/license_boundary.json` and
   `release/oss/release_evidence.json` for the same commit and approved-path
   digest.
5. Run `scripts/check-license-boundary.ps1`,
   `scripts/check-oss-source-graph.ps1`, `scripts/build-oss-sbom.ps1`, and
   `scripts/build-oss-source.ps1 -CheckOnly` from the exact clean commit.
6. Run `scripts/check-oss-release-gates.ps1 -RequireReady`; it is the atomic
   release decision and must fail when exact-commit evidence or final publication
   authorization is absent.
7. Record the owner's final source-only distribution authorization, change the
   export state to `approved` and `publishable=true`, and rerun the exact-commit
   archive, scan, SBOM, and clean-build evidence before external publication.

The policy follows the Apache Software Foundation's public guidance for applying
Apache License 2.0 and for assembling distribution-specific LICENSE and NOTICE
files:

- https://www.apache.org/legal/apply-license.html
- https://infra.apache.org/licensing-howto.html
- https://www.apache.org/foundation/license-faq.html
