# Upstream Sources (OSV + NVD)

This doc answers how OSV and NVD behave, how we query them, and how we normalize their data.

## OSV
- **API style**: query-by-package, not a push/full feed by default.
  - `POST /v1/query` for a single package.
  - `POST /v1/querybatch` for multiple packages.
  - `GET /v1/vulns/{id}` for details.
- **Bulk data**: OSV also publishes full dumps (per-ecosystem) for offline ingestion, but the prototype can use live queries.
- **What you get**: affected ranges (`introduced`, `fixed`, `last_affected`), references, and OSV IDs.
- **Normalization needed**:
  - Map local package names to OSV ecosystem (likely `Debian` for this dataset).
  - Normalize versions as strings; avoid semantic comparisons across distro schemes.
- **Strengths**: best for fixed versions and affected ranges.

## NVD
- **API style**: query-by-CVE or search; not a push by default.
  - `GET /rest/json/cves/2.0?cveId=CVE-YYYY-NNNN` (or similar).
  - Responses are paginated for search queries.
- **Bulk data**: NVD provides full JSON feeds (CVE 2.0) for offline ingestion.
- **What you get**: `vulnStatus`, descriptions, CVSS, references, and CPEs.
- **Normalization needed**:
  - Canonicalize CVE IDs (uppercase).
  - CPEs are vendor/product oriented and typically do not map cleanly to Debian packages.
- **Strengths**: good for status (e.g., `Rejected`, `Awaiting Analysis`), metadata, and references.

## Do we always get a full dump?
- **No**. Both OSV and NVD are query-first APIs. Full dumps are available but optional.
- For a prototype: query per advisory, cache results, and add TTL-based refresh.

## Do we need different transformations per source?
- **Yes**. OSV is package/ecosystem-centric; NVD is CVE-centric.
- Use a source adapter pattern that converts each response into a shared evidence schema.
- Store raw payloads for traceability in `evidence_json`.

## Can we keep it as one table?
- Yes. Keep a unified evidence table with source-specific payloads in JSON.
- Suggested schema fields: `source`, `source_id`, `captured_at`, `normalized`, `raw_payload`.

## Prioritization between OSV and NVD
1. CSV override (authoritative for `not_applicable`).
2. OSV for `fixed_version` (most reliable for fixes).
3. NVD for rejection/withdrawal status or metadata.
4. Freshness tie-breaker: prefer the newest evidence in conflicts.

## Ecosystem fallback (recommended)
- Default OSV ecosystem to `Debian` for this dataset.
- If Debian yields no results for a package, try `Ubuntu` as a fallback.
- Always record which ecosystem was used in the evidence payload.
