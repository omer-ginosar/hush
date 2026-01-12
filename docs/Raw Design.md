Mature Design: Multi-Source CVE Advisory Pipeline
The Real Problem at Scale
When you have dozens of sources, the challenges compound:
Source Heterogeneity

NVD gives you CVE-ID + CVSS + CPE, updates weekly-ish
OSV gives you ecosystem + package + version ranges, updates in near real-time
Debian Tracker gives you per-release status with maintainer notes
GHSA gives you GHSA-IDs that may or may not map to CVEs
Vendor bulletins are HTML/PDF with no API
Some sources are authoritative for specific ecosystems, others are aggregators

Identity Resolution Crisis

One vulnerability can be: CVE-2024-1234, GHSA-xxxx-yyyy, DSA-5432, USN-6789, RHSA-2024:1234
Package "openssl" in Debian ≠ "openssl" in Alpine ≠ "pyopenssl" in PyPI
Version "1.2.3-debian1" ≠ "1.2.3" upstream

Trust and Conflict

NVD says CVSS 9.8, Red Hat says 7.5 (different context)
OSV says fixed in 1.2.3, Debian says fixed in 1.2.3-2 (patch backport)
One source says "not affected", another hasn't assessed yet (absence vs. negation)

Temporal Complexity

Source A updated yesterday, Source B updated 3 months ago
CVE was "pending" but the upstream project is now abandoned
Fix was released but then reverted


Source Taxonomy and Strategy
I categorize sources into tiers based on their role, not just trust:
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SOURCE TAXONOMY                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  TIER 0: INTERNAL SIGNALS (Highest Authority for Echo-specific decisions)  │
│  ├── Echo CSV (not_applicable overrides from research/AI)                  │
│  ├── Echo data.json (base advisory corpus)                                 │
│  └── Analyst manual inputs (future: ticket system integration)             │
│                                                                             │
│  TIER 1: AUTHORITATIVE VULNERABILITY REGISTRIES                            │
│  ├── NVD (CVE metadata, CVSS, rejection status)                           │
│  ├── MITRE CVE List (CVE existence, basic description)                    │
│  ├── CISA KEV (known exploited - critical signal)                         │
│  └── VulnCheck/VulnDB (commercial enrichment, if licensed)                │
│                                                                             │
│  TIER 2: DISTRIBUTION/VENDOR SECURITY TRACKERS                             │
│  ├── Debian Security Tracker (authoritative for Debian packages)          │
│  ├── Red Hat Security Data (CSAF/VEX for RHEL)                            │
│  ├── Ubuntu CVE Tracker                                                    │
│  ├── Alpine SecDB                                                          │
│  ├── SUSE OVAL                                                             │
│  └── Amazon Linux Security Center                                          │
│                                                                             │
│  TIER 3: ECOSYSTEM ADVISORY AGGREGATORS                                    │
│  ├── OSV (aggregates: PyPI, npm, Go, Rust, Linux, etc.)                   │
│  ├── GitHub Advisory Database (GHSA, covers npm, pip, etc.)               │
│  └── Snyk Intel (if licensed)                                              │
│                                                                             │
│  TIER 4: LANGUAGE/PACKAGE ECOSYSTEM FEEDS                                  │
│  ├── npm security advisories                                               │
│  ├── PyPA advisory-database                                                │
│  ├── RustSec                                                               │
│  ├── Go vulndb                                                             │
│  ├── RubyGems (rubysec)                                                    │
│  └── Packagist (PHP)                                                       │
│                                                                             │
│  TIER 5: UNSTRUCTURED / SUPPLEMENTARY                                      │
│  ├── Upstream project issue trackers (GitHub issues, GitLab)              │
│  ├── Mailing lists (oss-security, distros)                                │
│  ├── Vendor security pages (HTML scraping)                                │
│  └── Social signals (Twitter/X, Reddit - for early warning)               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
Key insight: Tier isn't about "trust" in abstract—it's about authority scope. Debian Tracker is Tier 2 but it's the only authoritative source for Debian-specific decisions. NVD is Tier 1 but it doesn't know about Debian patch backports.

Canonical Data Model
The core challenge is representing heterogeneous data in a unified model that preserves provenance and enables conflict resolution.
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CANONICAL DATA MODEL                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ENTITY: vulnerability_identity                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ canonical_vuln_id    (our internal ID, deterministic hash)          │   │
│  │ cve_id               (CVE-2024-XXXX, nullable)                      │   │
│  │ aliases[]            (GHSA-xxx, DSA-xxx, USN-xxx, etc.)             │   │
│  │ created_at           (first seen in our system)                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ENTITY: package_identity                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ canonical_package_id (our internal ID)                              │   │
│  │ echo_package_name    (name as it appears in Echo data.json)         │   │
│  │ ecosystem_mappings[] (ecosystem, ecosystem_package_name)            │   │
│  │   e.g., [("Debian", "openssl"), ("Alpine", "openssl"),              │   │
│  │          ("PyPI", "pyopenssl"), ("npm", null)]                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ENTITY: source_observation (immutable, append-only)                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ observation_id       (unique)                                       │   │
│  │ source_id            (nvd, osv, debian_tracker, echo_csv, etc.)     │   │
│  │ source_record_id     (ID within that source)                        │   │
│  │ canonical_vuln_id    (FK)                                           │   │
│  │ canonical_package_id (FK, nullable for vuln-only sources)           │   │
│  │ observed_at          (when we fetched this)                         │   │
│  │ source_updated_at    (when source says it was updated)              │   │
│  │ raw_payload          (JSONB - original source response)             │   │
│  │ normalized_signals   (JSONB - extracted signals, schema below)      │   │
│  │ confidence_score     (0-1, based on source quality + data quality)  │   │
│  │ is_latest            (boolean, only one per source+vuln+package)    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  SCHEMA: normalized_signals (embedded in source_observation)               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ fix_available        (boolean, nullable if unknown)                 │   │
│  │ fixed_version        (string, nullable)                             │   │
│  │ affected_versions    (version range expression, nullable)           │   │
│  │ status_assertion     (affected|not_affected|under_investigation)    │   │
│  │ rejection_status     (none|rejected|disputed|reserved)              │   │
│  │ cvss_score           (float, nullable)                              │   │
│  │ cvss_vector          (string, nullable)                             │   │
│  │ exploit_available    (boolean, nullable)                            │   │
│  │ exploit_in_wild      (boolean, nullable - CISA KEV signal)          │   │
│  │ references[]         (url, type: fix|advisory|exploit|discussion)   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ENTITY: advisory_state (SCD2, the output of decision engine)              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ advisory_id          (echo_package + cve_id composite key)          │   │
│  │ canonical_vuln_id    (FK)                                           │   │
│  │ canonical_package_id (FK)                                           │   │
│  │ state                (fixed|not_applicable|wont_fix|pending_upstream│   │
│  │                       |under_investigation|unknown)                 │   │
│  │ state_type           (final|non_final)                              │   │
│  │ fixed_version        (resolved from best source)                    │   │
│  │ confidence           (high|medium|low - based on source agreement)  │   │
│  │ explanation          (customer-facing text)                         │   │
│  │ explanation_template (which template generated explanation)         │   │
│  │ reason_code          (machine-readable: CSV_OVERRIDE, OSV_FIX, etc.)│   │
│  │ evidence_json        (sources + signals that led to this decision)  │   │
│  │ decision_rule        (which rule fired, version)                    │   │
│  │ contributing_sources (array of source_ids that informed decision)   │   │
│  │ dissenting_sources   (sources that disagreed, for audit)            │   │
│  │ effective_from       (SCD2)                                         │   │
│  │ effective_to         (SCD2, null if current)                        │   │
│  │ is_current           (boolean)                                      │   │
│  │ run_id               (which pipeline run produced this)             │   │
│  │ staleness_score      (0-1, how stale is the underlying data)        │   │
│  │ next_review_at       (when to re-check even if no new signals)      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

Architecture: Full System
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                                    CONTROL PLANE                                         │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐         │
│  │ Source Registry│  │ Rule Registry  │  │ Package Alias  │  │ Feature Flags  │         │
│  │ (source configs│  │ (versioned     │  │ Registry       │  │ (gradual       │         │
│  │  schedules,    │  │  decision      │  │ (Echo pkg →    │  │  rollout,      │         │
│  │  credentials,  │  │  rules, A/B    │  │  ecosystem     │  │  source        │         │
│  │  health)       │  │  testing)      │  │  mappings)     │  │  toggles)      │         │
│  └────────────────┘  └────────────────┘  └────────────────┘  └────────────────┘         │
└───────────────────────────────────────────┬──────────────────────────────────────────────┘
                                            │
┌───────────────────────────────────────────▼──────────────────────────────────────────────┐
│                              ORCHESTRATION (Airflow)                                     │
│                                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │                         DAG: source_ingestion (per source)                      │    │
│  │   Each source runs independently. Failure in one doesn't block others.          │    │
│  │   Schedules vary: NVD hourly, CISA KEV hourly, Debian daily, etc.              │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                            │                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │                         DAG: enrichment_pipeline (hourly)                       │    │
│  │   Triggered after source ingestion. Processes only changed/stale advisories.   │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                            │                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │                         DAG: quality_monitoring (continuous)                    │    │
│  │   Staleness detection, anomaly detection, source health checks.                │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
└───────────────────────────────────────────┬──────────────────────────────────────────────┘
                                            │
┌───────────────────────────────────────────▼──────────────────────────────────────────────┐
│                                SOURCE ADAPTER LAYER                                      │
│                                                                                          │
│   Each adapter implements a common interface:                                            │
│   - fetch_incremental(since: timestamp) → raw records                                   │
│   - fetch_full() → raw records (for backfill/recovery)                                  │
│   - get_health_status() → SourceHealth                                                  │
│   - normalize(raw) → NormalizedObservation                                              │
│                                                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  │   NVD    │ │   OSV    │ │  Debian  │ │  GHSA    │ │ CISA KEV │ │ Echo CSV │  ...    │
│  │ Adapter  │ │ Adapter  │ │ Adapter  │ │ Adapter  │ │ Adapter  │ │ Adapter  │         │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘         │
│       │            │            │            │            │            │                 │
│       │  ┌─────────────────────────────────────────────────────────────┐                │
│       │  │              ADAPTER FRAMEWORK FEATURES                     │                │
│       │  │  - Rate limiting (per-source, token bucket)                 │                │
│       │  │  - Retry with exponential backoff                           │                │
│       │  │  - Circuit breaker (stop hammering failed sources)          │                │
│       │  │  - Response caching (dedup identical fetches)               │                │
│       │  │  - Schema validation (reject malformed data early)          │                │
│       │  │  - Metrics emission (latency, success rate, volume)         │                │
│       │  └─────────────────────────────────────────────────────────────┘                │
│       │            │            │            │            │            │                 │
└───────┼────────────┼────────────┼────────────┼────────────┼────────────┼─────────────────┘
        │            │            │            │            │            │
        ▼            ▼            ▼            ▼            ▼            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              RAW DATA LAKE (Snowflake)                                  │
│                                                                                          │
│   Schema: raw_sources                                                                    │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│   │ Table per source: raw.nvd_cves, raw.osv_vulns, raw.debian_tracker, ...          │   │
│   │                                                                                  │   │
│   │ Common columns:                                                                  │   │
│   │   - ingestion_id (unique per fetch)                                             │   │
│   │   - ingested_at (timestamp)                                                     │   │
│   │   - source_record_id (ID from source)                                           │   │
│   │   - raw_payload (VARIANT/JSONB - full original response)                        │   │
│   │   - fetch_metadata (API endpoint, params, response headers)                     │   │
│   │                                                                                  │   │
│   │ Retention: raw data kept for 90 days (replay, debugging, audit)                 │   │
│   │ Partitioned by: ingested_at (for efficient pruning)                             │   │
│   └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
└───────────────────────────────────────────┬─────────────────────────────────────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           NORMALIZATION LAYER (dbt)                                     │
│                                                                                          │
│   STAGE 1: Schema Normalization                                                         │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│   │ Each source → staging model that extracts fields into canonical schema          │   │
│   │ Example: stg_nvd_cves extracts cve_id, cvss, cpe_matches, references           │   │
│   │ Example: stg_osv_vulns extracts aliases, affected[], fixed_versions[]          │   │
│   │                                                                                  │   │
│   │ Handles:                                                                         │   │
│   │  - Type coercion (string CVSS → float)                                          │   │
│   │  - Null handling (missing fields → explicit nulls)                              │   │
│   │  - Array flattening (one row per affected package where needed)                 │   │
│   │  - Timestamp normalization (various formats → UTC timestamp)                    │   │
│   └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
│   STAGE 2: Identity Resolution                                                          │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│   │ int_vulnerability_identity_resolution                                           │   │
│   │  - CVE-ID is primary key when available                                         │   │
│   │  - GHSA-xxx → CVE-xxx mapping (GitHub provides this)                           │   │
│   │  - DSA/USN → CVE mapping (distro trackers provide this)                        │   │
│   │  - For vulns without CVE: generate deterministic canonical_vuln_id             │   │
│   │                                                                                  │   │
│   │ int_package_identity_resolution                                                 │   │
│   │  - Join with package_alias_registry (maintained separately)                     │   │
│   │  - Echo package name → (ecosystem, ecosystem_package_name) mapping              │   │
│   │  - Handle ambiguity: "openssl" in Echo → which ecosystem?                       │   │
│   │    Default: Debian (per ASSUMPTIONS.md), but registry can override             │   │
│   └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
│   STAGE 3: Signal Extraction                                                            │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│   │ int_source_observations                                                         │   │
│   │  - Unified table of all observations from all sources                           │   │
│   │  - Each row = one source's view of one vuln (optionally scoped to package)     │   │
│   │  - normalized_signals extracted per source type:                                │   │
│   │      NVD: cvss_score, rejection_status, cpe_affected                           │   │
│   │      OSV: affected_versions, fixed_version, fix_commit_url                     │   │
│   │      Debian: per_release_status, maintainer_notes, backport_version            │   │
│   │      CISA KEV: exploit_in_wild = true                                          │   │
│   │      Echo CSV: status_override = not_applicable                                │   │
│   └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
└───────────────────────────────────────────┬─────────────────────────────────────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           ENRICHMENT LAYER (dbt)                                        │
│                                                                                          │
│   int_enriched_advisories                                                               │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│   │ For each (echo_advisory_id, package, cve):                                      │   │
│   │                                                                                  │   │
│   │ 1. Gather all source_observations for this vuln+package                         │   │
│   │                                                                                  │   │
│   │ 2. Compute aggregate signals with conflict resolution:                          │   │
│   │                                                                                  │   │
│   │    fix_available:                                                               │   │
│   │      - ANY source says fix exists → true                                        │   │
│   │      - Source priority for fixed_version: Debian > OSV > GHSA > NVD            │   │
│   │        (more specific to Echo's Debian context wins)                            │   │
│   │                                                                                  │   │
│   │    cvss_score:                                                                  │   │
│   │      - Prefer NVD (authoritative for CVSS)                                      │   │
│   │      - Fall back to GHSA, then OSV                                              │   │
│   │                                                                                  │   │
│   │    exploit_status:                                                              │   │
│   │      - CISA KEV = exploit_in_wild (highest signal)                             │   │
│   │      - Any source with exploit reference → exploit_available                    │   │
│   │                                                                                  │   │
│   │    rejection_status:                                                            │   │
│   │      - NVD REJECTED → propagate                                                 │   │
│   │      - MITRE DISPUTED → flag for review                                         │   │
│   │                                                                                  │   │
│   │ 3. Compute confidence based on source agreement:                                │   │
│   │      - All sources agree → high                                                 │   │
│   │      - Majority agree → medium                                                  │   │
│   │      - Conflict or single source → low                                          │   │
│   │                                                                                  │   │
│   │ 4. Compute staleness_score:                                                     │   │
│   │      - Based on max(source_updated_at) vs expected_update_frequency             │   │
│   │      - e.g., NVD not updated in 30 days for active CVE → stale                 │   │
│   │                                                                                  │   │
│   │ 5. Preserve dissenting_sources for audit trail                                  │   │
│   │                                                                                  │   │
│   └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
└───────────────────────────────────────────┬─────────────────────────────────────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           DECISION ENGINE (dbt + SQL)                                   │
│                                                                                          │
│   The decision engine is a prioritized rule chain. First matching rule wins.            │
│   Rules are versioned and auditable. Each rule produces:                                │
│     - state                                                                             │
│     - reason_code (machine-readable)                                                    │
│     - explanation_template (human-readable template)                                    │
│     - evidence (which signals triggered this rule)                                      │
│                                                                                          │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│   │                         RULE CHAIN (priority order)                             │   │
│   │                                                                                  │   │
│   │  ┌─────────────────────────────────────────────────────────────────────────┐   │   │
│   │  │ RULE 0: Internal Override (CSV)                            PRIORITY: 0  │   │   │
│   │  │ IF: echo_csv.status = 'not_applicable' for this CVE+package             │   │   │
│   │  │ THEN: state = not_applicable                                            │   │   │
│   │  │       reason_code = CSV_OVERRIDE                                        │   │   │
│   │  │       explanation = "Marked as not applicable by Echo security team.    │   │   │
│   │  │                      Reason: {csv.reason}. Updated: {csv.updated_at}"   │   │   │
│   │  │ NOTE: Internal signals always win. This is Echo's authoritative voice.  │   │   │
│   │  └─────────────────────────────────────────────────────────────────────────┘   │   │
│   │                                                                                  │   │
│   │  ┌─────────────────────────────────────────────────────────────────────────┐   │   │
│   │  │ RULE 1: CVE Rejected                                       PRIORITY: 1  │   │   │
│   │  │ IF: nvd.rejection_status = 'REJECTED'                                   │   │   │
│   │  │ THEN: state = not_applicable                                            │   │   │
│   │  │       reason_code = NVD_REJECTED                                        │   │   │
│   │  │       explanation = "This CVE has been rejected by NVD. Rejection       │   │   │
│   │  │                      reason: {nvd.rejection_reason}"                    │   │   │
│   │  └─────────────────────────────────────────────────────────────────────────┘   │   │
│   │                                                                                  │   │
│   │  ┌─────────────────────────────────────────────────────────────────────────┐   │   │
│   │  │ RULE 2: Upstream Fix Available                             PRIORITY: 2  │   │   │
│   │  │ IF: enriched.fix_available = true AND enriched.fixed_version IS NOT NULL│   │   │
│   │  │ THEN: state = fixed                                                     │   │   │
│   │  │       reason_code = UPSTREAM_FIX                                        │   │   │
│   │  │       explanation = "Fixed in version {fixed_version}. Source:          │   │   │
│   │  │                      {best_source}. Commit: {fix_commit_url}"           │   │   │
│   │  └─────────────────────────────────────────────────────────────────────────┘   │   │
│   │                                                                                  │   │
│   │  ┌─────────────────────────────────────────────────────────────────────────┐   │   │
│   │  │ RULE 3: Distro-Specific Not Affected                       PRIORITY: 3  │   │   │
│   │  │ IF: debian_tracker.status = 'not_affected' for this package             │   │   │
│   │  │     AND echo.ecosystem = 'Debian'                                       │   │   │
│   │  │ THEN: state = not_applicable                                            │   │   │
│   │  │       reason_code = DISTRO_NOT_AFFECTED                                 │   │   │
│   │  │       explanation = "Not affected in Debian. Reason: {debian.notes}     │   │   │
│   │  │                      (e.g., 'vulnerable code introduced later')"        │   │   │
│   │  └─────────────────────────────────────────────────────────────────────────┘   │   │
│   │                                                                                  │   │
│   │  ┌─────────────────────────────────────────────────────────────────────────┐   │   │
│   │  │ RULE 4: Wont Fix (Distro Decision)                         PRIORITY: 4  │   │   │
│   │  │ IF: debian_tracker.status = 'wont_fix' OR debian.tag = 'no-dsa'         │   │   │
│   │  │ THEN: state = wont_fix                                                  │   │   │
│   │  │       reason_code = DISTRO_WONT_FIX                                     │   │   │
│   │  │       explanation = "Debian has marked this as won't fix.               │   │   │
│   │  │                      Reason: {debian.notes}"                            │   │   │
│   │  │ NOTE: This is a final state but may be overridden by future CSV input   │   │   │
│   │  └─────────────────────────────────────────────────────────────────────────┘   │   │
│   │                                                                                  │   │
│   │  ┌─────────────────────────────────────────────────────────────────────────┐   │   │
│   │  │ RULE 5: Under Investigation                                PRIORITY: 5  │   │   │
│   │  │ IF: any_source.status = 'under_investigation'                           │   │   │
│   │  │     OR (cve_age < 7 days AND no upstream signals yet)                   │   │   │
│   │  │ THEN: state = under_investigation                                       │   │   │
│   │  │       reason_code = UNDER_INVESTIGATION                                 │   │   │
│   │  │       explanation = "This vulnerability is under investigation.         │   │   │
│   │  │                      {investigating_sources} are analyzing."            │   │   │
│   │  └─────────────────────────────────────────────────────────────────────────┘   │   │
│   │                                                                                  │   │
│   │  ┌─────────────────────────────────────────────────────────────────────────┐   │   │
│   │  │ RULE 6: Pending Upstream (Default)                         PRIORITY: 6  │   │   │
│   │  │ IF: no other rule matched                                               │   │   │
│   │  │ THEN: state = pending_upstream                                          │   │   │
│   │  │       reason_code = AWAITING_FIX                                        │   │   │
│   │  │       explanation = "No fix is currently available upstream.            │   │   │
│   │  │                      Last checked: {max_source_updated_at}.             │   │   │
│   │  │                      Sources consulted: {source_list}"                  │   │   │
│   │  └─────────────────────────────────────────────────────────────────────────┘   │   │
│   │                                                                                  │   │
│   └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
│   STATE CLASSIFICATION:                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│   │ Final states (skip re-enrichment unless triggered):                             │   │
│   │   - fixed, not_applicable, wont_fix                                             │   │
│   │                                                                                  │   │
│   │ Non-final states (always re-enrich):                                            │   │
│   │   - pending_upstream, under_investigation, unknown                              │   │
│   │                                                                                  │   │
│   │ Re-enrichment triggers for final states:                                        │   │
│   │   - CSV input changed                                                           │   │
│   │   - staleness_score > threshold (e.g., no source update in 30 days)            │   │
│   │   - Manual review request                                                       │   │
│   │   - Source that contributed to decision has new data                            │   │
│   └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
└───────────────────────────────────────────┬─────────────────────────────────────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           STATE MANAGEMENT LAYER (Snowflake)                            │
│                                                                                          │
│   mart.advisory_state_history (SCD Type 2)                                              │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│   │ - Append new row whenever state OR explanation changes                          │   │
│   │ - Previous row gets effective_to = current_timestamp, is_current = false        │   │
│   │ - New row gets effective_from = current_timestamp, is_current = true            │   │
│   │                                                                                  │   │
│   │ - run_id links to pipeline_runs table for full audit                            │   │
│   │ - evidence_json preserves all contributing signals at decision time             │   │
│   │ - decision_rule + version enables rule change impact analysis                   │   │
│   │                                                                                  │   │
│   │ - Snowflake Time Travel enables point-in-time queries even beyond SCD2          │   │
│   └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
│   mart.advisory_current (View)                                                          │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│   │ SELECT * FROM mart.advisory_state_history WHERE is_current = true               │   │
│   │                                                                                  │   │
│   │ This is the view consumed by downstream systems and the publication layer.      │   │
│   └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
│   meta.pipeline_runs (Audit)                                                            │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│   │ run_id, started_at, completed_at, status, trigger_type                          │   │
│   │ advisories_processed, advisories_changed, advisories_unchanged                  │   │
│   │ sources_succeeded[], sources_failed[], source_latencies{}                       │   │
│   │ rules_fired_counts{}, new_fixed_count, new_not_applicable_count                 │   │
│   │ error_summary                                                                   │   │
│   └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
└───────────────────────────────────────────┬─────────────────────────────────────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PUBLICATION LAYER                                          │
│                                                                                          │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│   │ JSON Export (advisory_current.json)                                             │   │
│   │  - Scheduled export after each pipeline run                                     │   │
│   │  - Published to S3/GCS, signed with checksum                                    │   │
│   │  - Maintains backward compatibility with existing data.json schema              │   │
│   │  - New fields (explanation, confidence, etc.) added without breaking existing   │   │
│   └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│   │ CSAF/VEX Export (Optional)                                                      │   │
│   │  - For enterprise customers who want standard format                            │   │
│   │  - Maps state → VEX status (fixed, known_affected, known_not_affected)          │   │
│   │  - Includes justification in standard fields                                    │   │
│   └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│   │ API Layer (Future)                                                              │   │
│   │  - REST/GraphQL API for real-time queries                                       │   │
│   │  - Webhook notifications on state changes                                       │   │
│   │  - Bulk export endpoints                                                        │   │
│   └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘

Handling Key Challenges
1. Conflicting Upstream Data
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                         CONFLICT RESOLUTION STRATEGY                                    │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  PRINCIPLE: Context-specific authority trumps generic authority                         │
│                                                                                         │
│  Example: CVE-2024-1234 affects "openssl" package in Echo                              │
│                                                                                         │
│  Source observations:                                                                   │
│    NVD:            affected = true, fixed_version = null, cvss = 7.5                   │
│    OSV:            affected = true, fixed_version = "1.1.1w"                           │
│    Debian Tracker: affected = false (note: "vulnerable code not present in bullseye")  │
│    GHSA:           affected = true, fixed_version = "1.1.1w"                           │
│                                                                                         │
│  Resolution for Echo (Debian-based):                                                    │
│    1. Debian Tracker says "not affected" for their package → this wins for status     │
│    2. State = not_applicable (RULE 3: DISTRO_NOT_AFFECTED)                            │
│    3. Explanation = "Not affected in Debian. Vulnerable code not present in bullseye" │
│    4. dissenting_sources = [NVD, OSV, GHSA] → preserved for audit                     │
│    5. confidence = medium (single authoritative source, but dissent exists)            │
│                                                                                         │
│  If Echo used Alpine instead:                                                           │
│    1. No Alpine-specific signal, fall back to OSV                                      │
│    2. OSV says fixed in 1.1.1w → state = fixed                                         │
│    3. Explanation = "Fixed in version 1.1.1w. Source: OSV"                             │
│                                                                                         │
│  CONFLICT RECORDING:                                                                    │
│    evidence_json = {                                                                    │
│      "deciding_source": "debian_tracker",                                              │
│      "deciding_signal": {"status": "not_affected", "note": "..."},                    │
│      "agreeing_sources": [],                                                           │
│      "dissenting_sources": [                                                           │
│        {"source": "nvd", "signal": {"affected": true}},                               │
│        {"source": "osv", "signal": {"affected": true, "fixed": "1.1.1w"}},            │
│        {"source": "ghsa", "signal": {"affected": true, "fixed": "1.1.1w"}}            │
│      ],                                                                                 │
│      "resolution_reason": "Debian-specific tracker is authoritative for Echo context" │
│    }                                                                                    │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
2. Staleness Detection and Re-enrichment
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                         STALENESS MANAGEMENT                                            │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  Each source has expected_update_frequency:                                             │
│    NVD:            daily (they aim for 24-48h enrichment)                              │
│    OSV:            real-time (commits detected within hours)                            │
│    Debian Tracker: daily (security team active on weekdays)                            │
│    CISA KEV:       weekly (new exploited vulns added weekly)                           │
│    Echo CSV:       on-demand (whenever research team updates)                          │
│                                                                                         │
│  Staleness score computation:                                                           │
│    staleness_score = 1 - exp(-days_since_update / expected_frequency_days)             │
│                                                                                         │
│    Example: NVD expected = 7 days, last update = 30 days ago                           │
│    staleness_score = 1 - exp(-30/7) = 0.986 (very stale)                               │
│                                                                                         │
│  Actions based on staleness:                                                            │
│    staleness < 0.3:  Fresh, no action needed                                           │
│    staleness 0.3-0.7: Aging, schedule background refresh                               │
│    staleness > 0.7:  Stale, force re-enrichment even for final states                  │
│    staleness > 0.9:  Critical, alert + investigate source health                       │
│                                                                                         │
│  Per-advisory staleness:                                                                │
│    advisory_staleness = weighted_avg(source_staleness for contributing_sources)        │
│    Advisories in final state with high staleness → re-open for verification            │
│                                                                                         │
│  Source health monitoring:                                                              │
│    If a source has no updates for 5x expected_frequency → alert: source may be dead   │
│    If a source returns errors for 3 consecutive runs → circuit breaker + alert        │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
3. Efficiency: Avoiding Re-processing
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                         INCREMENTAL PROCESSING STRATEGY                                 │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  PROBLEM: With 200k+ CVEs and dozens of sources, full re-analysis is expensive        │
│                                                                                         │
│  SOLUTION: Process only what changed                                                    │
│                                                                                         │
│  Step 1: Identify candidate advisories for processing                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ candidates = (                                                                   │   │
│  │   -- Non-final states always processed                                          │   │
│  │   SELECT advisory_id FROM advisory_current                                       │   │
│  │   WHERE state_type = 'non_final'                                                │   │
│  │                                                                                  │   │
│  │   UNION                                                                          │   │
│  │                                                                                  │   │
│  │   -- Final states with new source observations since last decision              │   │
│  │   SELECT ac.advisory_id FROM advisory_current ac                                │   │
│  │   JOIN source_observations so ON so.canonical_vuln_id = ac.canonical_vuln_id    │   │
│  │   WHERE ac.state_type = 'final'                                                 │   │
│  │     AND so.observed_at > ac.effective_from                                      │   │
│  │     AND so.source_id IN (ac.contributing_sources)  -- relevant source changed   │   │
│  │                                                                                  │   │
│  │   UNION                                                                          │   │
│  │                                                                                  │   │
│  │   -- Final states that are stale (need verification)                            │   │
│  │   SELECT advisory_id FROM advisory_current                                       │   │
│  │   WHERE state_type = 'final'                                                    │   │
│  │     AND staleness_score > 0.7                                                   │   │
│  │                                                                                  │   │
│  │   UNION                                                                          │   │
│  │                                                                                  │   │
│  │   -- CSV changed (always re-evaluate)                                           │   │
│  │   SELECT advisory_id FROM echo_csv_changes_this_run                             │   │
│  │ )                                                                                │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  Step 2: Batch enrichment only for candidates                                           │
│    - Reduces API calls to upstream sources                                             │
│    - Caches upstream responses by (source, cve_id) with TTL                           │
│    - Parallel fetching with rate limiting per source                                   │
│                                                                                         │
│  Step 3: Decision engine processes only candidates                                      │
│    - Unchanged advisories keep their current state (no SCD2 row added)                │
│    - Only write to history if state OR explanation actually changed                    │
│                                                                                         │
│  METRICS:                                                                               │
│    Typical run: 200k total advisories, ~5k candidates, ~500 state changes             │
│    Processing time: 5k enrichments vs 200k = 40x reduction                            │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
4. Source Adapter Resilience
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                         SOURCE ADAPTER RESILIENCE PATTERNS                              │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  1. RATE LIMITING (per source)                                                          │
│     - Token bucket algorithm: e.g., NVD allows 5 req/sec without API key              │
│     - Configuration in source_registry: {nvd: {rpm: 300, burst: 10}}                  │
│     - Sleep between batches, respect Retry-After headers                               │
│                                                                                         │
│  2. RETRY WITH EXPONENTIAL BACKOFF                                                      │
│     - Initial delay: 1s                                                                 │
│     - Max delay: 5 minutes                                                              │
│     - Max retries: 5                                                                    │
│     - Jitter: random 0-30% to prevent thundering herd                                  │
│     - Retry on: 429, 500, 502, 503, 504, network timeout                               │
│                                                                                         │
│  3. CIRCUIT BREAKER                                                                     │
│     - If source fails 5 consecutive times → open circuit                               │
│     - Circuit open: skip source for 15 minutes, use cached data                        │
│     - Half-open: try one request after 15 min, close if success                        │
│     - Alert on circuit open                                                             │
│                                                                                         │
│  4. GRACEFUL DEGRADATION                                                                │
│     - Pipeline continues even if sources fail                                          │
│     - Decision engine works with available data                                         │
│     - Advisories affected by failed source: staleness_score increases                  │
│     - No state change due to missing data (conservative: keep current state)           │
│                                                                                         │
│  5. CACHING                                                                             │
│     - Response cache: (source, cve_id, package) → response, ttl=1h                    │
│     - Dedup: don't fetch same CVE twice in one run                                     │
│     - Persistent cache in Redis/Snowflake for cross-run dedup                          │
│                                                                                         │
│  6. SOURCE HEALTH DASHBOARD                                                             │
│     - Success rate (last 24h, 7d, 30d)                                                 │
│     - Latency percentiles                                                               │
│     - Last successful fetch timestamp                                                   │
│     - Data volume trend (sudden drop = potential issue)                                │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘

Observability & Trust
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              OBSERVABILITY ARCHITECTURE                                 │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  LAYER 1: PIPELINE METRICS (Datadog/Prometheus)                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ Per-run metrics:                                                                 │   │
│  │   pipeline.run.duration_seconds                                                  │   │
│  │   pipeline.run.advisories.processed                                              │   │
│  │   pipeline.run.advisories.changed                                                │   │
│  │   pipeline.run.state_transitions{from, to}  (e.g., pending→fixed: 42)           │   │
│  │   pipeline.run.rules_fired{rule_id}                                              │   │
│  │                                                                                  │   │
│  │ Per-source metrics:                                                              │   │
│  │   source.fetch.duration_seconds{source}                                          │   │
│  │   source.fetch.success{source}                                                   │   │
│  │   source.fetch.failure{source, error_type}                                       │   │
│  │   source.fetch.records_count{source}                                             │   │
│  │   source.circuit_breaker.state{source}  (closed/open/half-open)                 │   │
│  │                                                                                  │   │
│  │ Data quality metrics:                                                            │   │
│  │   quality.staleness.avg                                                          │   │
│  │   quality.staleness.p99                                                          │   │
│  │   quality.confidence.distribution{level}                                         │   │
│  │   quality.dissent.count  (advisories with source disagreement)                  │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  LAYER 2: ALERTING                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ CRITICAL:                                                                        │   │
│  │   - Pipeline failed to complete                                                  │   │
│  │   - No state changes in 24h (pipeline may be stuck)                             │   │
│  │   - Source circuit breaker open for >1h                                         │   │
│  │   - >10% of advisories have staleness > 0.9                                     │   │
│  │                                                                                  │   │
│  │ WARNING:                                                                         │   │
│  │   - Source latency > 2x baseline                                                │   │
│  │   - Unexpected spike in state transitions (potential data issue)                │   │
│  │   - New CVEs not enriched within SLA (e.g., 4h for critical)                    │   │
│  │   - Rule firing anomaly (a rule that usually fires 100x now fired 10x)          │   │
│  │                                                                                  │   │
│  │ INFO:                                                                            │   │
│  │   - New source added/removed                                                     │   │
│  │   - Rule version updated                                                         │   │
│  │   - Scheduled maintenance window                                                 │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  LAYER 3: DATA QUALITY MONITORING (dbt tests + custom)                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ Schema tests (dbt built-in):                                                     │   │
│  │   - unique: advisory_id                                                          │   │
│  │   - not_null: state, explanation, canonical_vuln_id                             │   │
│  │   - accepted_values: state in (fixed, pending_upstream, ...)                    │   │
│  │   - relationships: FK integrity                                                  │   │
│  │                                                                                  │   │
│  │ Custom data tests:                                                               │   │
│  │   - No regression: advisory that was 'fixed' should not become 'pending'        │   │
│  │     (unless explicit override or new CVE info)                                  │   │
│  │   - Explanation not empty for customer-facing states                            │   │
│  │   - evidence_json is valid JSON and contains required fields                    │   │
│  │   - CVE-ID format validation                                                    │   │
│  │   - fixed_version is semver-parseable (where applicable)                        │   │
│  │                                                                                  │   │
│  │ Anomaly detection:                                                               │   │
│  │   - State distribution drift (compare to 7-day rolling avg)                     │   │
│  │   - Volume anomaly (significantly more/fewer advisories than expected)          │   │
│  │   - Source contribution anomaly (a source suddenly contributes 0 records)       │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  LAYER 4: STALLED CVE DETECTION                                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ Definition: CVE in non-final state for extended period                          │   │
│  │                                                                                  │   │
│  │ Stalled criteria:                                                                │   │
│  │   - pending_upstream for >90 days (may indicate abandoned upstream)             │   │
│  │   - under_investigation for >30 days (investigation stalled)                    │   │
│  │   - High-severity (CVSS >= 7) pending for >14 days (SLA breach)                │   │
│  │   - CISA KEV (exploited) pending for >7 days (critical SLA)                    │   │
│  │                                                                                  │   │
│  │ Actions:                                                                         │   │
│  │   - Generate weekly stalled CVE report                                          │   │
│  │   - Auto-escalate to security team for manual review                            │   │
│  │   - Consider marking as wont_fix if upstream truly abandoned                    │   │
│  │   - Surface in dashboard for visibility                                         │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  LAYER 5: AUDIT & TRACEABILITY                                                         │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ Every state change is traceable:                                                 │   │
│  │   - Which pipeline run? (run_id)                                                │   │
│  │   - Which rule? (decision_rule + version)                                       │   │
│  │   - Which sources? (contributing_sources, dissenting_sources)                   │   │
│  │   - What was the evidence? (evidence_json with full signals)                    │   │
│  │   - Who/what triggered the change? (trigger_type: scheduled/csv_update/manual)  │   │
│  │                                                                                  │   │
│  │ Query capabilities:                                                              │   │
│  │   - "Why did CVE-X become fixed on Jan 5?" → join to evidence                   │   │
│  │   - "What changed in run 12345?" → filter history by run_id                     │   │
│  │   - "Show all decisions made by RULE 3" → filter by decision_rule               │   │
│  │   - "Point-in-time: what was state on Dec 1?" → SCD2 temporal query             │   │
│  │                                                                                  │   │
│  │ Retention:                                                                       │   │
│  │   - advisory_state_history: indefinite (audit requirement)                      │   │
│  │   - source_observations: 1 year (space management, raw in lake longer)          │   │
│  │   - pipeline_runs: 2 years                                                       │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘

Rule Engine Maintenance & Extensibility
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           RULE ENGINE GOVERNANCE                                        │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  RULE VERSIONING:                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ - Rules stored in version control (git)                                         │   │
│  │ - Each rule has: rule_id, version, effective_from, effective_to                 │   │
│  │ - Rule changes require PR review (security team approval)                       │   │
│  │ - Rule version recorded in advisory_state_history.decision_rule                 │   │
│  │                                                                                  │   │
│  │ Schema (rule_registry table):                                                    │   │
│  │   rule_id, version, priority, condition_sql, state_output,                      │   │
│  │   reason_code, explanation_template, effective_from, is_active                  │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  ADDING A NEW RULE:                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ 1. Define the rule in code/SQL with clear condition                             │   │
│  │ 2. Write unit tests: given these signals, expect this state                     │   │
│  │ 3. Dry-run: apply rule to historical data, review impact                        │   │
│  │ 4. Shadow mode: run new rule in parallel, compare to production (no publish)    │   │
│  │ 5. Gradual rollout: enable for 10% of advisories, monitor                       │   │
│  │ 6. Full rollout: enable globally                                                │   │
│  │                                                                                  │   │
│  │ Example: Adding "RULE 7: Disputed CVE"                                          │   │
│  │   Condition: nvd.status = 'DISPUTED' OR mitre.tag = 'disputed'                  │   │
│  │   State: under_investigation (not final, needs human review)                    │   │
│  │   Explanation: "This CVE is disputed. {dispute_reason}"                         │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  ADDING A NEW SOURCE:                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ 1. Implement adapter (fetch, normalize, health check)                           │   │
│  │ 2. Define schema mapping: source fields → normalized_signals                    │   │
│  │ 3. Add to source_registry with schedule and rate limits                         │   │
│  │ 4. Create staging dbt model: stg_new_source                                     │   │
│  │ 5. Update int_source_observations to include new source                         │   │
│  │ 6. Decide trust tier and conflict resolution priority                           │   │
│  │ 7. Update enrichment layer if new source is authoritative for any signal        │   │
│  │ 8. Add new rules if source provides unique signals                              │   │
│  │                                                                                  │   │
│  │ Timeline: ~1-2 days for structured API source, ~1 week for scraping             │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  RULE TESTING FRAMEWORK:                                                                │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ Unit tests (pytest + dbt):                                                       │   │
│  │   - Mock source observations                                                     │   │
│  │   - Assert expected state + explanation                                          │   │
│  │                                                                                  │   │
│  │ Integration tests:                                                               │   │
│  │   - Seed database with known CVEs and source data                               │   │
│  │   - Run full pipeline                                                            │   │
│  │   - Assert final states match expected                                           │   │
│  │                                                                                  │   │
│  │ Regression tests:                                                                │   │
│  │   - Golden dataset of ~100 CVEs with known correct states                       │   │
│  │   - Run after every rule change                                                  │   │
│  │   - Alert if any golden state changes unexpectedly                              │   │
│  │                                                                                  │   │
│  │ Impact analysis:                                                                 │   │
│  │   - Before rule change: simulate on production data                             │   │
│  │   - Report: "This rule change would affect X advisories"                        │   │
│  │   - Review affected advisories before deploying                                 │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘

Migration Path
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           MIGRATION STRATEGY                                            │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  CURRENT STATE:                                                                         │
│    - data.json published by existing factory pipeline                                  │
│    - No historical tracking                                                            │
│    - No explanations                                                                    │
│    - Limited enrichment                                                                 │
│                                                                                         │
│  PHASE 1: SHADOW MODE (Week 1-2)                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ - Deploy new pipeline alongside existing                                         │   │
│  │ - Ingest same data.json as input                                                │   │
│  │ - Run enrichment and decision engine                                             │   │
│  │ - Output to advisory_current_shadow (not published)                              │   │
│  │ - Compare: new_state vs implied_state_from_existing_data                        │   │
│  │ - Fix discrepancies, tune rules                                                  │   │
│  │ - Goal: >95% agreement with expected states                                      │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  PHASE 2: DUAL PUBLISH (Week 3-4)                                                      │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ - New pipeline publishes advisory_current.json                                   │   │
│  │ - Old pipeline continues publishing data.json                                    │   │
│  │ - Both available to consumers                                                    │   │
│  │ - Monitor consumer feedback                                                      │   │
│  │ - Validate explanations make sense                                               │   │
│  │ - Goal: new format adopted by internal consumers                                │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  PHASE 3: CUTOVER (Week 5)                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ - New pipeline becomes primary                                                   │   │
│  │ - Old data.json deprecated (redirect or generate from new)                      │   │
│  │ - Full SCD2 history active                                                       │   │
│  │ - Alerting and monitoring live                                                   │   │
│  │ - Documentation updated                                                          │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  PHASE 4: ENHANCEMENT (Week 6+)                                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ - Add more sources incrementally                                                 │   │
│  │ - Refine rules based on feedback                                                │   │
│  │ - Build API layer                                                                │   │
│  │ - Add customer-facing explanation UI                                             │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  ROLLBACK PLAN:                                                                         │
│    - Keep old pipeline runnable for 30 days post-cutover                              │
│    - Snapshot of last old data.json preserved                                         │
│    - If critical issue: revert to old pipeline within 1 hour                          │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘

Prototype Scope (What to Actually Build)
Given the mature design above, the prototype demonstrates the core concepts with minimal implementation:
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           PROTOTYPE SCOPE                                               │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  IMPLEMENT:                                                                             │
│    ✓ SQLite database with SCD2 schema                                                  │
│    ✓ Load data.json (first run) → advisory_history table                              │
│    ✓ Load CSV (every run) → internal_signals table                                    │
│    ✓ Two source adapters: NVD (mock), OSV (mock or real)                              │
│    ✓ Normalization: extract signals from each source                                   │
│    ✓ Decision engine: 4 rules (CSV override, rejected, fixed, pending)                │
│    ✓ Explanation generation with evidence                                              │
│    ✓ SCD2 state tracking                                                               │
│    ✓ JSON output with current state + explanation                                      │
│    ✓ Basic run logging                                                                 │
│                                                                                         │
│  MOCK/SIMPLIFY:                                                                         │
│    - API calls: use mock responses or cache real responses                             │
│    - Rate limiting: simple sleep between calls                                         │
│    - Caching: in-memory dict, not Redis                                                │
│    - Orchestration: single Python script, not Airflow                                  │
│    - Storage: SQLite, not Snowflake                                                    │
│    - Monitoring: print statements, not Datadog                                         │
│                                                                                         │
│  DOCUMENT GAPS:                                                                         │
│    - "In production, this would use Snowflake with..."                                │
│    - "Additional sources would be added via..."                                        │
│    - "Conflict resolution between N sources would..."                                  │
│                                                                                         │
│  DELIVERABLE: Working Python script that:                                              │
│    1. Reads data.json + CSV                                                            │
│    2. Queries mock NVD/OSV                                                             │
│    3. Applies rules                                                                     │
│    4. Produces advisory_current.json with explanations                                 │
│    5. Maintains state history in SQLite                                                │
│    6. Can run multiple times showing incremental updates                               │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘

