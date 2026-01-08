# Data Context

This summarizes what we know about the provided inputs based on the CSV and the `data.json` sample.

## `advisory_not_applicable.csv`
- Columns: `cve_id`, `package`, `status`, `fixed_version`, `internal_status`.
- The sample shows `status` consistently as `not_applicable` with richer reasoning in `internal_status` (e.g., `disputed`, `code_not_in_use`, `os_specific`, `code_not_released`).
- Some rows include a `fixed_version` even when status is `not_applicable`.
- This file is a live, authoritative feed and may change on every run.

## `data.json` (sample)
- Shape: `package -> cve_id -> { fixed_version? }`.
- CVEs may have an explicit `fixed_version`, or be `{}` when unknown.
- Some package entries are empty objects (no CVEs yet or not populated).
- Non-CVE identifiers exist (e.g., `TEMP-*`), which should not be sent to NVD.

## Package ecosystem hint
- The expanded package list (e.g., `apt`, `adduser`, `apache2`, `lib*`) strongly resembles Debian source/binary package names.
- This likely implies OSV ecosystem `Debian`, but needs verification (see `docs/OPEN_QUESTIONS.md`).

