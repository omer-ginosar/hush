# Assumptions

- Package names largely resemble Debian source/binary packages; OSV ecosystem likely `Debian`.
- CSV rows are authoritative and map to `not_applicable` for now.
- `not_applicable` is global to Echo, not per-customer.
- `pending_upstream` is non-final; SLA starts when a fix exists.
- `wont_fix` is a final state but may require additional upstream signals beyond OSV/NVD.
- NVD is used for metadata and rejection status, not for fixed versions.
- OSV is the primary upstream source for fixed versions and affected ranges.
- The prototype intentionally uses only one or two sources and documents gaps.
- SQLite is the only storage component for the prototype.
- State history is stored as SCD2; a current-state view drives the app.
- CSV `fixed_version` is retained as a TODO and not used for decisions yet.
- Prototype focuses on correctness and clarity over performance.
