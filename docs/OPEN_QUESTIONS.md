# Open Questions

- Should any `internal_status` values be mapped to `wont_fix`, or keep all as `not_applicable`?
- How should we treat CSV `fixed_version` when `status=not_applicable`?
- What upstream signals can reliably drive `wont_fix` in the prototype?
- Confirm OSV ecosystem mapping (is `Debian` correct for all packages?).
- How to handle packages that do not exist in OSV (fall back to NVD only?).
- Frequency of pipeline runs (hourly, daily, on-demand?).
- Should we store additional provenance fields (actor, rule version, or dataset version)?
