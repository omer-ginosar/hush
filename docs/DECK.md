# Advisory Data Pipeline — Echo

## Slide 1 — 🧭 Goal & Lifecycle
- Build a single, explainable source of truth for advisory state.
- Lifecycle: `unknown` → `pending_upstream` → `fixed` / `not_applicable`.
- Every decision has evidence, provenance, and a preserved history (SCD2).

---

## Slide 2 — 🏗️ Architecture
- Ingest: `data.json` + live CSV.
- Enrich: OSV (fixes) + NVD (status/metadata).
- Decide: deterministic rules + explanations.
- Store: SQLite SCD2 + current-state view for the app.

---

## Slide 3 — 📦 Data Model
- `advisory_state_history` (SCD2): state + explanation + evidence + timestamps.
- `advisory_current` view: always-on snapshot for consumers.
- Evidence JSON preserves raw upstream payloads.

---

## Slide 4 — 🧠 Decision Logic
- CSV override → `not_applicable` (authoritative).
- OSV fix → `fixed` with version.
- NVD rejected/withdrawn → `not_applicable`.
- Else → `pending_upstream`.

---

## Slide 5 — ✅ Tradeoffs & Non‑Goals
- Tradeoff: prototype clarity over full-scale optimization.
- Non-goals: perfect version comparisons, full upstream dumps.
- Path to scale: add adapters, caches, and incremental scheduling.

