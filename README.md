# 🌑 Hush — Advisory Data Pipeline

This repo is a lightweight handoff for the Echo advisory pipeline task. It captures the expected architecture, decision logic, and open questions so another agent can implement the prototype quickly and correctly.

**Scope**
- Periodically enrich Echo advisories using upstream sources (OSV + NVD).
- Decide and persist advisory state with explainability.
- Store state history as SCD2 in SQLite with a current-state view.

**Deliverables expected by the task**
- Technical design (architecture, data model, state logic, reliability).
- Short deck (max 5 slides) in Markdown.
- Prototype (Python) that reads `data.json` and `advisory_not_applicable.csv`, enriches, decides, and emits an updated advisory view.

**Key decisions already made**
- CSV is authoritative for `not_applicable` (all CSV rows map to that state).
- OSV and NVD are used as upstream sources; design must scale to more.
- SQLite is the storage layer; advisory history is SCD2.
- CSV `fixed_version` is retained as an open question (see `docs/OPEN_QUESTIONS.md`).

**Repository layout**
- `docs/DATA_CONTEXT.md`: what we know about the input data.
- `docs/DECISION_ENGINE.md`: detailed decision rules and explanations.
- `docs/ARCHITECTURE.md`: end-to-end system design.
- `docs/SOURCES.md`: NVD/OSV behavior and normalization guidance.
- `docs/ASSUMPTIONS.md`: assumptions and constraints.
- `docs/OPEN_QUESTIONS.md`: unresolved items.
- `docs/DECK.md`: 5-slide Markdown deck.
- `docs/HANDOFF.md`: suggested next steps for implementation.
- `docs/SCHEMA.sql`: SQLite schema draft for SCD2 storage.
- `docs/RUNBOOK.md`: prototype runbook (expected operator steps).

**Primary inputs**
- `advisory_not_applicable.csv` (live feed, authoritative)
- `https://advisory.echohq.com/data.json` (Echo public advisory dataset)
