-- SQLite schema for advisory state history (SCD2) and run metadata.

CREATE TABLE IF NOT EXISTS advisory_state_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  advisory_id TEXT NOT NULL,
  package TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  state TEXT NOT NULL,
  state_type TEXT NOT NULL,
  fixed_version TEXT,
  explanation TEXT NOT NULL,
  reason_code TEXT,
  decision_rule TEXT NOT NULL,
  evidence_json TEXT,
  effective_from TEXT NOT NULL,
  effective_to TEXT,
  is_current INTEGER NOT NULL DEFAULT 1,
  run_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_advisory_current
  ON advisory_state_history(advisory_id)
  WHERE is_current = 1;

CREATE INDEX IF NOT EXISTS idx_advisory_cve
  ON advisory_state_history(cve_id);

CREATE INDEX IF NOT EXISTS idx_advisory_package
  ON advisory_state_history(package);

CREATE INDEX IF NOT EXISTS idx_advisory_state
  ON advisory_state_history(state);

CREATE INDEX IF NOT EXISTS idx_advisory_state_type
  ON advisory_state_history(state_type);

CREATE TABLE IF NOT EXISTS run_metadata (
  run_id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  stats_json TEXT,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS upstream_cache (
  source TEXT NOT NULL,
  cache_key TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  expires_at TEXT,
  payload_json TEXT NOT NULL,
  PRIMARY KEY (source, cache_key)
);

CREATE VIEW IF NOT EXISTS advisory_current AS
SELECT *
FROM advisory_state_history
WHERE is_current = 1;
