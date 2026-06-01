package store

const schemaSQL = `
CREATE TABLE IF NOT EXISTS schema_migration (
    name TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS archive_cache (
    archive_key TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS password_observation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    archive_path TEXT NOT NULL DEFAULT '',
    archive_name TEXT NOT NULL DEFAULT '',
    parent_dir TEXT NOT NULL DEFAULT '',
    password TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    archive_size INTEGER NOT NULL DEFAULT 0,
    root_session_id TEXT NOT NULL DEFAULT '',
    parent_archive TEXT NOT NULL DEFAULT '',
    depth INTEGER NOT NULL DEFAULT 0,
    success_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_password_observation_password
    ON password_observation(password);

CREATE INDEX IF NOT EXISTS idx_password_observation_parent_dir
    ON password_observation(parent_dir);

CREATE TABLE IF NOT EXISTS pattern_rule (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_type TEXT NOT NULL,
    pattern_key TEXT NOT NULL,
    password TEXT NOT NULL,
    alpha REAL NOT NULL DEFAULT 1,
    beta REAL NOT NULL DEFAULT 1,
    support INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    UNIQUE(pattern_type, pattern_key, password)
);

CREATE INDEX IF NOT EXISTS idx_pattern_rule_lookup
    ON pattern_rule(pattern_type, pattern_key, confidence DESC, support DESC);

CREATE TABLE IF NOT EXISTS password_dict (
    password TEXT PRIMARY KEY,
    total_uses INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session_context (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    root_session_id TEXT NOT NULL DEFAULT '',
    parent_dir TEXT NOT NULL DEFAULT '',
    password TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    success_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_context_dir_time
    ON session_context(parent_dir, success_at DESC);

CREATE TABLE IF NOT EXISTS preferences (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    delete_after_extract INTEGER NOT NULL DEFAULT 0,
    delete_preference_set INTEGER NOT NULL DEFAULT 0,
    cost_budget TEXT NOT NULL DEFAULT '',
    max_parallel_probes INTEGER NOT NULL DEFAULT 0,
    privacy_mode INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
`
