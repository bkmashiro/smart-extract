package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps the local SQLite learning database.
type Store struct {
	db *sql.DB
}

// Open opens or creates a SQLite store at path and applies the current schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}
	db.SetMaxOpenConns(1)

	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("set sqlite busy timeout: %w", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable sqlite foreign keys: %w", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA journal_mode = WAL;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable sqlite wal: %w", err)
	}

	st := &Store{db: db}
	if err := st.applySchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return st, nil
}

// Close closes the underlying database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) applySchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply sqlite schema: %w", err)
	}
	return nil
}

// SaveExact upserts an exact archive cache entry.
func (s *Store) SaveExact(ctx context.Context, entry ExactCacheEntry) error {
	if entry.ArchiveKey == "" {
		return errors.New("archive key is required")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO archive_cache (archive_key, password, source, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(archive_key) DO UPDATE SET
			password = excluded.password,
			source = excluded.source,
			updated_at = excluded.updated_at
	`, entry.ArchiveKey, entry.Password, entry.Source, nowString())
	if err != nil {
		return fmt.Errorf("save exact cache: %w", err)
	}
	return nil
}

// LookupExact returns a cached password for archiveKey, if present.
func (s *Store) LookupExact(ctx context.Context, archiveKey string) (string, bool, error) {
	var password string
	err := s.db.QueryRowContext(ctx, `SELECT password FROM archive_cache WHERE archive_key = ?`, archiveKey).Scan(&password)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("lookup exact cache: %w", err)
	}
	return password, true, nil
}

// AddObservation appends a successful password observation.
func (s *Store) AddObservation(ctx context.Context, obs PasswordObservation) (int64, error) {
	successAt := obs.SuccessAt
	if successAt.IsZero() {
		successAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin password observation: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		INSERT INTO password_observation (
			archive_path, archive_name, parent_dir, password, source, archive_size,
			root_session_id, parent_archive, depth, success_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, obs.ArchivePath, obs.ArchiveName, obs.ParentDir, obs.Password, obs.Source, obs.ArchiveSize,
		obs.RootSessionID, obs.ParentArchive, obs.Depth, timeString(successAt))
	if err != nil {
		return 0, fmt.Errorf("add password observation: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read observation id: %w", err)
	}
	if obs.Password != "" {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO password_dict (password, total_uses, source, updated_at)
			VALUES (?, 1, ?, ?)
			ON CONFLICT(password) DO UPDATE SET
				total_uses = total_uses + 1,
				source = excluded.source,
				updated_at = excluded.updated_at
		`, obs.Password, obs.Source, timeString(successAt)); err != nil {
			return 0, fmt.Errorf("update password dictionary: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit password observation: %w", err)
	}
	return id, nil
}

// ListObservations returns observations ordered by insertion id.
func (s *Store) ListObservations(ctx context.Context) ([]PasswordObservation, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, archive_path, archive_name, parent_dir, password, source, archive_size,
		       root_session_id, parent_archive, depth, success_at
		FROM password_observation
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("list observations: %w", err)
	}
	defer rows.Close()

	var out []PasswordObservation
	for rows.Next() {
		var obs PasswordObservation
		var successAt string
		if err := rows.Scan(&obs.ID, &obs.ArchivePath, &obs.ArchiveName, &obs.ParentDir, &obs.Password, &obs.Source,
			&obs.ArchiveSize, &obs.RootSessionID, &obs.ParentArchive, &obs.Depth, &successAt); err != nil {
			return nil, fmt.Errorf("scan observation: %w", err)
		}
		parsed, err := parseTime(successAt)
		if err != nil {
			return nil, fmt.Errorf("parse observation success_at: %w", err)
		}
		obs.SuccessAt = parsed
		out = append(out, obs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate observations: %w", err)
	}
	return out, nil
}

// SessionPasswords returns recent distinct successful passwords for a parent directory.
func (s *Store) SessionPasswords(ctx context.Context, parentDir string, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT password
		FROM (
			SELECT password, MAX(success_at) AS last_success_at
			FROM password_observation
			WHERE parent_dir = ?
			GROUP BY password
		)
		ORDER BY last_success_at DESC
		LIMIT ?
	`, parentDir, limit)
	if err != nil {
		return nil, fmt.Errorf("query session passwords: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var password string
		if err := rows.Scan(&password); err != nil {
			return nil, fmt.Errorf("scan session password: %w", err)
		}
		out = append(out, password)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate session passwords: %w", err)
	}
	return out, nil
}

// PatternRules returns pattern rules for the requested type/key.
func (s *Store) PatternRules(ctx context.Context, patternType, patternKey string) ([]PatternRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, pattern_type, pattern_key, password, alpha, beta, support, confidence, source, updated_at
		FROM pattern_rule
		WHERE pattern_type = ? AND pattern_key = ?
		ORDER BY confidence DESC, support DESC, id ASC
	`, patternType, patternKey)
	if err != nil {
		return nil, fmt.Errorf("query pattern rules: %w", err)
	}
	defer rows.Close()

	var out []PatternRule
	for rows.Next() {
		var r PatternRule
		var updatedAt string
		if err := rows.Scan(&r.ID, &r.PatternType, &r.PatternKey, &r.Password, &r.Alpha, &r.Beta, &r.Support, &r.Confidence, &r.Source, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan pattern rule: %w", err)
		}
		parsed, err := parseTime(updatedAt)
		if err != nil {
			return nil, fmt.Errorf("parse pattern updated_at: %w", err)
		}
		r.UpdatedAt = parsed
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pattern rules: %w", err)
	}
	return out, nil
}

// TopPasswords returns password dictionary entries by local use count.
func (s *Store) TopPasswords(ctx context.Context, limit int) ([]PasswordStat, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT password, total_uses, source, updated_at
		FROM password_dict
		ORDER BY total_uses DESC, password ASC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("query top passwords: %w", err)
	}
	defer rows.Close()

	var out []PasswordStat
	for rows.Next() {
		var p PasswordStat
		var updatedAt string
		if err := rows.Scan(&p.Password, &p.TotalUses, &p.Source, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan password stat: %w", err)
		}
		parsed, err := parseTime(updatedAt)
		if err != nil {
			return nil, fmt.Errorf("parse password updated_at: %w", err)
		}
		p.UpdatedAt = parsed
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate top passwords: %w", err)
	}
	return out, nil
}

// GetPreferences returns stored preferences, or zero/default values when absent.
func (s *Store) GetPreferences(ctx context.Context) (Preferences, error) {
	var prefs Preferences
	var deleteAfter, deleteSet, privacyMode int
	err := s.db.QueryRowContext(ctx, `
		SELECT delete_after_extract, delete_preference_set, cost_budget, max_parallel_probes, privacy_mode
		FROM preferences
		WHERE id = 1
	`).Scan(&deleteAfter, &deleteSet, &prefs.CostBudget, &prefs.MaxParallelProbes, &privacyMode)
	if errors.Is(err, sql.ErrNoRows) {
		return prefs, nil
	}
	if err != nil {
		return Preferences{}, fmt.Errorf("get preferences: %w", err)
	}
	prefs.DeleteAfterExtract = deleteAfter != 0
	prefs.DeletePreferenceSet = deleteSet != 0
	prefs.PrivacyMode = privacyMode != 0
	return prefs, nil
}

// MigrationVersion returns the recorded version for a named migration.
func (s *Store) MigrationVersion(ctx context.Context, name string) (int, error) {
	var version int
	err := s.db.QueryRowContext(ctx, `SELECT version FROM schema_migration WHERE name = ?`, name).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("get migration version: %w", err)
	}
	return version, nil
}

func timeString(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func nowString() string {
	return timeString(time.Now().UTC())
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}
