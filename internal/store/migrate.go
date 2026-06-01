package store

import (
	"context"
	"fmt"

	"github.com/bkmashiro/smart-extract/internal/config"
)

// MigrateLearned imports legacy learned.yaml data into SQLite.
func (s *Store) MigrateLearned(ctx context.Context, legacy *config.Learned) error {
	if legacy == nil {
		legacy = &config.Learned{}
	}
	version, err := s.MigrationVersion(ctx, "learned_yaml")
	if err != nil {
		return err
	}
	if version >= 1 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin learned migration: %w", err)
	}
	defer tx.Rollback()

	now := nowString()
	for archiveKey, password := range legacy.Exact {
		if archiveKey == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO archive_cache (archive_key, password, source, updated_at)
			VALUES (?, ?, 'legacy_learned_yaml', ?)
			ON CONFLICT(archive_key) DO UPDATE SET
				password = excluded.password,
				source = excluded.source,
				updated_at = excluded.updated_at
		`, archiveKey, password, now); err != nil {
			return fmt.Errorf("migrate exact cache %q: %w", archiveKey, err)
		}
	}

	for person, statsByPassword := range legacy.PersonStats {
		support := len(legacy.PersonFilenames[person])
		for password, stats := range statsByPassword {
			if password == "" || stats == nil {
				continue
			}
			confidence := 0.0
			if stats.Alpha+stats.Beta > 0 {
				confidence = stats.Alpha / (stats.Alpha + stats.Beta)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO pattern_rule (pattern_type, pattern_key, password, alpha, beta, support, confidence, source, updated_at)
				VALUES ('legacy_person', ?, ?, ?, ?, ?, ?, 'learned_yaml_person_stats', ?)
				ON CONFLICT(pattern_type, pattern_key, password) DO UPDATE SET
					alpha = excluded.alpha,
					beta = excluded.beta,
					support = excluded.support,
					confidence = excluded.confidence,
					source = excluded.source,
					updated_at = excluded.updated_at
			`, person, password, stats.Alpha, stats.Beta, support, confidence, now); err != nil {
				return fmt.Errorf("migrate person stat %q/%q: %w", person, password, err)
			}
		}
	}

	for password, count := range legacy.PasswordHitCount {
		if password == "" || count <= 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO password_dict (password, total_uses, source, updated_at)
			VALUES (?, ?, 'legacy_hit_count', ?)
			ON CONFLICT(password) DO UPDATE SET
				total_uses = excluded.total_uses,
				source = excluded.source,
				updated_at = excluded.updated_at
		`, password, count, now); err != nil {
			return fmt.Errorf("migrate password hit count %q: %w", password, err)
		}
	}

	if legacy.Preferences.DeleteAfterExtract || legacy.Preferences.DeletePreferenceSet {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO preferences (id, delete_after_extract, delete_preference_set, updated_at)
			VALUES (1, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				delete_after_extract = excluded.delete_after_extract,
				delete_preference_set = excluded.delete_preference_set,
				updated_at = excluded.updated_at
		`, boolInt(legacy.Preferences.DeleteAfterExtract), boolInt(legacy.Preferences.DeletePreferenceSet), now); err != nil {
			return fmt.Errorf("migrate preferences: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO schema_migration (name, version, applied_at)
		VALUES ('learned_yaml', 1, ?)
		ON CONFLICT(name) DO UPDATE SET
			version = excluded.version,
			applied_at = excluded.applied_at
	`, now); err != nil {
		return fmt.Errorf("record learned migration: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit learned migration: %w", err)
	}
	return nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
