package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/bkmashiro/smart-extract/internal/config"
)

func TestSQLiteStoreExactCacheRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	defer st.Close()

	if err := st.SaveExact(ctx, ExactCacheEntry{ArchiveKey: "secret.zip", Password: "pw1", Source: "test"}); err != nil {
		t.Fatalf("SaveExact: %v", err)
	}
	if err := st.SaveExact(ctx, ExactCacheEntry{ArchiveKey: "secret.zip", Password: "pw2", Source: "test-update"}); err != nil {
		t.Fatalf("SaveExact update: %v", err)
	}

	password, ok, err := st.LookupExact(ctx, "secret.zip")
	if err != nil {
		t.Fatalf("LookupExact: %v", err)
	}
	if !ok {
		t.Fatalf("LookupExact did not find saved entry")
	}
	if password != "pw2" {
		t.Fatalf("password = %q, want %q", password, "pw2")
	}

	_, ok, err = st.LookupExact(ctx, "missing.zip")
	if err != nil {
		t.Fatalf("LookupExact missing: %v", err)
	}
	if ok {
		t.Fatalf("LookupExact found missing entry")
	}
}

func TestSQLiteStoreAppendsRawObservations(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	defer st.Close()

	at := time.Date(2026, 6, 1, 12, 30, 0, 0, time.UTC)
	id, err := st.AddObservation(ctx, PasswordObservation{
		ArchivePath:   `/downloads/[DLsite] RJ123456.zip`,
		ArchiveName:   `[DLsite] RJ123456.zip`,
		ParentDir:     `/downloads`,
		Password:      "shared-pass",
		Source:        "user_input",
		ArchiveSize:   123456,
		RootSessionID: "session-1",
		ParentArchive: "root.zip",
		Depth:         1,
		SuccessAt:     at,
	})
	if err != nil {
		t.Fatalf("AddObservation: %v", err)
	}
	if id == 0 {
		t.Fatalf("AddObservation returned zero id")
	}

	observations, err := st.ListObservations(ctx)
	if err != nil {
		t.Fatalf("ListObservations: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	got := observations[0]
	if got.ArchiveName != `[DLsite] RJ123456.zip` || got.Password != "shared-pass" || got.Depth != 1 {
		t.Fatalf("unexpected observation: %+v", got)
	}
	if !got.SuccessAt.Equal(at) {
		t.Fatalf("SuccessAt = %s, want %s", got.SuccessAt, at)
	}
}

func TestMigrateLearnedImportsLegacyYAMLData(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	defer st.Close()

	legacy := &config.Learned{
		Exact: map[string]string{
			"old.zip": "old-pass",
		},
		PersonStats: map[string]map[string]*config.BetaStats{
			"alice": {
				"alice-pass": {Alpha: 5, Beta: 2},
			},
		},
		PersonFilenames: map[string][]string{
			"alice": {"alice_001.zip", "alice_002.zip"},
		},
		PasswordHitCount: map[string]int{
			"popular-pass": 7,
		},
		Preferences: config.Preferences{DeleteAfterExtract: true, DeletePreferenceSet: true},
	}

	if err := st.MigrateLearned(ctx, legacy); err != nil {
		t.Fatalf("MigrateLearned: %v", err)
	}
	// Migration is idempotent.
	if err := st.MigrateLearned(ctx, legacy); err != nil {
		t.Fatalf("MigrateLearned second run: %v", err)
	}

	password, ok, err := st.LookupExact(ctx, "old.zip")
	if err != nil {
		t.Fatalf("LookupExact after migration: %v", err)
	}
	if !ok || password != "old-pass" {
		t.Fatalf("migrated exact = (%q, %v), want old-pass,true", password, ok)
	}

	rules, err := st.PatternRules(ctx, "legacy_person", "alice")
	if err != nil {
		t.Fatalf("PatternRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1", len(rules))
	}
	if rules[0].Password != "alice-pass" || rules[0].Alpha != 5 || rules[0].Beta != 2 || rules[0].Support != 2 {
		t.Fatalf("unexpected legacy pattern rule: %+v", rules[0])
	}

	top, err := st.TopPasswords(ctx, 1)
	if err != nil {
		t.Fatalf("TopPasswords: %v", err)
	}
	if len(top) != 1 || top[0].Password != "popular-pass" || top[0].TotalUses != 7 {
		t.Fatalf("unexpected password_dict rows: %+v", top)
	}

	prefs, err := st.GetPreferences(ctx)
	if err != nil {
		t.Fatalf("GetPreferences: %v", err)
	}
	if !prefs.DeleteAfterExtract || !prefs.DeletePreferenceSet {
		t.Fatalf("preferences not migrated: %+v", prefs)
	}

	version, err := st.MigrationVersion(ctx, "learned_yaml")
	if err != nil {
		t.Fatalf("MigrationVersion: %v", err)
	}
	if version != 1 {
		t.Fatalf("migration version = %d, want 1", version)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "smart-extract.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	return st
}
