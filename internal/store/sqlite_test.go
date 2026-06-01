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

func TestSQLiteStoreObservationUpdatesPasswordDictionary(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	defer st.Close()

	for _, obs := range []PasswordObservation{
		{ArchiveName: "a.zip", ParentDir: `/downloads`, Password: "shared-pass", Source: "test"},
		{ArchiveName: "b.zip", ParentDir: `/downloads`, Password: "shared-pass", Source: "test"},
		{ArchiveName: "c.zip", ParentDir: `/downloads`, Password: "rare-pass", Source: "test"},
	} {
		if _, err := st.AddObservation(ctx, obs); err != nil {
			t.Fatalf("AddObservation: %v", err)
		}
	}

	stats, err := st.TopPasswords(ctx, 2)
	if err != nil {
		t.Fatalf("TopPasswords: %v", err)
	}
	if len(stats) != 2 {
		t.Fatalf("len(TopPasswords) = %d, want 2: %#v", len(stats), stats)
	}
	if stats[0].Password != "shared-pass" || stats[0].TotalUses != 2 {
		t.Fatalf("top password = %+v, want shared-pass with 2 uses", stats[0])
	}
	if stats[1].Password != "rare-pass" || stats[1].TotalUses != 1 {
		t.Fatalf("second password = %+v, want rare-pass with 1 use", stats[1])
	}
}

func TestSQLiteStoreReturnsRecentSessionPasswordsByParentDir(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	defer st.Close()

	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	observations := []PasswordObservation{
		{ArchiveName: "old.zip", ParentDir: `/downloads`, Password: "old-pass", Source: "test", SuccessAt: base},
		{ArchiveName: "new.zip", ParentDir: `/downloads`, Password: "new-pass", Source: "test", SuccessAt: base.Add(time.Minute)},
		{ArchiveName: "dup.zip", ParentDir: `/downloads`, Password: "new-pass", Source: "test", SuccessAt: base.Add(2 * time.Minute)},
		{ArchiveName: "other.zip", ParentDir: `/other`, Password: "other-pass", Source: "test", SuccessAt: base.Add(3 * time.Minute)},
	}
	for _, obs := range observations {
		if _, err := st.AddObservation(ctx, obs); err != nil {
			t.Fatalf("AddObservation: %v", err)
		}
	}

	got, err := st.SessionPasswords(ctx, `/downloads`, 2)
	if err != nil {
		t.Fatalf("SessionPasswords: %v", err)
	}
	want := []string{"new-pass", "old-pass"}
	if len(got) != len(want) {
		t.Fatalf("len(SessionPasswords) = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SessionPasswords[%d] = %q, want %q; all=%#v", i, got[i], want[i], got)
		}
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

func TestSQLiteStoreLookupExactCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	defer st.Close()

	if err := st.SaveExact(ctx, ExactCacheEntry{ArchiveKey: "Movie.ZIP", Password: "pw-mixed", Source: "test"}); err != nil {
		t.Fatalf("SaveExact: %v", err)
	}

	password, ok, err := st.LookupExact(ctx, "movie.zip")
	if err != nil {
		t.Fatalf("LookupExact: %v", err)
	}
	if !ok {
		t.Fatalf("LookupExact did not find case-insensitive match")
	}
	if password != "pw-mixed" {
		t.Fatalf("password = %q, want %q", password, "pw-mixed")
	}
}

func TestSQLiteStoreLookupExactPrefersExactCase(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	defer st.Close()

	if err := st.SaveExact(ctx, ExactCacheEntry{ArchiveKey: "Movie.ZIP", Password: "pw-mixed", Source: "test"}); err != nil {
		t.Fatalf("SaveExact mixed: %v", err)
	}
	if err := st.SaveExact(ctx, ExactCacheEntry{ArchiveKey: "movie.zip", Password: "pw-lower", Source: "test"}); err != nil {
		t.Fatalf("SaveExact lower: %v", err)
	}

	password, ok, err := st.LookupExact(ctx, "movie.zip")
	if err != nil {
		t.Fatalf("LookupExact: %v", err)
	}
	if !ok {
		t.Fatalf("LookupExact did not find entry")
	}
	if password != "pw-lower" {
		t.Fatalf("password = %q, want exact-case %q", password, "pw-lower")
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
