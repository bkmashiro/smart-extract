package cmd

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/bkmashiro/smart-extract/internal/config"
	"github.com/bkmashiro/smart-extract/internal/store"
)

type fakeCandidateSource struct {
	exact    map[string]string
	sessions map[string][]string
}

func (f fakeCandidateSource) LookupExact(ctx context.Context, archiveKey string) (string, bool, error) {
	password, ok := f.exact[archiveKey]
	return password, ok, nil
}

func (f fakeCandidateSource) SessionPasswords(ctx context.Context, parentDir string, limit int) ([]string, error) {
	passwords := append([]string(nil), f.sessions[parentDir]...)
	if limit > 0 && len(passwords) > limit {
		passwords = passwords[:limit]
	}
	return passwords, nil
}

func (fakeCandidateSource) PatternRules(ctx context.Context, patternType, patternKey string) ([]store.PatternRule, error) {
	return nil, nil
}

func (fakeCandidateSource) TopPasswords(ctx context.Context, limit int) ([]store.PasswordStat, error) {
	return nil, nil
}

func TestPasswordProviderUsesLearningCandidateSourceBeforeLegacyFallbacks(t *testing.T) {
	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider("/downloads/password=filename-pass.zip", "password=filename-pass.zip", cfg, learned)
	provider.candidateSource = fakeCandidateSource{
		exact:    map[string]string{"password=filename-pass.zip": "exact-pass"},
		sessions: map[string][]string{"/downloads": {"session-pass"}},
	}

	got, err := provider.getPasswords("/downloads/password=filename-pass.zip")
	if err != nil {
		t.Fatalf("getPasswords: %v", err)
	}
	want := []string{"exact-pass", "filename-pass", "session-pass", "", "fallback-pass"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("password candidates = %#v, want %#v", got, want)
	}
}

func TestPasswordProviderKeepsLegacyPersonPasswordsWhenLearningSourceEnabled(t *testing.T) {
	cfg := &config.Config{
		People: map[string]*config.Person{
			"alice":  {Passwords: []string{"person-pass"}},
			"common": {MatchMode: "always_try", Priority: 1, Passwords: []string{"common-pass"}},
		},
		FallbackPasswords: []string{"global-fallback"},
	}
	learned := &config.Learned{
		Exact: map[string]string{},
		PersonStats: map[string]map[string]*config.BetaStats{
			"alice": {"learned-person-pass": {Alpha: 4, Beta: 1}},
		},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider("/downloads/plain.zip", "plain.zip", cfg, learned)
	provider.candidateSource = fakeCandidateSource{}
	provider.resolvedPerson = "alice"

	got, err := provider.getPasswords("/downloads/plain.zip")
	if err != nil {
		t.Fatalf("getPasswords: %v", err)
	}
	for _, password := range []string{"person-pass", "learned-person-pass", "common-pass", "global-fallback"} {
		if !containsString(got, password) {
			t.Fatalf("password candidates missing %q: %#v", password, got)
		}
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func TestOpenLearningStoreMigratesLegacyExactCache(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	legacy := &config.Learned{
		Exact:           map[string]string{"legacy.zip": "legacy-pass"},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}

	st, err := openLearningStore(legacy)
	if err != nil {
		t.Fatalf("openLearningStore: %v", err)
	}
	defer st.Close()

	if gotPath := config.LearningStorePath(); gotPath != filepath.Join(dir, "learning.db") {
		t.Fatalf("learning store path = %q", gotPath)
	}
	password, ok, err := st.LookupExact(context.Background(), "legacy.zip")
	if err != nil {
		t.Fatalf("LookupExact: %v", err)
	}
	if !ok || password != "legacy-pass" {
		t.Fatalf("LookupExact = (%q, %v), want legacy-pass,true", password, ok)
	}
}

func TestRecordLearningSuccessSavesExactAndRawObservation(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	st, err := openLearningStore(&config.Learned{})
	if err != nil {
		t.Fatalf("openLearningStore: %v", err)
	}
	defer st.Close()

	archivePath := filepath.Join(dir, "packs", "new.zip")
	if err := recordLearningSuccess(st, archivePath, "learned-pass", "candidate"); err != nil {
		t.Fatalf("recordLearningSuccess: %v", err)
	}

	password, ok, err := st.LookupExact(context.Background(), "new.zip")
	if err != nil {
		t.Fatalf("LookupExact: %v", err)
	}
	if !ok || password != "learned-pass" {
		t.Fatalf("LookupExact = (%q, %v), want learned-pass,true", password, ok)
	}
	sessionPasswords, err := st.SessionPasswords(context.Background(), filepath.Join(dir, "packs"), 1)
	if err != nil {
		t.Fatalf("SessionPasswords: %v", err)
	}
	if !reflect.DeepEqual(sessionPasswords, []string{"learned-pass"}) {
		t.Fatalf("SessionPasswords = %#v", sessionPasswords)
	}
}
