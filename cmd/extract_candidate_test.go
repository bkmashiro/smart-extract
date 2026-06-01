package cmd

import (
	"context"
	"fmt"
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

func TestPasswordProviderPrioritizesParentPasswordForNestedArchive(t *testing.T) {
	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider("/downloads/nested.zip", "nested.zip", cfg, learned)
	provider.candidateSource = fakeCandidateSource{
		exact: map[string]string{"nested.zip": "exact-pass"},
	}
	provider.parentPassword = "parent-pass"

	got, err := provider.getPasswords("/downloads/nested.zip")
	if err != nil {
		t.Fatalf("getPasswords: %v", err)
	}
	wantPrefix := []string{"parent-pass", "exact-pass"}
	if len(got) < len(wantPrefix) || !reflect.DeepEqual(got[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("password candidates = %#v, want prefix %#v", got, wantPrefix)
	}
}

func makePasswordList(prefix string, n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%s-%03d", prefix, i))
	}
	return out
}

func TestPasswordProviderLightProfileCapsCandidateList(t *testing.T) {
	cfg := &config.Config{
		People: map[string]*config.Person{
			"common": {
				MatchMode: "always_try",
				Priority:  1,
				Passwords: makePasswordList("p", 30),
			},
		},
		FallbackPasswords:  makePasswordList("fb", 10),
		ProbeBudgetProfile: "light",
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider("/tmp/some.zip", "some.zip", cfg, learned)
	provider.candidateSource = fakeCandidateSource{}

	got, err := provider.getPasswords("/tmp/some.zip")
	if err != nil {
		t.Fatalf("getPasswords: %v", err)
	}
	if len(got) == 0 {
		t.Fatalf("expected some candidates, got 0")
	}
	if len(got) > 20 {
		t.Fatalf("light profile cheap-zip cap should be <=20 candidates, got %d", len(got))
	}

	cfgAgg := *cfg
	cfgAgg.ProbeBudgetProfile = "aggressive"
	providerAgg := newPasswordProvider("/tmp/some.zip", "some.zip", &cfgAgg, learned)
	providerAgg.candidateSource = fakeCandidateSource{}
	aggressive, err := providerAgg.getPasswords("/tmp/some.zip")
	if err != nil {
		t.Fatalf("getPasswords(aggressive): %v", err)
	}
	if len(aggressive) <= len(got) {
		t.Fatalf("aggressive (%d) should yield more candidates than light (%d)", len(aggressive), len(got))
	}
}

func TestPasswordProviderEmptyProfilePreservesLegacyCandidateList(t *testing.T) {
	// With no profile configured, the candidate list should not be truncated
	// for a small set — i.e. backwards compatibility.
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

func TestRecordLearningSuccessDerivesShapePatternsAfterRepeatedSuccess(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	st, err := openLearningStore(&config.Learned{})
	if err != nil {
		t.Fatalf("openLearningStore: %v", err)
	}
	defer st.Close()

	for _, name := range []string{"RJ123456.zip", "RJ654321.zip"} {
		archivePath := filepath.Join(dir, name)
		if err := recordLearningSuccess(st, archivePath, "shape-derived-pass", "auto_candidate"); err != nil {
			t.Fatalf("recordLearningSuccess(%s): %v", name, err)
		}
	}

	rules, err := st.PatternRules(context.Background(), "shape", "rjnnnnnn.zip")
	if err != nil {
		t.Fatalf("PatternRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1; rules=%+v", len(rules), rules)
	}
	if rules[0].Password != "shape-derived-pass" || rules[0].Support != 2 {
		t.Fatalf("unexpected rule: %+v", rules[0])
	}

	thirdPath := filepath.Join(dir, "RJ999999.zip")
	provider := newPasswordProvider(thirdPath, "RJ999999.zip", &config.Config{
		People: map[string]*config.Person{},
	}, &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	})
	provider.candidateSource = st
	got, err := provider.getPasswords(thirdPath)
	if err != nil {
		t.Fatalf("getPasswords: %v", err)
	}
	if !containsString(got, "shape-derived-pass") {
		t.Fatalf("expected candidates to contain shape-derived-pass; got %#v", got)
	}
}

func TestRecordLearningSuccessDerivesStemShapeAcrossArchiveExtensions(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	st, err := openLearningStore(&config.Learned{})
	if err != nil {
		t.Fatalf("openLearningStore: %v", err)
	}
	defer st.Close()

	for _, name := range []string{"RJ123456.zip", "RJ654321.rar"} {
		archivePath := filepath.Join(dir, name)
		if err := recordLearningSuccess(st, archivePath, "stem-derived-pass", "auto_candidate"); err != nil {
			t.Fatalf("recordLearningSuccess(%s): %v", name, err)
		}
	}

	rules, err := st.PatternRules(context.Background(), "stem_shape", "rjnnnnnn")
	if err != nil {
		t.Fatalf("PatternRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("len(stem_shape rules) = %d, want 1; rules=%+v", len(rules), rules)
	}
	if rules[0].Password != "stem-derived-pass" || rules[0].Support != 2 {
		t.Fatalf("unexpected stem_shape rule: %+v", rules[0])
	}

	thirdPath := filepath.Join(dir, "RJ999999.7z")
	provider := newPasswordProvider(thirdPath, "RJ999999.7z", &config.Config{
		People: map[string]*config.Person{},
	}, &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	})
	provider.candidateSource = st
	got, err := provider.getPasswords(thirdPath)
	if err != nil {
		t.Fatalf("getPasswords: %v", err)
	}
	if !containsString(got, "stem-derived-pass") {
		t.Fatalf("expected candidates to contain stem-derived-pass for cross-extension archive; got %#v", got)
	}
}

func TestArchiveSuccessRecorderLearnsTopLevelAndNestedArchives(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	st, err := openLearningStore(&config.Learned{})
	if err != nil {
		t.Fatalf("openLearningStore: %v", err)
	}
	defer st.Close()

	recorder := makeArchiveSuccessRecorder(st, &config.Config{})
	top := filepath.Join(dir, "top.zip")
	nested := filepath.Join(dir, "top", "nested.zip")
	recorder(top, "top-pass")
	recorder(nested, "nested-pass")

	for archiveName, wantPassword := range map[string]string{
		"top.zip":    "top-pass",
		"nested.zip": "nested-pass",
	} {
		password, ok, err := st.LookupExact(context.Background(), archiveName)
		if err != nil {
			t.Fatalf("LookupExact(%s): %v", archiveName, err)
		}
		if !ok || password != wantPassword {
			t.Fatalf("LookupExact(%s) = (%q, %v), want (%q, true)", archiveName, password, ok, wantPassword)
		}
	}
}
