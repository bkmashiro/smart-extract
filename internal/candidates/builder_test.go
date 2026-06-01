package candidates

import (
	"context"
	"testing"

	"github.com/bkmashiro/smart-extract/internal/store"
)

func TestBuildOrdersSourcesAndDeduplicatesPasswords(t *testing.T) {
	source := &fakeSource{
		exact:            map[string]string{"[site] RJ123456 password=inline.zip": "exact-pass"},
		sessionPasswords: []string{"session-pass", "exact-pass"},
		patternRules: []store.PatternRule{
			{Password: "pattern-pass", Confidence: 0.95, Support: 5},
			{Password: "session-pass", Confidence: 0.9, Support: 4},
		},
		topPasswords: []store.PasswordStat{
			{Password: "dict-pass", TotalUses: 10},
			{Password: "pattern-pass", TotalUses: 9},
		},
	}

	got, err := Build(context.Background(), Request{
		ArchivePath:       `/downloads/[site] RJ123456 password=inline.zip`,
		ArchiveKey:        "[site] RJ123456 password=inline.zip",
		ParentPassword:    "parent-pass",
		FallbackPasswords: []string{"fallback-pass", "dict-pass"},
		DictionaryLimit:   10,
	}, source)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	want := []Candidate{
		{Password: "parent-pass", Source: SourceParent},
		{Password: "exact-pass", Source: SourceExact},
		{Password: "inline", Source: SourceFilename},
		{Password: "session-pass", Source: SourceSession},
		{Password: "pattern-pass", Source: SourcePattern},
		{Password: "dict-pass", Source: SourceDictionary},
		{Password: "", Source: SourceEmpty},
		{Password: "fallback-pass", Source: SourceFallback},
	}
	assertCandidates(t, got, want)
}

func TestBuildAppliesCandidateLimitAfterDeduplication(t *testing.T) {
	source := &fakeSource{
		exact:            map[string]string{"file.zip": "exact-pass"},
		sessionPasswords: []string{"session-pass"},
		topPasswords:     []store.PasswordStat{{Password: "dict-pass", TotalUses: 3}},
	}

	got, err := Build(context.Background(), Request{
		ArchivePath:       `/downloads/file.zip`,
		ArchiveKey:        "file.zip",
		ParentPassword:    "parent-pass",
		FallbackPasswords: []string{"fallback-pass"},
		DictionaryLimit:   10,
		CandidateLimit:    3,
	}, source)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	want := []Candidate{
		{Password: "parent-pass", Source: SourceParent},
		{Password: "exact-pass", Source: SourceExact},
		{Password: "session-pass", Source: SourceSession},
	}
	assertCandidates(t, got, want)
}

func TestBuildUsesShapePatternForNumberedFilenames(t *testing.T) {
	source := &fakeSource{
		patternRulesByKey: map[string][]store.PatternRule{
			"[site] rjnnnnnn voln.zip": {{Password: "shape-pass", Confidence: 0.8, Support: 4}},
		},
	}

	got, err := Build(context.Background(), Request{
		ArchivePath:     `/downloads/[site] RJ123456 vol2.zip`,
		ArchiveKey:      "[site] RJ123456 vol2.zip",
		DictionaryLimit: 10,
	}, source)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	want := []Candidate{
		{Password: "shape-pass", Source: SourcePattern},
		{Password: "", Source: SourceEmpty},
	}
	assertCandidates(t, got, want)
}

func TestBuildUsesStemShapePatternAcrossExtensions(t *testing.T) {
	source := &fakeSource{
		patternRulesByKey: map[string][]store.PatternRule{
			"rjnnnnnn": {{Password: "stem-pass", Confidence: 0.7, Support: 3}},
		},
	}

	got, err := Build(context.Background(), Request{
		ArchivePath:     `/downloads/RJ999999.7z`,
		ArchiveKey:      "RJ999999.7z",
		DictionaryLimit: 10,
	}, source)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	want := []Candidate{
		{Password: "stem-pass", Source: SourcePattern},
		{Password: "", Source: SourceEmpty},
	}
	assertCandidates(t, got, want)
}

func TestBuildPrefersFullShapeBeforeStemShape(t *testing.T) {
	source := &fakeSource{
		patternRulesByKey: map[string][]store.PatternRule{
			"rjnnnnnn.7z": {{Password: "full-shape-pass", Confidence: 0.9, Support: 5}},
			"rjnnnnnn":    {{Password: "stem-pass", Confidence: 0.7, Support: 3}},
		},
	}

	got, err := Build(context.Background(), Request{
		ArchivePath:     `/downloads/RJ999999.7z`,
		ArchiveKey:      "RJ999999.7z",
		DictionaryLimit: 10,
	}, source)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	want := []Candidate{
		{Password: "full-shape-pass", Source: SourcePattern},
		{Password: "stem-pass", Source: SourcePattern},
		{Password: "", Source: SourceEmpty},
	}
	assertCandidates(t, got, want)
}

func TestBuildSkipsStemShapeQueryForNonGeneralizableStem(t *testing.T) {
	source := &fakeSource{
		patternRulesByKey: map[string][]store.PatternRule{
			"release": {{Password: "should-not-appear", Confidence: 0.9, Support: 5}},
		},
	}

	got, err := Build(context.Background(), Request{
		ArchivePath:     `/downloads/release.zip`,
		ArchiveKey:      "release.zip",
		DictionaryLimit: 10,
	}, source)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	for _, candidate := range got {
		if candidate.Password == "should-not-appear" {
			t.Fatalf("did not expect non-generalizable stem rule, got %#v", got)
		}
	}
}

func assertCandidates(t *testing.T, got, want []Candidate) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("len(candidates) = %d, want %d\ngot: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Password != want[i].Password || got[i].Source != want[i].Source {
			t.Fatalf("candidate[%d] = (%q,%q), want (%q,%q)\nall: %#v", i, got[i].Password, got[i].Source, want[i].Password, want[i].Source, got)
		}
	}
}

type fakeSource struct {
	exact             map[string]string
	sessionPasswords  []string
	patternRules      []store.PatternRule
	patternRulesByKey map[string][]store.PatternRule
	topPasswords      []store.PasswordStat
}

func (f *fakeSource) LookupExact(_ context.Context, archiveKey string) (string, bool, error) {
	if f.exact == nil {
		return "", false, nil
	}
	password, ok := f.exact[archiveKey]
	return password, ok, nil
}

func (f *fakeSource) SessionPasswords(_ context.Context, _ string, _ int) ([]string, error) {
	return f.sessionPasswords, nil
}

func (f *fakeSource) PatternRules(_ context.Context, patternType, patternKey string) ([]store.PatternRule, error) {
	if f.patternRulesByKey != nil {
		return f.patternRulesByKey[patternKey], nil
	}
	return f.patternRules, nil
}

func (f *fakeSource) TopPasswords(_ context.Context, limit int) ([]store.PasswordStat, error) {
	if limit <= 0 || limit >= len(f.topPasswords) {
		return f.topPasswords, nil
	}
	return f.topPasswords[:limit], nil
}
