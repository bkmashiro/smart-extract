package learning

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/bkmashiro/smart-extract/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "smart-extract.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestSummarizeShapePatternsRequiresMinSupport(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	if _, err := st.AddObservation(ctx, store.PasswordObservation{
		ArchiveName: "RJ123456.zip",
		ParentDir:   "/downloads",
		Password:    "shared-pass",
		Source:      "test",
	}); err != nil {
		t.Fatalf("AddObservation: %v", err)
	}

	if err := SummarizeShapePatterns(ctx, st, 2); err != nil {
		t.Fatalf("SummarizeShapePatterns: %v", err)
	}

	rules, err := st.PatternRules(ctx, "shape", "rjnnnnnn.zip")
	if err != nil {
		t.Fatalf("PatternRules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected no shape rules with single observation, got %+v", rules)
	}
}

func TestSummarizeShapePatternsDerivesRuleFromTwoMatchingObservations(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	for _, name := range []string{"RJ123456.zip", "RJ654321.zip"} {
		if _, err := st.AddObservation(ctx, store.PasswordObservation{
			ArchiveName: name,
			ParentDir:   "/downloads",
			Password:    "shared-pass",
			Source:      "test",
		}); err != nil {
			t.Fatalf("AddObservation %s: %v", name, err)
		}
	}

	if err := SummarizeShapePatterns(ctx, st, 2); err != nil {
		t.Fatalf("SummarizeShapePatterns: %v", err)
	}

	rules, err := st.PatternRules(ctx, "shape", "rjnnnnnn.zip")
	if err != nil {
		t.Fatalf("PatternRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1; rules=%+v", len(rules), rules)
	}
	r := rules[0]
	if r.Password != "shared-pass" {
		t.Fatalf("rule.Password = %q, want %q", r.Password, "shared-pass")
	}
	if r.Support != 2 {
		t.Fatalf("rule.Support = %d, want 2", r.Support)
	}
	if r.Alpha != 3 || r.Beta != 1 {
		t.Fatalf("rule.Alpha/Beta = %v/%v, want 3/1", r.Alpha, r.Beta)
	}
	wantConfidence := 2.0 / 3.0
	if r.Confidence < wantConfidence-1e-9 || r.Confidence > wantConfidence+1e-9 {
		t.Fatalf("rule.Confidence = %v, want %v", r.Confidence, wantConfidence)
	}
	if r.Source != "local_summary" {
		t.Fatalf("rule.Source = %q, want local_summary", r.Source)
	}
}

func TestSummarizeShapePatternsIgnoresDuplicateArchiveNames(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	for i := 0; i < 2; i++ {
		if _, err := st.AddObservation(ctx, store.PasswordObservation{
			ArchiveName: "RJ123456.zip",
			Password:    "shared-pass",
			Source:      "test",
		}); err != nil {
			t.Fatalf("AddObservation: %v", err)
		}
	}

	if err := SummarizeShapePatterns(ctx, st, 2); err != nil {
		t.Fatalf("SummarizeShapePatterns: %v", err)
	}

	rules, err := st.PatternRules(ctx, "shape", "rjnnnnnn.zip")
	if err != nil {
		t.Fatalf("PatternRules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected duplicate archive observations not to create rule, got %+v", rules)
	}
}

func TestSummarizeShapePatternsIgnoresNonGeneralizableShapes(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	for _, name := range []string{"release.zip", "RELEASE.zip"} {
		if _, err := st.AddObservation(ctx, store.PasswordObservation{
			ArchiveName: name,
			Password:    "shared-pass",
			Source:      "test",
		}); err != nil {
			t.Fatalf("AddObservation: %v", err)
		}
	}

	if err := SummarizeShapePatterns(ctx, st, 0); err != nil {
		t.Fatalf("SummarizeShapePatterns: %v", err)
	}

	rules, err := st.PatternRules(ctx, "shape", "release.zip")
	if err != nil {
		t.Fatalf("PatternRules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected no rule for shape without numeric placeholder, got %+v", rules)
	}
}

func TestSummarizeShapePatternsIgnoresEmptyFields(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	observations := []store.PasswordObservation{
		{ArchiveName: "", Password: "p", Source: "test"},
		{ArchiveName: "a.zip", Password: "", Source: "test"},
	}
	for _, obs := range observations {
		if _, err := st.AddObservation(ctx, obs); err != nil {
			t.Fatalf("AddObservation: %v", err)
		}
	}

	if err := SummarizeShapePatterns(ctx, st, 0); err != nil {
		t.Fatalf("SummarizeShapePatterns: %v", err)
	}

	rules, err := st.PatternRules(ctx, "shape", "a.zip")
	if err != nil {
		t.Fatalf("PatternRules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected no rules from empty-field obs, got %+v", rules)
	}
}

func TestSummarizeShapePatternsDefaultMinSupportIsTwo(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	for _, name := range []string{"abc12.zip", "abc34.zip"} {
		if _, err := st.AddObservation(ctx, store.PasswordObservation{
			ArchiveName: name,
			Password:    "p",
			Source:      "test",
		}); err != nil {
			t.Fatalf("AddObservation: %v", err)
		}
	}

	if err := SummarizeShapePatterns(ctx, st, 0); err != nil {
		t.Fatalf("SummarizeShapePatterns: %v", err)
	}

	rules, err := st.PatternRules(ctx, "shape", "abcnn.zip")
	if err != nil {
		t.Fatalf("PatternRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1; rules=%+v", len(rules), rules)
	}
}
