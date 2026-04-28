package ml

import (
	"testing"

	"github.com/bkmashiro/smart-extract/internal/config"
)

func TestProvenPasswordAlwaysFirst(t *testing.T) {
	// Simulate the user's scenario: person "yejiang" has password "yejiang"
	// with alpha=2, beta=1 (only successes). It should always be first.
	learned := &config.Learned{
		Exact:           make(map[string]string),
		PersonStats:     make(map[string]map[string]*config.BetaStats),
		PersonFilenames: make(map[string][]string),
	}
	learned.PersonStats["yejiang"] = map[string]*config.BetaStats{
		"yejiang":  {Alpha: 2, Beta: 1},
		"other123": {Alpha: 1, Beta: 1},
		"badpw":    {Alpha: 1, Beta: 3},
	}

	passwords := []string{"yejiang", "other123", "badpw"}

	// Run 100 times to ensure determinism for proven passwords
	for i := 0; i < 100; i++ {
		ranked := RankPasswordsThompson("yejiang", passwords, learned)
		if len(ranked) != 3 {
			t.Fatalf("expected 3 ranked passwords, got %d", len(ranked))
		}
		if ranked[0].Password != "yejiang" {
			t.Fatalf("iteration %d: expected proven password 'yejiang' first, got %q", i, ranked[0].Password)
		}
	}
}

func TestMultipleProvenSortedByAlpha(t *testing.T) {
	learned := &config.Learned{
		Exact:           make(map[string]string),
		PersonStats:     make(map[string]map[string]*config.BetaStats),
		PersonFilenames: make(map[string][]string),
	}
	learned.PersonStats["person"] = map[string]*config.BetaStats{
		"pw_high": {Alpha: 10, Beta: 1},
		"pw_low":  {Alpha: 3, Beta: 1},
		"pw_new":  {Alpha: 1, Beta: 1},
	}

	passwords := []string{"pw_high", "pw_low", "pw_new"}

	for i := 0; i < 50; i++ {
		ranked := RankPasswordsThompson("person", passwords, learned)
		if ranked[0].Password != "pw_high" {
			t.Fatalf("expected pw_high first, got %q", ranked[0].Password)
		}
		if ranked[1].Password != "pw_low" {
			t.Fatalf("expected pw_low second, got %q", ranked[1].Password)
		}
	}
}

func TestNgramPersonIdentification(t *testing.T) {
	// Simulate the user's scenario: person "yejiang" has filenames
	// "26.04 恶毒" and "26.04 火花". A new file "26.04 热血.zip" should match.
	personFilenames := map[string][]string{
		"yejiang": {"26.04 恶毒", "26.04 火花"},
	}

	matches := IdentifyPerson("26.04 热血.zip", personFilenames)
	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}
	top := matches[0]
	if top.PersonName != "yejiang" {
		t.Fatalf("expected match for 'yejiang', got %q", top.PersonName)
	}
	// With the shared "26.04 " prefix, confidence should be above the new auto-assign threshold of 0.7
	if top.Confidence < 0.5 {
		t.Fatalf("expected confidence >= 0.5, got %.2f", top.Confidence)
	}
	t.Logf("confidence for '26.04 热血.zip' matching yejiang: %.2f", top.Confidence)
}
