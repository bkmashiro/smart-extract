package budget

import (
	"runtime"
	"testing"
)

const (
	mib = int64(1024 * 1024)
	gib = 1024 * mib
)

func TestParseProfile(t *testing.T) {
	cases := []struct {
		in   string
		want Profile
	}{
		{"light", ProfileLight},
		{"LIGHT", ProfileLight},
		{"  normal  ", ProfileNormal},
		{"aggressive", ProfileAggressive},
		{"", ProfileNormal},
		{"bogus", ProfileNormal},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := ParseProfile(tc.in); got != tc.want {
				t.Fatalf("ParseProfile(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestRecommendDefaultsAreNormalAndExpensive(t *testing.T) {
	// Empty Inputs: unknown format is expensive, profile defaults to normal.
	got := Recommend(Inputs{})
	if got.MaxParallelProbes != 1 {
		t.Fatalf("expensive format must serialize probes, got %d", got.MaxParallelProbes)
	}
	if got.CandidateLimit <= 0 {
		t.Fatalf("CandidateLimit must be positive, got %d", got.CandidateLimit)
	}
	// Normal profile, expensive baseline.
	want := Recommend(Inputs{Format: "unknown", Profile: ProfileNormal})
	if got.CandidateLimit != want.CandidateLimit {
		t.Fatalf("zero Inputs should equal explicit normal+unknown: got %d, want %d", got.CandidateLimit, want.CandidateLimit)
	}
}

func TestRecommendCheapVsExpensiveLimits(t *testing.T) {
	cheap := Recommend(Inputs{Format: "zip", Profile: ProfileNormal})
	expensive := Recommend(Inputs{Format: "7z-solid", Profile: ProfileNormal})
	if cheap.CandidateLimit <= expensive.CandidateLimit {
		t.Fatalf("cheap (%d) must exceed expensive (%d) candidate limits", cheap.CandidateLimit, expensive.CandidateLimit)
	}
	if cheap.MaxParallelProbes < 2 {
		t.Fatalf("cheap formats should permit parallel probes, got %d", cheap.MaxParallelProbes)
	}
	if expensive.MaxParallelProbes != 1 {
		t.Fatalf("expensive formats must run serially, got %d", expensive.MaxParallelProbes)
	}
}

func TestRecommendProfileOrdering(t *testing.T) {
	light := Recommend(Inputs{Format: "zip", Profile: ProfileLight})
	normal := Recommend(Inputs{Format: "zip", Profile: ProfileNormal})
	aggressive := Recommend(Inputs{Format: "zip", Profile: ProfileAggressive})
	if !(light.CandidateLimit < normal.CandidateLimit && normal.CandidateLimit < aggressive.CandidateLimit) {
		t.Fatalf("profile ordering broken: light=%d normal=%d aggressive=%d",
			light.CandidateLimit, normal.CandidateLimit, aggressive.CandidateLimit)
	}
}

func TestRecommendExpensiveLargeArchiveReduces(t *testing.T) {
	small := Recommend(Inputs{Format: "7z-solid", Profile: ProfileNormal, ArchiveSizeBytes: 1 * mib})
	large := Recommend(Inputs{Format: "7z-solid", Profile: ProfileNormal, ArchiveSizeBytes: 800 * mib})
	huge := Recommend(Inputs{Format: "7z-solid", Profile: ProfileNormal, ArchiveSizeBytes: 4 * gib})
	if large.CandidateLimit >= small.CandidateLimit {
		t.Fatalf("large expensive archive should shrink budget: small=%d large=%d", small.CandidateLimit, large.CandidateLimit)
	}
	if huge.CandidateLimit >= large.CandidateLimit {
		t.Fatalf("huge expensive archive should shrink budget further: large=%d huge=%d", large.CandidateLimit, huge.CandidateLimit)
	}
	if huge.CandidateLimit < 1 {
		t.Fatalf("CandidateLimit must remain >=1 even for huge archives, got %d", huge.CandidateLimit)
	}
}

func TestRecommendCheapLargeArchiveUnchanged(t *testing.T) {
	// Cheap probes don't care much about size — header only.
	small := Recommend(Inputs{Format: "zip", Profile: ProfileNormal, ArchiveSizeBytes: 1 * mib})
	large := Recommend(Inputs{Format: "zip", Profile: ProfileNormal, ArchiveSizeBytes: 8 * gib})
	if small.CandidateLimit != large.CandidateLimit {
		t.Fatalf("cheap candidate limit should be size-independent: small=%d large=%d",
			small.CandidateLimit, large.CandidateLimit)
	}
}

func TestRecommendMaxParallelProbesInteraction(t *testing.T) {
	cases := []struct {
		name              string
		cpuCount          int
		maxParallelProbes int
		wantParallel      int
	}{
		{"unset_uses_default_capped_by_cpu", 8, 0, 4},
		{"unset_low_cpu", 2, 0, 2},
		{"explicit_below_cpu", 8, 3, 3},
		{"explicit_above_cpu_caps_at_cpu", 4, 16, 4},
		{"explicit_above_hard_cap", 32, 64, 8},
		{"negative_treated_as_unset", 8, -5, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Recommend(Inputs{
				Format:            "zip",
				Profile:           ProfileNormal,
				CPUCount:          tc.cpuCount,
				MaxParallelProbes: tc.maxParallelProbes,
			})
			if got.MaxParallelProbes != tc.wantParallel {
				t.Fatalf("MaxParallelProbes = %d, want %d", got.MaxParallelProbes, tc.wantParallel)
			}
		})
	}
}

func TestRecommendCPUCountFallsBackToRuntime(t *testing.T) {
	got := Recommend(Inputs{Format: "zip", Profile: ProfileNormal, CPUCount: 0, MaxParallelProbes: 0})
	expected := runtime.NumCPU()
	if expected > 4 {
		expected = 4
	}
	if expected > 8 {
		expected = 8
	}
	if expected < 1 {
		expected = 1
	}
	if got.MaxParallelProbes != expected {
		t.Fatalf("CPUCount=0 should fall back to runtime.NumCPU; got %d, want %d", got.MaxParallelProbes, expected)
	}
}

func TestRecommendExpensiveIgnoresMaxParallel(t *testing.T) {
	got := Recommend(Inputs{
		Format:            "tar-compressed",
		Profile:           ProfileAggressive,
		CPUCount:          16,
		MaxParallelProbes: 16,
	})
	if got.MaxParallelProbes != 1 {
		t.Fatalf("expensive must serialize regardless of CPU/MaxParallelProbes; got %d", got.MaxParallelProbes)
	}
}

func TestRecommendNegativeSizeTreatedAsZero(t *testing.T) {
	zero := Recommend(Inputs{Format: "7z-solid", Profile: ProfileNormal, ArchiveSizeBytes: 0})
	neg := Recommend(Inputs{Format: "7z-solid", Profile: ProfileNormal, ArchiveSizeBytes: -42})
	if zero != neg {
		t.Fatalf("negative size should match zero size: zero=%+v neg=%+v", zero, neg)
	}
}

func TestRecommendUnknownFormatTreatedAsExpensive(t *testing.T) {
	unknown := Recommend(Inputs{Format: "frobnicator", Profile: ProfileNormal})
	expensive := Recommend(Inputs{Format: "7z-solid", Profile: ProfileNormal})
	if unknown != expensive {
		t.Fatalf("unknown format should equal expensive baseline; unknown=%+v expensive=%+v", unknown, expensive)
	}
}

func TestRecommendCheapMaxParallelAtLeastOne(t *testing.T) {
	got := Recommend(Inputs{Format: "zip", Profile: ProfileNormal, CPUCount: 1, MaxParallelProbes: 0})
	if got.MaxParallelProbes < 1 {
		t.Fatalf("MaxParallelProbes must be >= 1, got %d", got.MaxParallelProbes)
	}
}

func TestRecommendIsCheapFormat(t *testing.T) {
	cheap := []string{"zip", "rar", "7z", "ZIP", "Rar"}
	expensive := []string{"7z-solid", "tar-compressed", "unknown", "", "frobnicator"}
	for _, f := range cheap {
		if !IsCheapFormat(f) {
			t.Errorf("IsCheapFormat(%q) = false, want true", f)
		}
	}
	for _, f := range expensive {
		if IsCheapFormat(f) {
			t.Errorf("IsCheapFormat(%q) = true, want false", f)
		}
	}
}
