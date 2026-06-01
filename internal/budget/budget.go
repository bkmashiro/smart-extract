// Package budget computes cost-aware password candidate budgets and parallelism
// recommendations from archive format, size, and a user-selected profile.
package budget

import (
	"runtime"
	"strings"
)

// Profile selects how aggressively to spend probe attempts.
type Profile int

const (
	ProfileNormal Profile = iota
	ProfileLight
	ProfileAggressive
)

const (
	// DefaultMaxParallelProbes is used when no explicit limit is configured.
	DefaultMaxParallelProbes = 4
	// HardMaxParallelProbes caps parallelism regardless of CPU count or config.
	HardMaxParallelProbes = 8

	largeArchiveThreshold = 500 * 1024 * 1024
	hugeArchiveThreshold  = 2 * 1024 * 1024 * 1024
)

// Inputs describes the archive and environment context for budget calculation.
type Inputs struct {
	Format            string
	ArchiveSizeBytes  int64
	Profile           Profile
	MaxParallelProbes int
	CPUCount          int
}

// Recommendation is the budget output.
type Recommendation struct {
	CandidateLimit    int
	MaxParallelProbes int
}

// ParseProfile maps a string (e.g. from config or CLI flag) to a Profile.
// Unknown or empty values fall back to ProfileNormal.
func ParseProfile(s string) Profile {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "light":
		return ProfileLight
	case "aggressive":
		return ProfileAggressive
	default:
		return ProfileNormal
	}
}

var cheapFormats = map[string]struct{}{
	"zip": {},
	"rar": {},
	"7z":  {},
}

// IsCheapFormat reports whether the format allows quick header-only probes.
// Formats not listed here (including 7z-solid and tar-compressed) require
// significant decompression per attempt and are treated as expensive.
func IsCheapFormat(format string) bool {
	_, ok := cheapFormats[strings.ToLower(strings.TrimSpace(format))]
	return ok
}

// Recommend computes the candidate budget and parallel-probe recommendation.
func Recommend(in Inputs) Recommendation {
	cheap := IsCheapFormat(in.Format)
	limit := baseLimit(in.Profile, cheap)

	if !cheap {
		size := in.ArchiveSizeBytes
		if size < 0 {
			size = 0
		}
		switch {
		case size > hugeArchiveThreshold:
			limit = limit / 4
			if limit < 1 {
				limit = 1
			}
		case size > largeArchiveThreshold:
			limit = limit / 2
			if limit < 2 {
				limit = 2
			}
		}
	}

	return Recommendation{
		CandidateLimit:    limit,
		MaxParallelProbes: parallelProbes(in, cheap),
	}
}

func baseLimit(p Profile, cheap bool) int {
	switch p {
	case ProfileLight:
		if cheap {
			return 20
		}
		return 8
	case ProfileAggressive:
		if cheap {
			return 200
		}
		return 50
	default:
		if cheap {
			return 60
		}
		return 20
	}
}

func parallelProbes(in Inputs, cheap bool) int {
	if !cheap {
		return 1
	}
	cpu := in.CPUCount
	if cpu <= 0 {
		cpu = runtime.NumCPU()
	}
	n := in.MaxParallelProbes
	if n <= 0 {
		n = DefaultMaxParallelProbes
	}
	if n > cpu {
		n = cpu
	}
	if n > HardMaxParallelProbes {
		n = HardMaxParallelProbes
	}
	if n < 1 {
		n = 1
	}
	return n
}
