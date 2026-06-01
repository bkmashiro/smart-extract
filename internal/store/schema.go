package store

import "time"

// ExactCacheEntry stores an exact archive identifier to password mapping.
type ExactCacheEntry struct {
	ArchiveKey string
	Password   string
	Source     string
}

// PasswordObservation is an append-only successful extraction observation.
type PasswordObservation struct {
	ID            int64
	ArchivePath   string
	ArchiveName   string
	ParentDir     string
	Password      string
	Source        string
	ArchiveSize   int64
	RootSessionID string
	ParentArchive string
	Depth         int
	SuccessAt     time.Time
}

// PatternRule is a derived or migrated filename/context pattern rule.
type PatternRule struct {
	ID          int64
	PatternType string
	PatternKey  string
	Password    string
	Alpha       float64
	Beta        float64
	Support     int
	Confidence  float64
	Source      string
	UpdatedAt   time.Time
}

// PasswordStat stores aggregate local password popularity metadata.
type PasswordStat struct {
	Password  string
	TotalUses int
	Source    string
	UpdatedAt time.Time
}

// Preferences stores local learning/extraction preferences in SQLite.
type Preferences struct {
	DeleteAfterExtract  bool
	DeletePreferenceSet bool
	CostBudget          string
	MaxParallelProbes   int
	PrivacyMode         bool
}
