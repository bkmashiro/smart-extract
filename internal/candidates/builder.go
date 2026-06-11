package candidates

import (
	"context"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bkmashiro/smart-extract/internal/store"
)

const (
	SourceParent     = "parent"
	SourceExact      = "exact"
	SourceHelper     = "helper"
	SourceHashDB     = "hashdb"
	SourceFilename   = "filename"
	SourceSession    = "session"
	SourcePattern    = "pattern"
	SourceDictionary = "dictionary"
	SourceStatic     = "static"
	SourceEmpty      = "empty"
	SourceFallback   = "fallback"
)

// Candidate is one password attempt with provenance for later learning/debugging.
type Candidate struct {
	Password string
	Source   string
	Score    float64
}

// Request describes the archive and candidate-budget context.
type Request struct {
	ArchivePath       string
	ArchiveKey        string
	ParentPassword    string
	HelperPasswords   []string
	HashDBPasswords   []string
	StaticPasswords   []string
	FallbackPasswords []string
	DictionaryLimit   int
	CandidateLimit    int
}

// Source provides local learned candidate data.
type Source interface {
	LookupExact(ctx context.Context, archiveKey string) (string, bool, error)
	SessionPasswords(ctx context.Context, parentDir string, limit int) ([]string, error)
	PatternRules(ctx context.Context, patternType, patternKey string) ([]store.PatternRule, error)
	TopPasswords(ctx context.Context, limit int) ([]store.PasswordStat, error)
}

// Build returns ordered, deduplicated password candidates.
func Build(ctx context.Context, req Request, source Source) ([]Candidate, error) {
	builder := candidateBuilder{
		seen:  make(map[string]struct{}),
		limit: req.CandidateLimit,
	}

	if req.ParentPassword != "" {
		builder.add(Candidate{Password: req.ParentPassword, Source: SourceParent, Score: 2000})
	}

	archiveKey := req.ArchiveKey
	if archiveKey == "" {
		archiveKey = filepath.Base(req.ArchivePath)
	}
	if source != nil && archiveKey != "" {
		password, ok, err := source.LookupExact(ctx, archiveKey)
		if err != nil {
			return nil, err
		}
		if ok {
			builder.add(Candidate{Password: password, Source: SourceExact, Score: 1500})
		}
	}

	for _, password := range req.HelperPasswords {
		builder.add(Candidate{Password: password, Source: SourceHelper, Score: 1300})
	}

	for _, password := range req.HashDBPasswords {
		builder.add(Candidate{Password: password, Source: SourceHashDB, Score: 1200})
	}

	for _, password := range ExtractFilenamePasswords(filepath.Base(req.ArchivePath)) {
		builder.add(Candidate{Password: password, Source: SourceFilename, Score: 1000})
	}

	if source != nil {
		passwords, err := source.SessionPasswords(ctx, filepath.Dir(req.ArchivePath), 10)
		if err != nil {
			return nil, err
		}
		for _, password := range passwords {
			builder.add(Candidate{Password: password, Source: SourceSession, Score: 100})
		}
	}

	if source != nil {
		archiveBase := filepath.Base(req.ArchivePath)
		patternQueries := []struct {
			patternType string
			patternKey  string
		}{
			{"shape", ShapeKey(archiveBase)},
			{"stem_shape", StemShapeKey(archiveBase)},
		}
		for _, q := range patternQueries {
			if q.patternKey == "" {
				continue
			}
			rules, err := source.PatternRules(ctx, q.patternType, q.patternKey)
			if err != nil {
				return nil, err
			}
			sort.SliceStable(rules, func(i, j int) bool {
				if rules[i].Confidence != rules[j].Confidence {
					return rules[i].Confidence > rules[j].Confidence
				}
				return rules[i].Support > rules[j].Support
			})
			for _, rule := range rules {
				builder.add(Candidate{Password: rule.Password, Source: SourcePattern, Score: 10 + rule.Confidence})
			}
		}
	}

	if source != nil {
		limit := req.DictionaryLimit
		if limit == 0 {
			limit = 10
		}
		passwords, err := source.TopPasswords(ctx, limit)
		if err != nil {
			return nil, err
		}
		for _, password := range passwords {
			builder.add(Candidate{Password: password.Password, Source: SourceDictionary, Score: 1})
		}
	}

	for _, password := range req.StaticPasswords {
		builder.add(Candidate{Password: password, Source: SourceStatic, Score: 0.5})
	}

	builder.add(Candidate{Password: "", Source: SourceEmpty, Score: 0})
	for _, password := range req.FallbackPasswords {
		builder.add(Candidate{Password: password, Source: SourceFallback, Score: -1})
	}

	return builder.out, nil
}

type candidateBuilder struct {
	out   []Candidate
	seen  map[string]struct{}
	limit int
}

func (b *candidateBuilder) add(candidate Candidate) {
	if b.limit > 0 && len(b.out) >= b.limit {
		return
	}
	if _, ok := b.seen[candidate.Password]; ok {
		return
	}
	b.seen[candidate.Password] = struct{}{}
	b.out = append(b.out, candidate)
}

var explicitPasswordPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:password|passwd|pass|pwd)[=_-]([^\]\/\s.]+)`),
	regexp.MustCompile(`(?i)密码[=_-]?([^\]\/\s.]+)`),
}

// ExtractFilenamePasswords extracts explicit password hints embedded in a filename.
func ExtractFilenamePasswords(filename string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, pattern := range explicitPasswordPatterns {
		matches := pattern.FindAllStringSubmatch(filename, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			password := strings.Trim(match[1], " .,_-[](){}")
			if password == "" {
				continue
			}
			if _, ok := seen[password]; ok {
				continue
			}
			seen[password] = struct{}{}
			out = append(out, password)
		}
	}
	return out
}

// ShapeKey normalizes filename digits for simple batch-derived pattern lookup.
func ShapeKey(filename string) string {
	base := filepath.Base(filename)
	ext := filepath.Ext(base)
	stem := base
	if ext != "" && len(ext) < len(base) {
		stem = base[:len(base)-len(ext)]
	}
	return shapeDigits(stem) + strings.ToLower(ext)
}

func shapeDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune('N')
			continue
		}
		b.WriteRune(r)
	}
	return strings.ToLower(b.String())
}

// StemShapeKey returns the ShapeKey of the filename's stem (without its final
// extension). Returns "" when the stem has no digits to generalize, so callers
// can skip non-informative lookups.
func StemShapeKey(filename string) string {
	base := filepath.Base(filename)
	ext := filepath.Ext(base)
	stem := base
	if ext != "" && len(ext) < len(base) {
		stem = base[:len(base)-len(ext)]
	}
	if stem == "" {
		return ""
	}
	shaped := shapeDigits(stem)
	if shaped == strings.ToLower(stem) {
		return ""
	}
	return shaped
}
