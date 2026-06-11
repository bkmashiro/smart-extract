package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bkmashiro/smart-extract/internal/candidates"
	"github.com/bkmashiro/smart-extract/internal/config"
)

// explainResult is the deterministic, password-redacted summary that backs
// both the text and JSON explain reports. It is built without prompting,
// extraction, learning, contribution, or HTTP downloads.
type explainResult struct {
	Command          string         `json:"command"`
	Archive          string         `json:"archive"`
	BudgetProfile    string         `json:"budget_profile"`
	CandidateLimit   int            `json:"candidate_limit"`
	Person           string         `json:"person,omitempty"`
	TotalCandidates  int            `json:"total_candidates"`
	CandidateSources map[string]int `json:"candidate_sources"`
	HashDB           explainHashDB  `json:"hashdb"`
}

type explainHashDB struct {
	Mode       string                `json:"mode"`
	Configured int                   `json:"configured"`
	Active     int                   `json:"active"`
	Disabled   int                   `json:"disabled"`
	Matches    int                   `json:"matches"`
	Sources    []explainHashDBSource `json:"sources"`
}

type explainHashDBSource struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	State string `json:"state"`
}

// ExplainArchive prints a safe, password-redacted diagnostic report for how an
// archive would be handled. It only builds candidate metadata and consults
// configured HashDB lookup sources; it never extracts, prompts, learns,
// contributes, or deletes files.
func ExplainArchive(archivePath string, w io.Writer) error {
	if w == nil {
		w = io.Discard
	}
	result, err := buildExplainResult(archivePath, false)
	if err != nil {
		return err
	}
	writeExplainText(result, w)
	return nil
}

// ExplainArchiveJSON writes the same diagnostic data as ExplainArchive in a
// deterministic, indented JSON form suitable for bug reports and automation.
// It enforces the same safety contract: no extraction, prompting, learning,
// contribution, HTTP downloads, or plaintext password/candidate values.
func ExplainArchiveJSON(archivePath string, w io.Writer) error {
	if w == nil {
		w = io.Discard
	}
	result, err := buildExplainResult(archivePath, true)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func buildExplainResult(archivePath string, suppressWarnings bool) (explainResult, error) {
	absPath, err := filepath.Abs(archivePath)
	if err == nil {
		archivePath = absPath
	}
	if _, err := os.Stat(archivePath); err != nil {
		return explainResult{}, fmt.Errorf("文件不存在: %s", archivePath)
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		return explainResult{}, fmt.Errorf("加载配置失败: %w", err)
	}
	learned, err := config.LoadLearned()
	if err != nil {
		return explainResult{}, fmt.Errorf("加载学习数据失败: %w", err)
	}

	learningStore, err := openLearningStore(learned)
	if err == nil {
		defer learningStore.Close()
	}

	archiveName := filepath.Base(archivePath)
	provider := newPasswordProvider(archivePath, archiveName, cfg, learned)
	provider.suppressWarnings = suppressWarnings
	provider.candidateSource = learningStore
	person, _ := provider.identifyPerson()
	provider.resolvedPerson = person

	rec := provider.budgetRecommendation(archivePath)
	counts := map[string]int{}
	total := 0
	hashDBMatches := 0
	if learningStore != nil {
		helperPasswords := provider.helperPasswords(context.Background(), archivePath)
		hashDBPasswords := provider.hashDBPasswords(context.Background(), archivePath)
		hashDBMatches = len(hashDBPasswords)
		built, err := candidates.Build(context.Background(), candidates.Request{
			ArchivePath:       archivePath,
			ArchiveKey:        archiveName,
			HelperPasswords:   helperPasswords,
			HashDBPasswords:   hashDBPasswords,
			StaticPasswords:   provider.staticPasswords(false),
			FallbackPasswords: cfg.FallbackPasswords,
			CandidateLimit:    rec.CandidateLimit,
		}, learningStore)
		if err != nil {
			return explainResult{}, err
		}
		total = len(built)
		for _, candidate := range built {
			counts[candidate.Source]++
		}
	} else {
		passwords, err := provider.getPasswords(archivePath)
		if err != nil {
			return explainResult{}, err
		}
		total = len(passwords)
		counts["legacy"] = total
	}

	sources := make([]explainHashDBSource, 0, len(cfg.HashDB.Sources))
	for _, src := range cfg.HashDB.Sources {
		state := "active"
		if src.Disabled {
			state = "disabled"
		}
		sources = append(sources, explainHashDBSource{
			Name:  sanitizeDebugLine(hashDBSourceLabel(src)),
			Type:  sourceTypeForExplain(src.Type),
			State: state,
		})
	}

	result := explainResult{
		Command:          "explain",
		Archive:          sanitizeDebugLine(archiveName),
		BudgetProfile:    debugProfileName(cfg.ProbeBudgetProfile),
		CandidateLimit:   rec.CandidateLimit,
		Person:           sanitizeDebugLine(person),
		TotalCandidates:  total,
		CandidateSources: counts,
		HashDB: explainHashDB{
			Mode:       normalizedHashDBMode(cfg.HashDB.Mode),
			Configured: len(cfg.HashDB.Sources),
			Active:     activeHashDBSources(cfg),
			Disabled:   disabledHashDBSources(cfg),
			Matches:    hashDBMatches,
			Sources:    sources,
		},
	}
	return result, nil
}

func writeExplainText(r explainResult, w io.Writer) {
	fmt.Fprintf(w, "Smart Extract explain\n")
	fmt.Fprintf(w, "archive: %s\n", r.Archive)
	fmt.Fprintf(w, "budget_profile: %s\n", r.BudgetProfile)
	fmt.Fprintf(w, "candidate_limit: %d\n", r.CandidateLimit)
	if r.Person != "" {
		fmt.Fprintf(w, "person: %s\n", r.Person)
	}
	fmt.Fprintf(w, "total_candidates: %d\n", r.TotalCandidates)
	fmt.Fprintf(w, "candidate_sources: %s\n", sortedCountSummary(r.CandidateSources))
	fmt.Fprintf(w, "hashdb_mode: %s\n", r.HashDB.Mode)
	fmt.Fprintf(w, "hashdb_sources: configured=%d active=%d disabled=%d matches=%d\n",
		r.HashDB.Configured, r.HashDB.Active, r.HashDB.Disabled, r.HashDB.Matches)
	// Preserve config order in text output by iterating the same slice.
	for _, src := range r.HashDB.Sources {
		fmt.Fprintf(w, "  - %s type=%s state=%s\n", src.Name, src.Type, src.State)
	}
}

func normalizedHashDBMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "lookup") {
		return "lookup"
	}
	return "off"
}

func activeHashDBSources(cfg *config.Config) int {
	if cfg == nil || !strings.EqualFold(cfg.HashDB.Mode, "lookup") {
		return 0
	}
	active := 0
	for _, src := range cfg.HashDB.Sources {
		if !src.Disabled {
			active++
		}
	}
	return active
}

func disabledHashDBSources(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	disabled := 0
	for _, src := range cfg.HashDB.Sources {
		if src.Disabled {
			disabled++
		}
	}
	return disabled
}

func sourceTypeForExplain(sourceType string) string {
	sourceType = strings.ToLower(strings.TrimSpace(sourceType))
	if sourceType == "" {
		return "bundle"
	}
	return sourceType
}
