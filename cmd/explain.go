package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bkmashiro/smart-extract/internal/candidates"
	"github.com/bkmashiro/smart-extract/internal/config"
)

// ExplainArchive prints a safe, password-redacted diagnostic report for how an
// archive would be handled. It only builds candidate metadata and consults
// configured HashDB lookup sources; it never extracts, prompts, learns,
// contributes, or deletes files.
func ExplainArchive(archivePath string, w io.Writer) error {
	if w == nil {
		w = io.Discard
	}
	absPath, err := filepath.Abs(archivePath)
	if err == nil {
		archivePath = absPath
	}
	if _, err := os.Stat(archivePath); err != nil {
		return fmt.Errorf("文件不存在: %s", archivePath)
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("加载配置失败: %w", err)
	}
	learned, err := config.LoadLearned()
	if err != nil {
		return fmt.Errorf("加载学习数据失败: %w", err)
	}

	learningStore, err := openLearningStore(learned)
	if err == nil {
		defer learningStore.Close()
	}

	archiveName := filepath.Base(archivePath)
	provider := newPasswordProvider(archivePath, archiveName, cfg, learned)
	provider.candidateSource = learningStore
	person, _ := provider.identifyPerson()
	provider.resolvedPerson = person

	rec := provider.budgetRecommendation(archivePath)
	counts := map[string]int{}
	total := 0
	hashDBMatches := 0
	if learningStore != nil {
		hashDBPasswords := provider.hashDBPasswords(context.Background(), archivePath)
		hashDBMatches = len(hashDBPasswords)
		built, err := candidates.Build(context.Background(), candidates.Request{
			ArchivePath:       archivePath,
			ArchiveKey:        archiveName,
			HashDBPasswords:   hashDBPasswords,
			StaticPasswords:   provider.staticPasswords(false),
			FallbackPasswords: cfg.FallbackPasswords,
			CandidateLimit:    rec.CandidateLimit,
		}, learningStore)
		if err != nil {
			return err
		}
		total = len(built)
		for _, candidate := range built {
			counts[candidate.Source]++
		}
	} else {
		passwords, err := provider.getPasswords(archivePath)
		if err != nil {
			return err
		}
		total = len(passwords)
		counts["legacy"] = total
	}

	fmt.Fprintf(w, "Smart Extract explain\n")
	fmt.Fprintf(w, "archive: %s\n", sanitizeDebugLine(archiveName))
	fmt.Fprintf(w, "budget_profile: %s\n", debugProfileName(cfg.ProbeBudgetProfile))
	fmt.Fprintf(w, "candidate_limit: %d\n", rec.CandidateLimit)
	if person != "" {
		fmt.Fprintf(w, "person: %s\n", sanitizeDebugLine(person))
	}
	fmt.Fprintf(w, "total_candidates: %d\n", total)
	fmt.Fprintf(w, "candidate_sources: %s\n", sortedCountSummary(counts))
	fmt.Fprintf(w, "hashdb_mode: %s\n", normalizedHashDBMode(cfg.HashDB.Mode))
	fmt.Fprintf(w, "hashdb_sources: configured=%d active=%d disabled=%d matches=%d\n", len(cfg.HashDB.Sources), activeHashDBSources(cfg), disabledHashDBSources(cfg), hashDBMatches)
	for _, src := range cfg.HashDB.Sources {
		state := "active"
		if src.Disabled {
			state = "disabled"
		}
		fmt.Fprintf(w, "  - %s type=%s state=%s\n", sanitizeDebugLine(hashDBSourceLabel(src)), sourceTypeForExplain(src.Type), state)
	}
	return nil
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
