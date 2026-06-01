package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bkmashiro/smart-extract/internal/config"
)

func TestExplainArchiveReportsCandidateCountsWithoutPasswords(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.FallbackPasswords = []string{"fallback-secret"}
	cfg.ProbeBudgetProfile = "light"
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	archivePath := filepath.Join(dir, "password=filename-secret.zip")
	if err := os.WriteFile(archivePath, []byte("fake archive bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	var out bytes.Buffer
	if err := ExplainArchive(archivePath, &out); err != nil {
		t.Fatalf("ExplainArchive: %v", err)
	}
	report := out.String()
	for _, want := range []string{"Smart Extract explain", "archive: password=[redacted]", "budget_profile: light", "candidate_limit:", "total_candidates:", "candidate_sources:", "filename=1", "fallback=1", "empty=1", "hashdb_mode: off"} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
	for _, secret := range []string{"filename-secret", "fallback-secret"} {
		if strings.Contains(report, secret) {
			t.Fatalf("explain report leaked plaintext password %q:\n%s", secret, report)
		}
	}
}

func TestExplainArchiveReportsDisabledHashDBSource(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{Name: "private-disabled", Type: "bundle", Path: filepath.Join(dir, "missing.bundle.json"), Disabled: true},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	archivePath := filepath.Join(dir, "plain.zip")
	if err := os.WriteFile(archivePath, []byte("fake archive bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	var out bytes.Buffer
	if err := ExplainArchive(archivePath, &out); err != nil {
		t.Fatalf("ExplainArchive: %v", err)
	}
	report := out.String()
	for _, want := range []string{"hashdb_mode: lookup", "hashdb_sources: configured=1 active=0 disabled=1 matches=0", "private-disabled", "state=disabled"} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
}
