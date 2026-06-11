package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bkmashiro/smart-extract/internal/config"
	"github.com/bkmashiro/smart-extract/internal/helper"
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

func TestExplainArchiveJSONReportsCandidatesWithoutPasswords(t *testing.T) {
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
	if err := ExplainArchiveJSON(archivePath, &out); err != nil {
		t.Fatalf("ExplainArchiveJSON: %v", err)
	}
	raw := out.String()
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v; out=%s", err, raw)
	}
	if got["command"] != "explain" {
		t.Fatalf("command=%v, want explain", got["command"])
	}
	archive, _ := got["archive"].(string)
	if !strings.Contains(archive, "password=[redacted]") {
		t.Fatalf("archive field should be redacted, got %q", archive)
	}
	if got["budget_profile"] != "light" {
		t.Fatalf("budget_profile=%v, want light", got["budget_profile"])
	}
	if _, ok := got["candidate_limit"].(float64); !ok {
		t.Fatalf("candidate_limit missing/not number: %v", got["candidate_limit"])
	}
	if _, ok := got["total_candidates"].(float64); !ok {
		t.Fatalf("total_candidates missing/not number: %v", got["total_candidates"])
	}
	sources, ok := got["candidate_sources"].(map[string]any)
	if !ok {
		t.Fatalf("candidate_sources missing/not object: %v", got["candidate_sources"])
	}
	for _, key := range []string{"filename", "fallback", "empty"} {
		if _, ok := sources[key]; !ok {
			t.Fatalf("candidate_sources missing key %q: %v", key, sources)
		}
	}
	hashdb, ok := got["hashdb"].(map[string]any)
	if !ok {
		t.Fatalf("hashdb missing/not object: %v", got["hashdb"])
	}
	if hashdb["mode"] != "off" {
		t.Fatalf("hashdb.mode=%v want off", hashdb["mode"])
	}
	for _, secret := range []string{"filename-secret", "fallback-secret"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("explain JSON leaked plaintext password %q:\n%s", secret, raw)
		}
	}
}

func TestExplainArchiveIncludesLocalHelperCandidates(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()
	archivePath := filepath.Join(dir, "demo.zip")
	if err := os.WriteFile(archivePath, []byte("fake archive bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	store := helper.NewMemoryStore(time.Minute)
	if _, err := store.Add(helper.CandidateBundle{
		SchemaVersion:   1,
		ArchiveFilename: "demo.zip",
		Candidates:      []helper.CandidatePassword{{Value: "helper-secret", Source: "page_text", Score: 0.9}},
	}); err != nil {
		t.Fatalf("seed helper: %v", err)
	}
	server := httptest.NewServer(helper.NewHandler(store, helper.Options{BearerToken: "test-token"}))
	defer server.Close()

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.LocalHelper = config.LocalHelperConfig{Mode: "lookup", Endpoint: server.URL, Token: "test-token"}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	var out bytes.Buffer
	if err := ExplainArchiveJSON(archivePath, &out); err != nil {
		t.Fatalf("ExplainArchiveJSON: %v", err)
	}
	raw := out.String()
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v; out=%s", err, raw)
	}
	sources := got["candidate_sources"].(map[string]any)
	if sources["helper"].(float64) != 1 {
		t.Fatalf("helper candidate count = %v, want 1; raw=%s", sources["helper"], raw)
	}
	if strings.Contains(raw, "helper-secret") {
		t.Fatalf("explain JSON leaked helper password:\n%s", raw)
	}
}

func TestExplainArchiveJSONReportsDisabledHashDBSource(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{Name: "password=src-secret", Type: "bundle", Path: filepath.Join(dir, "missing.bundle.json"), Disabled: true},
		{Name: "ok-source", Type: "bundle", Path: filepath.Join(dir, "ok.bundle.json")},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	archivePath := filepath.Join(dir, "plain.zip")
	if err := os.WriteFile(archivePath, []byte("fake archive bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	var out bytes.Buffer
	stdout := captureStdout(t, func() {
		if err := ExplainArchiveJSON(archivePath, &out); err != nil {
			t.Fatalf("ExplainArchiveJSON: %v", err)
		}
	})
	if stdout != "" {
		t.Fatalf("ExplainArchiveJSON should not write warnings to stdout; got %q", stdout)
	}
	raw := out.String()
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v; out=%s", err, raw)
	}
	hashdb, ok := got["hashdb"].(map[string]any)
	if !ok {
		t.Fatalf("hashdb missing: %v", got)
	}
	if hashdb["mode"] != "lookup" {
		t.Fatalf("hashdb.mode=%v want lookup", hashdb["mode"])
	}
	if hashdb["configured"].(float64) != 2 {
		t.Fatalf("configured=%v want 2", hashdb["configured"])
	}
	if hashdb["disabled"].(float64) != 1 {
		t.Fatalf("disabled=%v want 1", hashdb["disabled"])
	}
	if hashdb["active"].(float64) != 1 {
		t.Fatalf("active=%v want 1", hashdb["active"])
	}
	sources, ok := hashdb["sources"].([]any)
	if !ok || len(sources) != 2 {
		t.Fatalf("sources should be array of length 2: %v", hashdb["sources"])
	}
	first := sources[0].(map[string]any)
	if name, _ := first["name"].(string); !strings.Contains(name, "password=[redacted]") {
		t.Fatalf("source name should redact password, got %q", name)
	}
	if first["state"] != "disabled" {
		t.Fatalf("first source state=%v want disabled", first["state"])
	}
	if strings.Contains(raw, "src-secret") {
		t.Fatalf("explain JSON leaked password-like source name:\n%s", raw)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close stdout pipe writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(out)
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
