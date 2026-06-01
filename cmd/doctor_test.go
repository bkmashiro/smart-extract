package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bkmashiro/smart-extract/internal/config"
)

func TestDoctorReportsConfigLearningAndHashDBWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.SevenZipPath = filepath.Join(dir, "missing-7z.exe")
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{Name: "password=source-secret", Type: "bundle", URL: "https://example.com/password=mirror-secret.bundle.json", CacheDir: filepath.Join(dir, "password=cache-secret")},
		{Name: "disabled-source", Type: "sharded", BaseDir: filepath.Join(dir, "missing-shards"), Disabled: true},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	var out bytes.Buffer
	if err := Doctor(&out); err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	report := out.String()
	for _, want := range []string{"Smart Extract doctor", "config: ok", "7zip: error", "legacy_learning: ok", "learning_store: ok", "hashdb: mode=lookup configured=2 active=1 disabled=1", "password=[redacted]", "disabled-source", "state=disabled"} {
		if !strings.Contains(report, want) {
			t.Fatalf("doctor report missing %q:\n%s", want, report)
		}
	}
	for _, secret := range []string{"source-secret", "mirror-secret", "cache-secret"} {
		if strings.Contains(report, secret) {
			t.Fatalf("doctor leaked secret-like text %q:\n%s", secret, report)
		}
	}
}

func TestDoctorJSONReportsConfigLearningAndHashDBWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.SevenZipPath = filepath.Join(dir, "missing-7z.exe")
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{Name: "password=source-secret", Type: "bundle", URL: "https://example.com/password=mirror-secret.bundle.json", CacheDir: filepath.Join(dir, "password=cache-secret")},
		{Name: "disabled-source", Type: "sharded", BaseDir: filepath.Join(dir, "missing-shards"), Disabled: true},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	var out bytes.Buffer
	if err := DoctorJSON(&out); err != nil {
		t.Fatalf("DoctorJSON: %v", err)
	}
	raw := out.String()
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v; out=%s", err, raw)
	}
	if got["command"] != "doctor" {
		t.Fatalf("command=%v want doctor", got["command"])
	}
	cfgSection, ok := got["config"].(map[string]any)
	if !ok || cfgSection["status"] != "ok" {
		t.Fatalf("config section missing or not ok: %v", got["config"])
	}
	sz, ok := got["sevenzip"].(map[string]any)
	if !ok || sz["status"] != "error" {
		t.Fatalf("sevenzip section should be error: %v", got["sevenzip"])
	}
	if _, ok := got["legacy_learning"].(map[string]any); !ok {
		t.Fatalf("legacy_learning section missing: %v", got["legacy_learning"])
	}
	if _, ok := got["learning_store"].(map[string]any); !ok {
		t.Fatalf("learning_store section missing: %v", got["learning_store"])
	}
	hashdb, ok := got["hashdb"].(map[string]any)
	if !ok {
		t.Fatalf("hashdb missing: %v", got["hashdb"])
	}
	if hashdb["mode"] != "lookup" {
		t.Fatalf("hashdb.mode=%v want lookup", hashdb["mode"])
	}
	if hashdb["configured"].(float64) != 2 {
		t.Fatalf("hashdb.configured=%v want 2", hashdb["configured"])
	}
	if hashdb["active"].(float64) != 1 {
		t.Fatalf("hashdb.active=%v want 1", hashdb["active"])
	}
	if hashdb["disabled"].(float64) != 1 {
		t.Fatalf("hashdb.disabled=%v want 1", hashdb["disabled"])
	}
	sources, ok := hashdb["sources"].([]any)
	if !ok || len(sources) != 2 {
		t.Fatalf("hashdb.sources should have 2 entries: %v", hashdb["sources"])
	}
	first := sources[0].(map[string]any)
	if name, _ := first["name"].(string); !strings.Contains(name, "password=[redacted]") {
		t.Fatalf("first source name should redact password, got %q", name)
	}
	if loc, _ := first["location"].(string); !strings.Contains(loc, "password=[redacted]") {
		t.Fatalf("first source location should redact password, got %q", loc)
	}
	for _, secret := range []string{"source-secret", "mirror-secret", "cache-secret"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("doctor JSON leaked secret-like text %q:\n%s", secret, raw)
		}
	}
}

func TestDoctorJSONDoesNotDownloadHTTPSources(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()
	cacheDir := filepath.Join(dir, "hashdb-cache")
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{{Name: "mirror", Type: "bundle", URL: "https://example.com/hashdb.bundle.json", CacheDir: cacheDir}}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	var out bytes.Buffer
	if err := DoctorJSON(&out); err != nil {
		t.Fatalf("DoctorJSON: %v", err)
	}
	if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
		t.Fatalf("doctor-json should not create/download cache dir, stat err=%v", err)
	}
}

func TestDoctorDoesNotDownloadHTTPSources(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()
	cacheDir := filepath.Join(dir, "hashdb-cache")
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{{Name: "mirror", Type: "bundle", URL: "https://example.com/hashdb.bundle.json", CacheDir: cacheDir}}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	var out bytes.Buffer
	if err := Doctor(&out); err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
		t.Fatalf("doctor should not create/download cache dir, stat err=%v", err)
	}
}
