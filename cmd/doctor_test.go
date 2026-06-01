package cmd

import (
	"bytes"
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
