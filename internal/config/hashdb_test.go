package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigHashDBDefaultsToOff(t *testing.T) {
	dir := setupTestDir(t)

	yamlContent := []byte("fallback_passwords:\n  - \"abc\"\n")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), yamlContent, 0o644); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	c, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.HashDB.Mode != "" && c.HashDB.Mode != "off" {
		t.Fatalf("HashDB.Mode = %q, want empty or off", c.HashDB.Mode)
	}
	if len(c.HashDB.Sources) != 0 {
		t.Fatalf("HashDB.Sources = %v, want empty", c.HashDB.Sources)
	}
}

func TestLoadConfigHashDBMissingSection(t *testing.T) {
	setupTestDir(t)

	c, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.HashDB.Mode != "" && c.HashDB.Mode != "off" {
		t.Fatalf("default HashDB.Mode = %q, want empty/off", c.HashDB.Mode)
	}
	if len(c.HashDB.Sources) != 0 {
		t.Fatalf("default HashDB.Sources = %v, want empty", c.HashDB.Sources)
	}
}

func TestLoadConfigHashDBLookupModeWithSource(t *testing.T) {
	dir := setupTestDir(t)

	yamlContent := []byte(`hashdb:
  mode: lookup
  sources:
    - name: official
      path: /tmp/bundle.json
      public_key: deadbeef
    - name: secondary
      path: /tmp/secondary.json
      disabled: true
`)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), yamlContent, 0o644); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	c, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.HashDB.Mode != "lookup" {
		t.Fatalf("HashDB.Mode = %q, want lookup", c.HashDB.Mode)
	}
	if len(c.HashDB.Sources) != 2 {
		t.Fatalf("len(Sources) = %d, want 2", len(c.HashDB.Sources))
	}
	s0 := c.HashDB.Sources[0]
	if s0.Name != "official" || s0.Path != "/tmp/bundle.json" || s0.PublicKey != "deadbeef" {
		t.Fatalf("source[0] = %+v", s0)
	}
	if s0.Disabled {
		t.Fatalf("source[0].Disabled = true, want false (default enabled)")
	}
	s1 := c.HashDB.Sources[1]
	if s1.Name != "secondary" || s1.Path != "/tmp/secondary.json" {
		t.Fatalf("source[1] = %+v", s1)
	}
	if !s1.Disabled {
		t.Fatalf("source[1].Disabled = false, want true")
	}
}
