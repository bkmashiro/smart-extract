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

func TestLoadConfigHashDBContributionDefaultsToOff(t *testing.T) {
	dir := setupTestDir(t)

	yamlContent := []byte("fallback_passwords:\n  - \"abc\"\n")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), yamlContent, 0o644); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	c, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.HashDB.Contribute != "" && c.HashDB.Contribute != "off" {
		t.Fatalf("HashDB.Contribute = %q, want empty or off", c.HashDB.Contribute)
	}
	if c.HashDB.Contribution.Type != "" {
		t.Fatalf("HashDB.Contribution.Type = %q, want empty", c.HashDB.Contribution.Type)
	}
	if c.HashDB.Contribution.Path != "" {
		t.Fatalf("HashDB.Contribution.Path = %q, want empty", c.HashDB.Contribution.Path)
	}
	if c.HashDB.Contribution.BaseDir != "" {
		t.Fatalf("HashDB.Contribution.BaseDir = %q, want empty", c.HashDB.Contribution.BaseDir)
	}
	if c.HashDB.Contribution.KeyPath != "" {
		t.Fatalf("HashDB.Contribution.KeyPath = %q, want empty", c.HashDB.Contribution.KeyPath)
	}
	if c.HashDB.Contribution.ShardPrefixLength != 0 {
		t.Fatalf("HashDB.Contribution.ShardPrefixLength = %d, want 0", c.HashDB.Contribution.ShardPrefixLength)
	}
}

func TestLoadConfigHashDBContributionAutoBundleParses(t *testing.T) {
	dir := setupTestDir(t)

	yamlContent := []byte(`hashdb:
  mode: lookup
  contribute: auto
  contribution:
    type: bundle
    path: /tmp/local-bundle.json
    key_path: /tmp/local-key.json
    source: local-private
`)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), yamlContent, 0o644); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	c, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.HashDB.Contribute != "auto" {
		t.Fatalf("HashDB.Contribute = %q, want auto", c.HashDB.Contribute)
	}
	if c.HashDB.Contribution.Type != "bundle" {
		t.Fatalf("Contribution.Type = %q", c.HashDB.Contribution.Type)
	}
	if c.HashDB.Contribution.Path != "/tmp/local-bundle.json" {
		t.Fatalf("Contribution.Path = %q", c.HashDB.Contribution.Path)
	}
	if c.HashDB.Contribution.KeyPath != "/tmp/local-key.json" {
		t.Fatalf("Contribution.KeyPath = %q", c.HashDB.Contribution.KeyPath)
	}
	if c.HashDB.Contribution.Source != "local-private" {
		t.Fatalf("Contribution.Source = %q", c.HashDB.Contribution.Source)
	}
}

func TestLoadConfigHashDBContributionShardedParses(t *testing.T) {
	dir := setupTestDir(t)

	yamlContent := []byte(`hashdb:
  contribute: auto
  contribution:
    type: sharded
    base_dir: /tmp/sharded
    key_path: /tmp/sharded-key.json
    source: local-private
    shard_prefix_length: 3
`)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), yamlContent, 0o644); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	c, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.HashDB.Contribute != "auto" {
		t.Fatalf("HashDB.Contribute = %q, want auto", c.HashDB.Contribute)
	}
	if c.HashDB.Contribution.Type != "sharded" {
		t.Fatalf("Contribution.Type = %q", c.HashDB.Contribution.Type)
	}
	if c.HashDB.Contribution.BaseDir != "/tmp/sharded" {
		t.Fatalf("Contribution.BaseDir = %q", c.HashDB.Contribution.BaseDir)
	}
	if c.HashDB.Contribution.KeyPath != "/tmp/sharded-key.json" {
		t.Fatalf("Contribution.KeyPath = %q", c.HashDB.Contribution.KeyPath)
	}
	if c.HashDB.Contribution.ShardPrefixLength != 3 {
		t.Fatalf("Contribution.ShardPrefixLength = %d, want 3", c.HashDB.Contribution.ShardPrefixLength)
	}
}

func TestLoadConfigHashDBShardedSourceParses(t *testing.T) {
	dir := setupTestDir(t)

	yamlContent := []byte(`hashdb:
  mode: lookup
  sources:
    - name: bundle-src
      path: /tmp/bundle.json
      public_key: aa
    - name: sharded-src
      type: sharded
      base_dir: /tmp/sharded
      manifest_path: /tmp/sharded/manifest.json
      public_key: bb
`)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), yamlContent, 0o644); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	c, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(c.HashDB.Sources) != 2 {
		t.Fatalf("len(Sources) = %d, want 2", len(c.HashDB.Sources))
	}
	s0 := c.HashDB.Sources[0]
	if s0.Type != "" {
		t.Fatalf("source[0].Type = %q, want empty for default bundle", s0.Type)
	}
	if s0.Path != "/tmp/bundle.json" || s0.PublicKey != "aa" {
		t.Fatalf("source[0] = %+v", s0)
	}
	s1 := c.HashDB.Sources[1]
	if s1.Type != "sharded" {
		t.Fatalf("source[1].Type = %q, want sharded", s1.Type)
	}
	if s1.BaseDir != "/tmp/sharded" {
		t.Fatalf("source[1].BaseDir = %q", s1.BaseDir)
	}
	if s1.ManifestPath != "/tmp/sharded/manifest.json" {
		t.Fatalf("source[1].ManifestPath = %q", s1.ManifestPath)
	}
	if s1.PublicKey != "bb" {
		t.Fatalf("source[1].PublicKey = %q", s1.PublicKey)
	}
}
