package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bkmashiro/smart-extract/internal/config"
)

func TestHashDBAddLocalSourceCreatesBundleLookupSource(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	keyPath := filepath.Join(dir, "hashdb", "signing.key.json")
	bundlePath := filepath.Join(dir, "hashdb", "private.bundle.json")

	pub, err := HashDBAddLocalSource(HashDBAddLocalSourceOptions{
		Name:    "my-private-bundle",
		Type:    "bundle",
		Path:    bundlePath,
		KeyPath: keyPath,
	})
	if err != nil {
		t.Fatalf("HashDBAddLocalSource: %v", err)
	}
	if pub == "" {
		t.Fatalf("public key is empty")
	}

	config.ReloadAll()
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.HashDB.Mode != "lookup" {
		t.Fatalf("HashDB.Mode = %q, want lookup", cfg.HashDB.Mode)
	}
	if len(cfg.HashDB.Sources) != 1 {
		t.Fatalf("len(Sources) = %d, want 1: %+v", len(cfg.HashDB.Sources), cfg.HashDB.Sources)
	}
	src := cfg.HashDB.Sources[0]
	if src.Name != "my-private-bundle" || src.Type != "bundle" || src.Path != bundlePath || src.PublicKey != pub {
		t.Fatalf("source = %+v, want name/type/path/public key", src)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected key file to be created: %v", err)
	}
}

func TestHashDBAddLocalSourceUpsertsByName(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	keyPath := filepath.Join(dir, "hashdb", "signing.key.json")
	firstPath := filepath.Join(dir, "hashdb", "old.bundle.json")
	secondPath := filepath.Join(dir, "hashdb", "new.bundle.json")

	if _, err := HashDBAddLocalSource(HashDBAddLocalSourceOptions{Name: "mine", Type: "bundle", Path: firstPath, KeyPath: keyPath}); err != nil {
		t.Fatalf("first add: %v", err)
	}
	pub, err := HashDBAddLocalSource(HashDBAddLocalSourceOptions{Name: "mine", Type: "bundle", Path: secondPath, KeyPath: keyPath})
	if err != nil {
		t.Fatalf("second add: %v", err)
	}

	config.ReloadAll()
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.HashDB.Sources) != 1 {
		t.Fatalf("len(Sources) = %d, want 1: %+v", len(cfg.HashDB.Sources), cfg.HashDB.Sources)
	}
	src := cfg.HashDB.Sources[0]
	if src.Path != secondPath || src.PublicKey != pub {
		t.Fatalf("source = %+v, want updated path and public key %s", src, pub)
	}
}

func TestHashDBAddLocalSourceCreatesShardedLookupSource(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	keyPath := filepath.Join(dir, "hashdb", "signing.key.json")
	baseDir := filepath.Join(dir, "hashdb", "private")

	pub, err := HashDBAddLocalSource(HashDBAddLocalSourceOptions{
		Name:    "my-private-shards",
		Type:    "sharded",
		BaseDir: baseDir,
		KeyPath: keyPath,
	})
	if err != nil {
		t.Fatalf("HashDBAddLocalSource: %v", err)
	}

	config.ReloadAll()
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.HashDB.Sources) != 1 {
		t.Fatalf("len(Sources) = %d, want 1: %+v", len(cfg.HashDB.Sources), cfg.HashDB.Sources)
	}
	src := cfg.HashDB.Sources[0]
	if src.Name != "my-private-shards" || src.Type != "sharded" || src.BaseDir != baseDir || src.PublicKey != pub {
		t.Fatalf("source = %+v, want sharded base dir and public key", src)
	}
}

func TestHashDBAddLocalSourceRejectsMissingTarget(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	_, err := HashDBAddLocalSource(HashDBAddLocalSourceOptions{
		Name:    "bad",
		Type:    "bundle",
		KeyPath: filepath.Join(dir, "key.json"),
	})
	if err == nil {
		t.Fatalf("expected missing bundle path to fail")
	}
}
