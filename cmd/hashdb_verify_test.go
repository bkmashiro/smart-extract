package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bkmashiro/smart-extract/internal/config"
)

func TestHashDBVerifySourceValidLocalBundle(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	archive := filepath.Join(dir, "archive.bin")
	if err := os.WriteFile(archive, []byte("verify-archive"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	bundlePath, pubHex := writeSignedBundleForTest(t, dir, archive, []string{"pw1", "pw2", "pw3"})

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{Name: "local", Type: "bundle", Path: bundlePath, PublicKey: pubHex},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	config.ReloadAll()

	res, err := HashDBVerifySource("local")
	if err != nil {
		t.Fatalf("HashDBVerifySource: %v", err)
	}
	if res.Status != "ok" {
		t.Fatalf("status=%q msg=%q", res.Status, res.Message)
	}
	if res.Records != 3 {
		t.Fatalf("records=%d want 3", res.Records)
	}
	if res.Type != "bundle" {
		t.Fatalf("type=%q want bundle", res.Type)
	}
	if res.Path == "" {
		t.Fatalf("expected bundle path in result")
	}
}

func TestHashDBVerifySourceDetectsPublicKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	archive := filepath.Join(dir, "archive.bin")
	if err := os.WriteFile(archive, []byte("verify-archive"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	bundlePath, _ := writeSignedBundleForTest(t, dir, archive, []string{"pw"})

	badPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{Name: "local", Type: "bundle", Path: bundlePath, PublicKey: hex.EncodeToString(badPub)},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	config.ReloadAll()

	res, err := HashDBVerifySource("local")
	if err != nil {
		t.Fatalf("HashDBVerifySource: %v", err)
	}
	if res.Status != "error" {
		t.Fatalf("status=%q want error", res.Status)
	}
	if !strings.Contains(strings.ToLower(res.Message), "public key") {
		t.Fatalf("message should mention public key, got %q", res.Message)
	}
}

func TestHashDBVerifySourceLocalSharded(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	archive := filepath.Join(dir, "archive.bin")
	if err := os.WriteFile(archive, []byte("sharded-archive-verify"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	shardBase := filepath.Join(dir, "shardroot")
	if err := os.MkdirAll(shardBase, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	_, pubHex := writeShardedSourceForTest(t, shardBase, archive, []string{"a", "b", "c"})

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{Name: "shards", Type: "sharded", BaseDir: shardBase, PublicKey: pubHex},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	config.ReloadAll()

	res, err := HashDBVerifySource("shards")
	if err != nil {
		t.Fatalf("HashDBVerifySource: %v", err)
	}
	if res.Status != "ok" {
		t.Fatalf("status=%q msg=%q", res.Status, res.Message)
	}
	if res.Type != "sharded" {
		t.Fatalf("type=%q want sharded", res.Type)
	}
	if res.Shards < 1 {
		t.Fatalf("shards=%d want >=1", res.Shards)
	}
	if res.Records < 3 {
		t.Fatalf("records=%d want >=3", res.Records)
	}
	if res.Path == "" {
		t.Fatalf("expected manifest path in result")
	}
}

func TestHashDBVerifySourceHTTPNoCacheReportsMissingCache(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	cacheDir := filepath.Join(dir, "hashdb-cache")
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{Name: "mirror", Type: "bundle", URL: "https://example.invalid/x.bundle.json", CacheDir: cacheDir},
		{Name: "mirror-shards", Type: "sharded", ManifestURL: "https://example.invalid/manifest.json", CacheDir: cacheDir},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	config.ReloadAll()

	res, err := HashDBVerifySource("mirror")
	if err != nil {
		t.Fatalf("HashDBVerifySource(mirror): %v", err)
	}
	if res.Status != "missing_cache" {
		t.Fatalf("status=%q want missing_cache (msg=%q)", res.Status, res.Message)
	}

	res, err = HashDBVerifySource("mirror-shards")
	if err != nil {
		t.Fatalf("HashDBVerifySource(mirror-shards): %v", err)
	}
	if res.Status != "missing_cache" {
		t.Fatalf("status=%q want missing_cache (msg=%q)", res.Status, res.Message)
	}

	// Confirm the offline verifier never created the cache directory or any
	// files under it.
	if _, statErr := os.Stat(cacheDir); !os.IsNotExist(statErr) {
		t.Fatalf("cache dir should not have been created, stat err=%v", statErr)
	}
}

func TestFormatHashDBVerifyResultRedactsNamePathAndMessage(t *testing.T) {
	line := FormatHashDBVerifyResult(HashDBVerifyResult{
		Name:    "password=name-secret",
		Type:    "bundle",
		Status:  "error",
		Path:    filepath.Join("tmp", "password=path-secret"),
		Message: "open password=message-secret: failed",
	})
	for _, secret := range []string{"name-secret", "path-secret", "message-secret"} {
		if strings.Contains(line, secret) {
			t.Fatalf("formatted verify result leaked %q: %s", secret, line)
		}
	}
	if !strings.Contains(line, "password=[redacted]") {
		t.Fatalf("expected redaction marker in formatted result, got %s", line)
	}
}

func TestHashDBVerifySourceMissingNameAndUnknown(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	if _, err := HashDBVerifySource(""); err == nil {
		t.Fatalf("expected error for empty name")
	}
	if _, err := HashDBVerifySource("does-not-exist"); err == nil {
		t.Fatalf("expected error for unknown source")
	}
}

func TestHashDBVerifyAllSourcesPreservesOrderAndIncludesAll(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	archive := filepath.Join(dir, "archive.bin")
	if err := os.WriteFile(archive, []byte("verify-all"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	bundlePath, pubHex := writeSignedBundleForTest(t, dir, archive, []string{"x"})
	cacheDir := filepath.Join(dir, "hashdb-cache")

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{Name: "local", Type: "bundle", Path: bundlePath, PublicKey: pubHex},
		{Name: "mirror", Type: "bundle", URL: "https://example.invalid/x.bundle.json", CacheDir: cacheDir},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	config.ReloadAll()

	results, err := HashDBVerifyAllSources()
	if err != nil {
		t.Fatalf("HashDBVerifyAllSources: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results)=%d want 2", len(results))
	}
	if results[0].Name != "local" || results[0].Status != "ok" {
		t.Fatalf("results[0]=%+v", results[0])
	}
	if results[1].Name != "mirror" || results[1].Status != "missing_cache" {
		t.Fatalf("results[1]=%+v", results[1])
	}
}
