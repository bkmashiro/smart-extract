package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bkmashiro/smart-extract/internal/config"
)

func seedManageConfig(t *testing.T, cacheDir string) []config.HashDBSource {
	t.Helper()
	sources := []config.HashDBSource{
		{
			Name:      "local-bundle",
			Type:      "",
			Path:      "/tmp/some-local.bundle.json",
			PublicKey: "aa",
		},
		{
			Name:        "mirror-bundle",
			Type:        "bundle",
			URL:         "https://example.com/hashdb/shared.bundle.json.gz",
			Compression: "gzip",
			SHA256:      "deadbeef",
			CacheDir:    cacheDir,
			PublicKey:   "bb",
		},
		{
			Name:        "mirror-shards",
			Type:        "sharded",
			ManifestURL: "https://example.com/hashdb/manifest.json",
			CacheDir:    cacheDir,
			PublicKey:   "cc",
			Disabled:    true,
		},
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = sources
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	config.ReloadAll()
	return sources
}

func TestHashDBListSourcesSummary(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	cacheDir := filepath.Join(dir, "hashdb-cache")
	sources := seedManageConfig(t, cacheDir)

	// Pre-create the cache root for the mirror-bundle source so CacheExists
	// is true for it, but not for the sharded source.
	bundleCache, err := hashDBSourceCacheRoot(sources[1])
	if err != nil {
		t.Fatalf("cache root: %v", err)
	}
	if err := os.MkdirAll(bundleCache, 0o755); err != nil {
		t.Fatalf("mkdir cache: %v", err)
	}

	summaries, err := HashDBListSources()
	if err != nil {
		t.Fatalf("HashDBListSources: %v", err)
	}
	if len(summaries) != 3 {
		t.Fatalf("len(summaries)=%d, want 3: %+v", len(summaries), summaries)
	}

	if summaries[0].Name != "local-bundle" || summaries[0].Type != "bundle" {
		t.Fatalf("local-bundle summary = %+v", summaries[0])
	}
	if summaries[0].Location != "/tmp/some-local.bundle.json" {
		t.Fatalf("local-bundle location = %q", summaries[0].Location)
	}
	if summaries[0].CachePath != "" || summaries[0].CacheExists {
		t.Fatalf("local-bundle should have no cache info: %+v", summaries[0])
	}

	if summaries[1].Name != "mirror-bundle" || summaries[1].Type != "bundle" {
		t.Fatalf("mirror-bundle summary = %+v", summaries[1])
	}
	if summaries[1].Location != "https://example.com/hashdb/shared.bundle.json.gz" {
		t.Fatalf("mirror-bundle location = %q", summaries[1].Location)
	}
	if summaries[1].CachePath != bundleCache {
		t.Fatalf("mirror-bundle cache path = %q want %q", summaries[1].CachePath, bundleCache)
	}
	if !summaries[1].CacheExists {
		t.Fatalf("mirror-bundle CacheExists should be true after MkdirAll")
	}
	if summaries[1].Compression != "gzip" || summaries[1].SHA256 != "deadbeef" {
		t.Fatalf("mirror-bundle compression/sha256 = %q/%q", summaries[1].Compression, summaries[1].SHA256)
	}

	if summaries[2].Name != "mirror-shards" || summaries[2].Type != "sharded" {
		t.Fatalf("mirror-shards summary = %+v", summaries[2])
	}
	if summaries[2].Location != "https://example.com/hashdb/manifest.json" {
		t.Fatalf("mirror-shards location = %q", summaries[2].Location)
	}
	shardCache, err := hashDBSourceCacheRoot(sources[2])
	if err != nil {
		t.Fatalf("cache root: %v", err)
	}
	if summaries[2].CachePath != shardCache {
		t.Fatalf("mirror-shards cache path = %q want %q", summaries[2].CachePath, shardCache)
	}
	if summaries[2].CacheExists {
		t.Fatalf("mirror-shards CacheExists should be false")
	}
	if !summaries[2].Disabled {
		t.Fatalf("mirror-shards Disabled should be true")
	}
}

func TestHashDBClearSourceCacheRemovesNamedHTTPSource(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	cacheDir := filepath.Join(dir, "hashdb-cache")
	sources := seedManageConfig(t, cacheDir)

	bundleCache, err := hashDBSourceCacheRoot(sources[1])
	if err != nil {
		t.Fatalf("cache root: %v", err)
	}
	shardCache, err := hashDBSourceCacheRoot(sources[2])
	if err != nil {
		t.Fatalf("cache root: %v", err)
	}
	if err := os.MkdirAll(bundleCache, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(shardCache, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleCache, "bundle.json"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	removed, existed, err := HashDBClearSourceCache("mirror-bundle")
	if err != nil {
		t.Fatalf("HashDBClearSourceCache: %v", err)
	}
	if removed != bundleCache {
		t.Fatalf("removed = %q, want %q", removed, bundleCache)
	}
	if !existed {
		t.Fatalf("existed should be true before removal")
	}
	if _, err := os.Stat(bundleCache); !os.IsNotExist(err) {
		t.Fatalf("bundleCache should be gone, stat err=%v", err)
	}
	if _, err := os.Stat(shardCache); err != nil {
		t.Fatalf("shardCache should be untouched, err=%v", err)
	}

	// Clearing a missing-cache HTTP source should still succeed with existed=false.
	_, existedAgain, err := HashDBClearSourceCache("mirror-bundle")
	if err != nil {
		t.Fatalf("second clear: %v", err)
	}
	if existedAgain {
		t.Fatalf("existed should be false on second clear")
	}
}

func TestHashDBClearSourceCacheRejectsLocalSource(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	seedManageConfig(t, filepath.Join(dir, "hashdb-cache"))

	if _, _, err := HashDBClearSourceCache("local-bundle"); err == nil {
		t.Fatalf("expected error clearing local-only source")
	}
	if _, _, err := HashDBClearSourceCache("does-not-exist"); err == nil {
		t.Fatalf("expected error for missing source name")
	}
	if _, _, err := HashDBClearSourceCache(""); err == nil {
		t.Fatalf("expected error for empty source name")
	}
}

func TestHashDBSetSourceDisabledTogglesNamedSource(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	cacheDir := filepath.Join(dir, "hashdb-cache")
	seedManageConfig(t, cacheDir)

	// Disable the currently-enabled mirror-bundle source.
	updated, err := HashDBSetSourceDisabled("mirror-bundle", true)
	if err != nil {
		t.Fatalf("HashDBSetSourceDisabled(disable): %v", err)
	}
	if updated.Name != "mirror-bundle" || !updated.Disabled {
		t.Fatalf("returned source = %+v, want Name=mirror-bundle Disabled=true", updated)
	}

	config.ReloadAll()
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.HashDB.Sources) != 3 {
		t.Fatalf("sources len = %d, want 3", len(cfg.HashDB.Sources))
	}
	if cfg.HashDB.Sources[0].Name != "local-bundle" ||
		cfg.HashDB.Sources[1].Name != "mirror-bundle" ||
		cfg.HashDB.Sources[2].Name != "mirror-shards" {
		t.Fatalf("source order changed: %+v", cfg.HashDB.Sources)
	}
	if cfg.HashDB.Sources[0].Disabled {
		t.Fatalf("local-bundle Disabled changed unexpectedly")
	}
	if !cfg.HashDB.Sources[1].Disabled {
		t.Fatalf("mirror-bundle should be disabled in saved config")
	}
	if !cfg.HashDB.Sources[2].Disabled {
		t.Fatalf("mirror-shards Disabled changed unexpectedly")
	}

	// Re-enable the already-disabled mirror-shards source.
	updated, err = HashDBSetSourceDisabled("mirror-shards", false)
	if err != nil {
		t.Fatalf("HashDBSetSourceDisabled(enable): %v", err)
	}
	if updated.Disabled {
		t.Fatalf("returned source should be enabled, got %+v", updated)
	}

	config.ReloadAll()
	cfg, err = config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.HashDB.Sources[2].Disabled {
		t.Fatalf("mirror-shards should now be enabled")
	}
}

func TestHashDBSetSourceDisabledIdempotent(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	cacheDir := filepath.Join(dir, "hashdb-cache")
	seedManageConfig(t, cacheDir)

	// mirror-shards is already disabled; disabling again must succeed.
	updated, err := HashDBSetSourceDisabled("mirror-shards", true)
	if err != nil {
		t.Fatalf("idempotent disable failed: %v", err)
	}
	if !updated.Disabled {
		t.Fatalf("expected Disabled=true, got %+v", updated)
	}

	// local-bundle is already enabled; enabling again must succeed.
	updated, err = HashDBSetSourceDisabled("local-bundle", false)
	if err != nil {
		t.Fatalf("idempotent enable failed: %v", err)
	}
	if updated.Disabled {
		t.Fatalf("expected Disabled=false, got %+v", updated)
	}
}

func TestHashDBSetSourceDisabledRejectsEmptyAndMissing(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	seedManageConfig(t, filepath.Join(dir, "hashdb-cache"))

	if _, err := HashDBSetSourceDisabled("", true); err == nil {
		t.Fatalf("expected error for empty name")
	}
	if _, err := HashDBSetSourceDisabled("does-not-exist", true); err == nil {
		t.Fatalf("expected error for missing source")
	}
}

func TestHashDBSetSourceDisabledPreservesOtherFields(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	cacheDir := filepath.Join(dir, "hashdb-cache")
	seedManageConfig(t, cacheDir)

	if _, err := HashDBSetSourceDisabled("mirror-bundle", true); err != nil {
		t.Fatalf("disable: %v", err)
	}

	config.ReloadAll()
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	got := cfg.HashDB.Sources[1]
	if got.Name != "mirror-bundle" || got.Type != "bundle" ||
		got.URL != "https://example.com/hashdb/shared.bundle.json.gz" ||
		got.Compression != "gzip" || got.SHA256 != "deadbeef" ||
		got.CacheDir != cacheDir || got.PublicKey != "bb" {
		t.Fatalf("non-Disabled fields modified: %+v", got)
	}
}

func TestHashDBClearAllSourceCachesDeduplicates(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()

	cacheDir := filepath.Join(dir, "hashdb-cache")
	// Two HTTP sources sharing the same URL → same cache root → must dedup.
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{Name: "local-only", Type: "bundle", Path: "/tmp/local.bundle.json"},
		{Name: "mirror-a", Type: "bundle", URL: "https://example.com/a.bundle.json", CacheDir: cacheDir},
		{Name: "mirror-a-dup", Type: "bundle", URL: "https://example.com/a.bundle.json", CacheDir: cacheDir},
		{Name: "mirror-b", Type: "sharded", ManifestURL: "https://example.com/b/manifest.json", CacheDir: cacheDir},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	config.ReloadAll()

	rootA, err := hashDBSourceCacheRoot(cfg.HashDB.Sources[1])
	if err != nil {
		t.Fatalf("cache root: %v", err)
	}
	rootB, err := hashDBSourceCacheRoot(cfg.HashDB.Sources[3])
	if err != nil {
		t.Fatalf("cache root: %v", err)
	}
	if err := os.MkdirAll(rootA, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(rootB, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	removals, err := HashDBClearAllSourceCaches()
	if err != nil {
		t.Fatalf("HashDBClearAllSourceCaches: %v", err)
	}
	if len(removals) != 2 {
		t.Fatalf("len(removals)=%d, want 2 (dedup): %+v", len(removals), removals)
	}
	if removals[0].Name != "mirror-a" || removals[0].Path != rootA || !removals[0].Existed {
		t.Fatalf("removals[0] = %+v", removals[0])
	}
	if removals[1].Name != "mirror-b" || removals[1].Path != rootB || !removals[1].Existed {
		t.Fatalf("removals[1] = %+v", removals[1])
	}
	if _, err := os.Stat(rootA); !os.IsNotExist(err) {
		t.Fatalf("rootA should be gone, err=%v", err)
	}
	if _, err := os.Stat(rootB); !os.IsNotExist(err) {
		t.Fatalf("rootB should be gone, err=%v", err)
	}
}
