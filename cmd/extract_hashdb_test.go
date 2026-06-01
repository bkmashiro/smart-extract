package cmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/bkmashiro/smart-extract/internal/config"
	"github.com/bkmashiro/smart-extract/internal/hashdb"
)

// writeSignedBundleForTest builds and writes a signed bundle binding archive
// bytes to passwords. Returns bundle path and hex public key.
func writeSignedBundleForTest(t *testing.T, dir, archivePath string, passwords []string) (string, string) {
	t.Helper()

	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	digest := hashdb.ArchiveHash(f)
	f.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	var recs []hashdb.Record
	for _, pw := range passwords {
		r, err := hashdb.BuildRecord(digest, pw, "test")
		if err != nil {
			t.Fatalf("BuildRecord: %v", err)
		}
		recs = append(recs, r)
	}
	signed, err := hashdb.SignBundle(hashdb.Bundle{Source: "test", Records: recs}, priv)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	data, err := hashdb.MarshalSignedBundle(signed)
	if err != nil {
		t.Fatalf("MarshalSignedBundle: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, data, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return bundlePath, hex.EncodeToString(pub)
}

func TestPasswordProviderUsesHashDBLookupWhenModeEnabled(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secret.zip")
	if err := os.WriteFile(archivePath, []byte("hashdb-flow-bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	bundlePath, pubHex := writeSignedBundleForTest(t, dir, archivePath, []string{"hashdb-found"})

	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
		HashDB: config.HashDBConfig{
			Mode: "lookup",
			Sources: []config.HashDBSource{
				{Name: "test", Path: bundlePath, PublicKey: pubHex},
			},
		},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider(archivePath, filepath.Base(archivePath), cfg, learned)
	provider.candidateSource = fakeCandidateSource{}

	got, err := provider.getPasswords(archivePath)
	if err != nil {
		t.Fatalf("getPasswords: %v", err)
	}
	if !containsString(got, "hashdb-found") {
		t.Fatalf("expected candidates to contain hashdb-found, got %#v", got)
	}
}

func TestPasswordProviderUsesHashDBWhenSQLiteCandidateSourceUnavailable(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secret.zip")
	if err := os.WriteFile(archivePath, []byte("hashdb-legacy-flow-bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	bundlePath, pubHex := writeSignedBundleForTest(t, dir, archivePath, []string{"hashdb-legacy-found"})

	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
		HashDB: config.HashDBConfig{
			Mode: "lookup",
			Sources: []config.HashDBSource{
				{Name: "test", Path: bundlePath, PublicKey: pubHex},
			},
		},
	}
	learned := &config.Learned{
		Exact:            map[string]string{},
		PersonStats:      map[string]map[string]*config.BetaStats{},
		PersonFilenames:  map[string][]string{},
		PasswordHitCount: map[string]int{},
	}
	provider := newPasswordProvider(archivePath, filepath.Base(archivePath), cfg, learned)

	got, err := provider.getPasswords(archivePath)
	if err != nil {
		t.Fatalf("getPasswords: %v", err)
	}
	if !containsString(got, "hashdb-legacy-found") {
		t.Fatalf("expected candidates to contain hashdb-legacy-found, got %#v", got)
	}
}

func TestPasswordProviderDownloadsAndCachesHTTPHashDBBundle(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secret.zip")
	if err := os.WriteFile(archivePath, []byte("hashdb-http-bundle-bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	bundlePath, pubHex := writeSignedBundleForTest(t, dir, archivePath, []string{"hashdb-http-found"})
	bundleData, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bundleData)
	}))
	defer server.Close()

	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
		HashDB: config.HashDBConfig{
			Mode: "lookup",
			Sources: []config.HashDBSource{
				{Name: "http-bundle", URL: server.URL + "/bundle.json", CacheDir: filepath.Join(dir, "cache"), PublicKey: pubHex},
			},
		},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider(archivePath, filepath.Base(archivePath), cfg, learned)

	for i := 0; i < 2; i++ {
		got := provider.hashDBPasswords(context.Background(), archivePath)
		if len(got) != 1 || got[0] != "hashdb-http-found" {
			t.Fatalf("lookup %d hashDBPasswords = %#v, want [hashdb-http-found]", i+1, got)
		}
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("HTTP bundle requests = %d, want 1 cached download", got)
	}
	cached, err := filepath.Glob(filepath.Join(dir, "cache", "*", "bundle.json"))
	if err != nil || len(cached) != 1 {
		t.Fatalf("expected one cached bundle file, got %v err=%v", cached, err)
	}
}

func TestPasswordProviderSkipsHashDBWhenModeOff(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secret.zip")
	if err := os.WriteFile(archivePath, []byte("hashdb-off-bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	bundlePath, pubHex := writeSignedBundleForTest(t, dir, archivePath, []string{"hashdb-should-not-appear"})

	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
		HashDB: config.HashDBConfig{
			// Mode left "" — default off
			Sources: []config.HashDBSource{
				{Name: "test", Path: bundlePath, PublicKey: pubHex},
			},
		},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider(archivePath, filepath.Base(archivePath), cfg, learned)
	provider.candidateSource = fakeCandidateSource{}

	got, err := provider.getPasswords(archivePath)
	if err != nil {
		t.Fatalf("getPasswords: %v", err)
	}
	if containsString(got, "hashdb-should-not-appear") {
		t.Fatalf("HashDB candidate leaked when mode off: %#v", got)
	}
}

func TestPasswordProviderSkipsDisabledHashDBSource(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secret.zip")
	if err := os.WriteFile(archivePath, []byte("hashdb-disabled-bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	bundlePath, pubHex := writeSignedBundleForTest(t, dir, archivePath, []string{"hashdb-disabled-pass"})

	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
		HashDB: config.HashDBConfig{
			Mode: "lookup",
			Sources: []config.HashDBSource{
				{Name: "test", Path: bundlePath, PublicKey: pubHex, Disabled: true},
			},
		},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider(archivePath, filepath.Base(archivePath), cfg, learned)
	provider.candidateSource = fakeCandidateSource{}

	got, err := provider.getPasswords(archivePath)
	if err != nil {
		t.Fatalf("getPasswords: %v", err)
	}
	if containsString(got, "hashdb-disabled-pass") {
		t.Fatalf("disabled HashDB source leaked candidate: %#v", got)
	}
}

// writeShardedSourceForTest builds and writes a sharded HashDB source (shards
// + manifest) under baseDir binding archive bytes to passwords. Returns the
// base dir and hex public key.
func writeShardedSourceForTest(t *testing.T, baseDir, archivePath string, passwords []string) (string, string) {
	t.Helper()

	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	digest := hashdb.ArchiveHash(f)
	f.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	var recs []hashdb.Record
	for _, pw := range passwords {
		r, err := hashdb.BuildRecord(digest, pw, "test")
		if err != nil {
			t.Fatalf("BuildRecord: %v", err)
		}
		recs = append(recs, r)
	}
	manifest, err := hashdb.BuildShardedSourceFromRecords(context.Background(), baseDir, "test", recs, priv, 2)
	if err != nil {
		t.Fatalf("BuildShardedSourceFromRecords: %v", err)
	}
	data, err := hashdb.MarshalManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "manifest.json"), data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return baseDir, hex.EncodeToString(pub)
}

func TestPasswordProviderUsesShardedHashDBSource(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secret.zip")
	if err := os.WriteFile(archivePath, []byte("hashdb-sharded-bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	shardBase := filepath.Join(dir, "shardroot")
	if err := os.MkdirAll(shardBase, 0o755); err != nil {
		t.Fatalf("mkdir shardroot: %v", err)
	}
	_, pubHex := writeShardedSourceForTest(t, shardBase, archivePath, []string{"sharded-found"})

	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
		HashDB: config.HashDBConfig{
			Mode: "lookup",
			Sources: []config.HashDBSource{
				{Name: "sharded", Type: "sharded", BaseDir: shardBase, PublicKey: pubHex},
			},
		},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider(archivePath, filepath.Base(archivePath), cfg, learned)
	provider.candidateSource = fakeCandidateSource{}

	got, err := provider.getPasswords(archivePath)
	if err != nil {
		t.Fatalf("getPasswords: %v", err)
	}
	if !containsString(got, "sharded-found") {
		t.Fatalf("expected candidates to contain sharded-found, got %#v", got)
	}
	// Sharded candidate must come before the static fallback "fallback-pass".
	idxShard, idxFallback := -1, -1
	for i, pw := range got {
		if idxShard < 0 && pw == "sharded-found" {
			idxShard = i
		}
		if idxFallback < 0 && pw == "fallback-pass" {
			idxFallback = i
		}
	}
	if idxShard < 0 || idxFallback < 0 || idxShard >= idxFallback {
		t.Fatalf("expected sharded-found before fallback-pass; got %#v (idxShard=%d idxFallback=%d)", got, idxShard, idxFallback)
	}
}

func TestPasswordProviderDownloadsOnlyMatchingHTTPHashDBShard(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secret.zip")
	if err := os.WriteFile(archivePath, []byte("hashdb-http-sharded-bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	shardBase := filepath.Join(dir, "sharded-src")
	if err := os.MkdirAll(shardBase, 0o755); err != nil {
		t.Fatalf("mkdir sharded source: %v", err)
	}
	_, pubHex := writeShardedSourceForTest(t, shardBase, archivePath, []string{"http-sharded-found"})
	manifestData, err := os.ReadFile(filepath.Join(shardBase, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifestRequests, shardRequests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manifest.json":
			atomic.AddInt32(&manifestRequests, 1)
			_, _ = w.Write(manifestData)
		default:
			atomic.AddInt32(&shardRequests, 1)
			http.ServeFile(w, r, filepath.Join(shardBase, r.URL.Path))
		}
	}))
	defer server.Close()

	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
		HashDB: config.HashDBConfig{
			Mode: "lookup",
			Sources: []config.HashDBSource{
				{Name: "http-sharded", Type: "sharded", ManifestURL: server.URL + "/manifest.json", CacheDir: filepath.Join(dir, "cache"), PublicKey: pubHex},
			},
		},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider(archivePath, filepath.Base(archivePath), cfg, learned)

	for i := 0; i < 2; i++ {
		got := provider.hashDBPasswords(context.Background(), archivePath)
		if len(got) != 1 || got[0] != "http-sharded-found" {
			t.Fatalf("lookup %d hashDBPasswords = %#v, want [http-sharded-found]", i+1, got)
		}
	}
	if got := atomic.LoadInt32(&manifestRequests); got != 1 {
		t.Fatalf("manifest requests = %d, want 1 cached download", got)
	}
	if got := atomic.LoadInt32(&shardRequests); got != 1 {
		t.Fatalf("shard requests = %d, want 1 cached download", got)
	}
	cachedManifest, err := filepath.Glob(filepath.Join(dir, "cache", "*", "manifest.json"))
	if err != nil || len(cachedManifest) != 1 {
		t.Fatalf("expected one cached manifest, got %v err=%v", cachedManifest, err)
	}
	cachedShards, err := filepath.Glob(filepath.Join(dir, "cache", "*", "shards", "*.json"))
	if err != nil || len(cachedShards) != 1 {
		t.Fatalf("expected one cached matching shard, got %v err=%v", cachedShards, err)
	}
}

func TestPasswordProviderUsesExplicitManifestPathForShardedSource(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secret.zip")
	if err := os.WriteFile(archivePath, []byte("hashdb-sharded-manifest-bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	shardBase := filepath.Join(dir, "shardroot")
	if err := os.MkdirAll(shardBase, 0o755); err != nil {
		t.Fatalf("mkdir shardroot: %v", err)
	}
	_, pubHex := writeShardedSourceForTest(t, shardBase, archivePath, []string{"sharded-manifest-found"})
	// Move the manifest to a non-default location.
	otherManifest := filepath.Join(dir, "other-manifest.json")
	if err := os.Rename(filepath.Join(shardBase, "manifest.json"), otherManifest); err != nil {
		t.Fatalf("rename manifest: %v", err)
	}

	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
		HashDB: config.HashDBConfig{
			Mode: "lookup",
			Sources: []config.HashDBSource{
				{Name: "sharded", Type: "sharded", BaseDir: shardBase, ManifestPath: otherManifest, PublicKey: pubHex},
			},
		},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider(archivePath, filepath.Base(archivePath), cfg, learned)
	provider.candidateSource = fakeCandidateSource{}

	got, err := provider.getPasswords(archivePath)
	if err != nil {
		t.Fatalf("getPasswords: %v", err)
	}
	if !containsString(got, "sharded-manifest-found") {
		t.Fatalf("expected candidates to contain sharded-manifest-found, got %#v", got)
	}
}

func TestPasswordProviderUnknownHashDBSourceTypeDoesNotAbort(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secret.zip")
	if err := os.WriteFile(archivePath, []byte("hashdb-unknown-type-bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
		HashDB: config.HashDBConfig{
			Mode: "lookup",
			Sources: []config.HashDBSource{
				{Name: "exotic", Type: "from-the-future", Path: filepath.Join(dir, "ignored.json")},
			},
		},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider(archivePath, filepath.Base(archivePath), cfg, learned)
	provider.candidateSource = fakeCandidateSource{}

	got, err := provider.getPasswords(archivePath)
	if err != nil {
		t.Fatalf("getPasswords: %v", err)
	}
	if !containsString(got, "fallback-pass") {
		t.Fatalf("expected fallback to remain when HashDB source has unknown type, got %#v", got)
	}
}

func TestPasswordProviderHashDBSourceOrderingAndDedupe(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secret.zip")
	if err := os.WriteFile(archivePath, []byte("hashdb-ordering-bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	// Bundle source contributes [shared, only-bundle].
	bundlePath, bundlePub := writeSignedBundleForTest(t, dir, archivePath, []string{"shared", "only-bundle"})

	// Sharded source contributes [only-sharded, shared].
	shardBase := filepath.Join(dir, "shardroot")
	if err := os.MkdirAll(shardBase, 0o755); err != nil {
		t.Fatalf("mkdir shardroot: %v", err)
	}
	_, shardPub := writeShardedSourceForTest(t, shardBase, archivePath, []string{"only-sharded", "shared"})

	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
		HashDB: config.HashDBConfig{
			Mode: "lookup",
			Sources: []config.HashDBSource{
				{Name: "bundle", Path: bundlePath, PublicKey: bundlePub},
				{Name: "sharded", Type: "sharded", BaseDir: shardBase, PublicKey: shardPub},
			},
		},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider(archivePath, filepath.Base(archivePath), cfg, learned)

	got := provider.hashDBPasswords(context.Background(), archivePath)
	want := []string{"shared", "only-bundle", "only-sharded"}
	if len(got) != len(want) {
		t.Fatalf("hashDBPasswords = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("hashDBPasswords[%d] = %q, want %q (full %#v)", i, got[i], want[i], got)
		}
	}
}

func TestPasswordProviderHashDBFailureDoesNotAbort(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secret.zip")
	if err := os.WriteFile(archivePath, []byte("hashdb-error-bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
		HashDB: config.HashDBConfig{
			Mode: "lookup",
			Sources: []config.HashDBSource{
				// Point to a nonexistent bundle file — must not abort lookup.
				{Name: "broken", Path: filepath.Join(dir, "missing.json")},
			},
		},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider(archivePath, filepath.Base(archivePath), cfg, learned)
	provider.candidateSource = fakeCandidateSource{}

	got, err := provider.getPasswords(archivePath)
	if err != nil {
		t.Fatalf("getPasswords: %v", err)
	}
	if !containsString(got, "fallback-pass") {
		t.Fatalf("expected fallback to remain when HashDB source fails, got %#v", got)
	}
}

// gzipBytes returns gzip(src) using stdlib compress/gzip.
func gzipBytes(t *testing.T, src []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(src); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func TestPasswordProviderDownloadsAndCachesCompressedHTTPHashDBBundle(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secret.zip")
	if err := os.WriteFile(archivePath, []byte("hashdb-compressed-bundle-bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	bundlePath, pubHex := writeSignedBundleForTest(t, dir, archivePath, []string{"hashdb-compressed-found"})
	bundleData, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	compressed := gzipBytes(t, bundleData)
	sum := sha256.Sum256(compressed)
	compressedSha := hex.EncodeToString(sum[:])

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(compressed)
	}))
	defer server.Close()

	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
		HashDB: config.HashDBConfig{
			Mode: "lookup",
			Sources: []config.HashDBSource{
				{
					Name:        "compressed-bundle",
					URL:         server.URL + "/bundle.json.gz",
					CacheDir:    filepath.Join(dir, "cache"),
					PublicKey:   pubHex,
					Compression: "gzip",
					SHA256:      compressedSha,
				},
			},
		},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider(archivePath, filepath.Base(archivePath), cfg, learned)

	for i := 0; i < 2; i++ {
		got := provider.hashDBPasswords(context.Background(), archivePath)
		if len(got) != 1 || got[0] != "hashdb-compressed-found" {
			t.Fatalf("lookup %d hashDBPasswords = %#v, want [hashdb-compressed-found]", i+1, got)
		}
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("HTTP bundle requests = %d, want 1 cached download", got)
	}
	cached, err := filepath.Glob(filepath.Join(dir, "cache", "*", "bundle.json"))
	if err != nil || len(cached) != 1 {
		t.Fatalf("expected one cached bundle file, got %v err=%v", cached, err)
	}
	cachedData, err := os.ReadFile(cached[0])
	if err != nil {
		t.Fatalf("read cached: %v", err)
	}
	if !bytes.Equal(cachedData, bundleData) {
		t.Fatalf("cached bundle bytes differ from decompressed bundle (len cached=%d want=%d)", len(cachedData), len(bundleData))
	}
}

func TestPasswordProviderRejectsHTTPHashDBBundleSHA256Mismatch(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secret.zip")
	if err := os.WriteFile(archivePath, []byte("hashdb-sha-mismatch-bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	bundlePath, pubHex := writeSignedBundleForTest(t, dir, archivePath, []string{"sha-mismatch-pw"})
	bundleData, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bundleData)
	}))
	defer server.Close()

	wrongSha := hex.EncodeToString(make([]byte, 32)) // all-zero hash, won't match
	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
		HashDB: config.HashDBConfig{
			Mode: "lookup",
			Sources: []config.HashDBSource{
				{
					Name:      "sha-mismatch",
					URL:       server.URL + "/bundle.json",
					CacheDir:  filepath.Join(dir, "cache"),
					PublicKey: pubHex,
					SHA256:    wrongSha,
				},
			},
		},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider(archivePath, filepath.Base(archivePath), cfg, learned)

	got := provider.hashDBPasswords(context.Background(), archivePath)
	if containsString(got, "sha-mismatch-pw") {
		t.Fatalf("expected sha mismatch to suppress password, got %#v", got)
	}
	cached, _ := filepath.Glob(filepath.Join(dir, "cache", "*", "bundle.json"))
	if len(cached) != 0 {
		t.Fatalf("expected no cache file installed on sha mismatch, got %v", cached)
	}
}

func TestPasswordProviderDownloadsCompressedHTTPHashDBShard(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secret.zip")
	if err := os.WriteFile(archivePath, []byte("hashdb-http-compressed-shard-bytes"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	shardBase := filepath.Join(dir, "sharded-src")
	if err := os.MkdirAll(shardBase, 0o755); err != nil {
		t.Fatalf("mkdir sharded source: %v", err)
	}
	_, pubHex := writeShardedSourceForTest(t, shardBase, archivePath, []string{"http-compressed-shard-found"})

	// Rewrite each shard to gzip form and update the manifest with the
	// compressed bytes' sha256 plus compression: "gzip".
	manifestData, err := os.ReadFile(filepath.Join(shardBase, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest hashdb.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	for prefix, shard := range manifest.Shards {
		raw, err := os.ReadFile(filepath.Join(shardBase, shard.Path))
		if err != nil {
			t.Fatalf("read shard: %v", err)
		}
		// Delete the uncompressed shard so any request for it would 404.
		_ = os.Remove(filepath.Join(shardBase, shard.Path))
		compressed := gzipBytes(t, raw)
		compressedRel := shard.Path + ".gz"
		if err := os.WriteFile(filepath.Join(shardBase, compressedRel), compressed, 0o644); err != nil {
			t.Fatalf("write compressed shard: %v", err)
		}
		sum := sha256.Sum256(compressed)
		shard.Path = compressedRel
		shard.SHA256 = hex.EncodeToString(sum[:])
		shard.Compression = "gzip"
		manifest.Shards[prefix] = shard
	}
	rewritten, err := hashdb.MarshalManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(shardBase, "manifest.json"), rewritten, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	manifestData = rewritten

	var manifestRequests, shardRequests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manifest.json":
			atomic.AddInt32(&manifestRequests, 1)
			_, _ = w.Write(manifestData)
		default:
			atomic.AddInt32(&shardRequests, 1)
			http.ServeFile(w, r, filepath.Join(shardBase, r.URL.Path))
		}
	}))
	defer server.Close()

	cfg := &config.Config{
		People:            map[string]*config.Person{},
		FallbackPasswords: []string{"fallback-pass"},
		HashDB: config.HashDBConfig{
			Mode: "lookup",
			Sources: []config.HashDBSource{
				{Name: "http-compressed-sharded", Type: "sharded", ManifestURL: server.URL + "/manifest.json", CacheDir: filepath.Join(dir, "cache"), PublicKey: pubHex},
			},
		},
	}
	learned := &config.Learned{
		Exact:           map[string]string{},
		PersonStats:     map[string]map[string]*config.BetaStats{},
		PersonFilenames: map[string][]string{},
	}
	provider := newPasswordProvider(archivePath, filepath.Base(archivePath), cfg, learned)

	for i := 0; i < 2; i++ {
		got := provider.hashDBPasswords(context.Background(), archivePath)
		if len(got) != 1 || got[0] != "http-compressed-shard-found" {
			t.Fatalf("lookup %d hashDBPasswords = %#v, want [http-compressed-shard-found]", i+1, got)
		}
	}
	if got := atomic.LoadInt32(&manifestRequests); got != 1 {
		t.Fatalf("manifest requests = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&shardRequests); got != 1 {
		t.Fatalf("compressed shard requests = %d, want 1", got)
	}
	cachedShards, err := filepath.Glob(filepath.Join(dir, "cache", "*", "shards", "*.json.gz"))
	if err != nil || len(cachedShards) != 1 {
		t.Fatalf("expected one cached compressed-named shard, got %v err=%v", cachedShards, err)
	}
	cachedData, err := os.ReadFile(cachedShards[0])
	if err != nil {
		t.Fatalf("read cached shard: %v", err)
	}
	// Cached shard must be the decompressed signed bundle JSON (begins with '{').
	if len(cachedData) == 0 || cachedData[0] != '{' {
		t.Fatalf("cached shard appears compressed (first byte %x); expected decompressed JSON", cachedData[:min(len(cachedData), 4)])
	}
}
