package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
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
