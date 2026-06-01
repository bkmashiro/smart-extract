package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bkmashiro/smart-extract/internal/config"
	"github.com/bkmashiro/smart-extract/internal/hashdb"
)

// makeContributionTempArchive writes a fake archive file with given bytes and
// returns its absolute path. The contribution path uses real ArchiveHash bytes
// so lookup can prove the contribution worked.
func makeContributionTempArchive(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write archive %s: %v", name, err)
	}
	return p
}

func TestArchiveSuccessRecorderModeOffCreatesNoContributionFiles(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	st, err := openLearningStore(&config.Learned{})
	if err != nil {
		t.Fatalf("openLearningStore: %v", err)
	}
	defer st.Close()

	archive := makeContributionTempArchive(t, dir, "off.zip", "off-mode-bytes")

	keyPath := filepath.Join(dir, "key.json")
	bundlePath := filepath.Join(dir, "bundle.json")

	cfg := &config.Config{
		HashDB: config.HashDBConfig{
			// Contribute left empty => off.
			Contribution: config.HashDBContribution{
				Type:    "bundle",
				Path:    bundlePath,
				KeyPath: keyPath,
				Source:  "local-private",
			},
		},
	}

	recorder := makeArchiveSuccessRecorder(st, cfg)
	recorder(archive, "any-pass")

	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("key file should not exist when contribute off, stat err=%v", err)
	}
	if _, err := os.Stat(bundlePath); !os.IsNotExist(err) {
		t.Fatalf("bundle file should not exist when contribute off, stat err=%v", err)
	}

	// Local SQLite learning still proceeds.
	pw, ok, err := st.LookupExact(context.Background(), "off.zip")
	if err != nil || !ok || pw != "any-pass" {
		t.Fatalf("LookupExact=(%q,%v,%v); want any-pass,true,nil", pw, ok, err)
	}
}

func TestArchiveSuccessRecorderAutoBundleContributes(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	st, err := openLearningStore(&config.Learned{})
	if err != nil {
		t.Fatalf("openLearningStore: %v", err)
	}
	defer st.Close()

	archive := makeContributionTempArchive(t, dir, "contrib.zip", "auto-bundle-bytes")

	keyPath := filepath.Join(dir, "subdir", "key.json")
	bundlePath := filepath.Join(dir, "subdir", "bundle.json")
	cfg := &config.Config{
		HashDB: config.HashDBConfig{
			Contribute: "auto",
			Contribution: config.HashDBContribution{
				Type:    "bundle",
				Path:    bundlePath,
				KeyPath: keyPath,
				Source:  "local-private",
			},
		},
	}

	recorder := makeArchiveSuccessRecorder(st, cfg)
	recorder(archive, "contributed-pass")

	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file missing after auto contribution: %v", err)
	}
	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatalf("bundle file missing after auto contribution: %v", err)
	}

	// Look up via FileSource to prove the contribution is consumable.
	pubKey, _, err := hashdb.LoadOrCreateSigningKey(context.Background(), keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey: %v", err)
	}
	pwds, err := hashdb.LookupFileSource(context.Background(), hashdb.FileSource{
		Name: "contrib",
		Path: bundlePath,
		// hex-encode the public key for the pin
		PublicKey: hexEncodeBytes(pubKey),
	}, archive)
	if err != nil {
		t.Fatalf("LookupFileSource: %v", err)
	}
	if len(pwds) != 1 || pwds[0] != "contributed-pass" {
		t.Fatalf("LookupFileSource = %#v, want [contributed-pass]", pwds)
	}
}

func TestArchiveSuccessRecorderAutoShardedContributes(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	st, err := openLearningStore(&config.Learned{})
	if err != nil {
		t.Fatalf("openLearningStore: %v", err)
	}
	defer st.Close()

	archive := makeContributionTempArchive(t, dir, "sharded.zip", "auto-sharded-bytes")

	keyPath := filepath.Join(dir, "skey.json")
	baseDir := filepath.Join(dir, "shardroot")
	cfg := &config.Config{
		HashDB: config.HashDBConfig{
			Contribute: "auto",
			Contribution: config.HashDBContribution{
				Type:              "sharded",
				BaseDir:           baseDir,
				KeyPath:           keyPath,
				Source:            "local-private",
				ShardPrefixLength: 2,
			},
		},
	}

	recorder := makeArchiveSuccessRecorder(st, cfg)
	recorder(archive, "sharded-contribution")

	if _, err := os.Stat(filepath.Join(baseDir, "manifest.json")); err != nil {
		t.Fatalf("manifest.json missing after auto contribution: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("signing key missing after auto contribution: %v", err)
	}

	pubKey, _, err := hashdb.LoadOrCreateSigningKey(context.Background(), keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey: %v", err)
	}
	pwds, err := hashdb.LookupShardedFileSource(context.Background(), hashdb.ShardedFileSource{
		Name:      "sharded",
		BaseDir:   baseDir,
		PublicKey: hexEncodeBytes(pubKey),
	}, archive)
	if err != nil {
		t.Fatalf("LookupShardedFileSource: %v", err)
	}
	if len(pwds) != 1 || pwds[0] != "sharded-contribution" {
		t.Fatalf("LookupShardedFileSource = %#v, want [sharded-contribution]", pwds)
	}
}

func TestArchiveSuccessRecorderEmptyPasswordSkipsContribution(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	st, err := openLearningStore(&config.Learned{})
	if err != nil {
		t.Fatalf("openLearningStore: %v", err)
	}
	defer st.Close()

	archive := makeContributionTempArchive(t, dir, "empty.zip", "empty-pw-bytes")
	keyPath := filepath.Join(dir, "key.json")
	bundlePath := filepath.Join(dir, "bundle.json")
	cfg := &config.Config{
		HashDB: config.HashDBConfig{
			Contribute: "auto",
			Contribution: config.HashDBContribution{
				Type:    "bundle",
				Path:    bundlePath,
				KeyPath: keyPath,
			},
		},
	}

	recorder := makeArchiveSuccessRecorder(st, cfg)
	recorder(archive, "")

	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("key file should not exist for empty password; stat=%v", err)
	}
	if _, err := os.Stat(bundlePath); !os.IsNotExist(err) {
		t.Fatalf("bundle file should not exist for empty password; stat=%v", err)
	}
}

func TestArchiveSuccessRecorderContributionFailureSoftAndLearningProceeds(t *testing.T) {
	dir := t.TempDir()
	config.Init(dir)
	st, err := openLearningStore(&config.Learned{})
	if err != nil {
		t.Fatalf("openLearningStore: %v", err)
	}
	defer st.Close()

	archive := makeContributionTempArchive(t, dir, "broken.zip", "soft-fail-bytes")

	// Write a bogus signing key file so LoadOrCreateSigningKey fails.
	keyPath := filepath.Join(dir, "key.json")
	if err := os.WriteFile(keyPath, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write bogus key: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	cfg := &config.Config{
		HashDB: config.HashDBConfig{
			Contribute: "auto",
			Contribution: config.HashDBContribution{
				Type:    "bundle",
				Path:    bundlePath,
				KeyPath: keyPath,
			},
		},
	}

	// Should not panic, should not block local learning.
	recorder := makeArchiveSuccessRecorder(st, cfg)
	recorder(archive, "soft-fail-pass")

	pw, ok, err := st.LookupExact(context.Background(), "broken.zip")
	if err != nil || !ok || pw != "soft-fail-pass" {
		t.Fatalf("LookupExact=(%q,%v,%v); want soft-fail-pass,true,nil", pw, ok, err)
	}
	if _, err := os.Stat(bundlePath); !os.IsNotExist(err) {
		t.Fatalf("bundle file should not exist after soft failure; stat=%v", err)
	}
}

// hexEncodeBytes returns the lowercase hex encoding of b without pulling in a
// separate import in the consuming test.
func hexEncodeBytes(b []byte) string {
	const hexchars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexchars[v>>4]
		out[i*2+1] = hexchars[v&0x0f]
	}
	return string(out)
}
