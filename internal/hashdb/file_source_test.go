package hashdb

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper: build a signed bundle on disk binding the given archive bytes to the
// given passwords. Returns the bundle path, the archive path, and the hex
// public key.
func writeSignedBundleFile(t *testing.T, dir string, archiveBytes []byte, passwords []string) (bundlePath, archivePath, pubHex string, priv ed25519.PrivateKey) {
	t.Helper()
	archivePath = filepath.Join(dir, "archive.zip")
	if err := os.WriteFile(archivePath, archiveBytes, 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	digest := ArchiveHash(f)
	f.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var records []Record
	for _, pw := range passwords {
		rec, err := BuildRecord(digest, pw, "src")
		if err != nil {
			t.Fatalf("BuildRecord: %v", err)
		}
		records = append(records, rec)
	}
	bundle := Bundle{Source: "test", Records: records}
	signed, err := SignBundle(bundle, priv)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	data, err := MarshalSignedBundle(signed)
	if err != nil {
		t.Fatalf("MarshalSignedBundle: %v", err)
	}
	bundlePath = filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, data, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return bundlePath, archivePath, hex.EncodeToString(pub), priv
}

func TestLookupFileSourceReturnsDecryptedPasswords(t *testing.T) {
	dir := t.TempDir()
	bundlePath, archivePath, pubHex, _ := writeSignedBundleFile(t, dir, []byte("archive-bytes-A"), []string{"pw1", "pw2"})

	got, err := LookupFileSource(context.Background(), FileSource{
		Name:      "test",
		Path:      bundlePath,
		PublicKey: pubHex,
	}, archivePath)
	if err != nil {
		t.Fatalf("LookupFileSource: %v", err)
	}
	want := []string{"pw1", "pw2"}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d; got=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLookupFileSourceDedupesPreservingOrder(t *testing.T) {
	dir := t.TempDir()
	bundlePath, archivePath, pubHex, _ := writeSignedBundleFile(t, dir, []byte("archive-bytes-dup"), []string{"pw1", "pw2", "pw1"})

	got, err := LookupFileSource(context.Background(), FileSource{Path: bundlePath, PublicKey: pubHex}, archivePath)
	if err != nil {
		t.Fatalf("LookupFileSource: %v", err)
	}
	want := []string{"pw1", "pw2"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got = %v, want %v", got, want)
	}
}

func TestLookupFileSourceReturnsEmptyWhenNoArchiveMatch(t *testing.T) {
	dir := t.TempDir()
	// Build bundle for one archive...
	bundlePath, _, pubHex, _ := writeSignedBundleFile(t, dir, []byte("archive-bytes-A"), []string{"pw1"})
	// ...but look up a different archive.
	otherArchive := filepath.Join(dir, "other.zip")
	if err := os.WriteFile(otherArchive, []byte("totally-different-content"), 0o644); err != nil {
		t.Fatalf("write other: %v", err)
	}

	got, err := LookupFileSource(context.Background(), FileSource{Path: bundlePath, PublicKey: pubHex}, otherArchive)
	if err != nil {
		t.Fatalf("LookupFileSource: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no passwords, got %v", got)
	}
}

func TestLookupFileSourceRejectsMismatchedPublicKey(t *testing.T) {
	dir := t.TempDir()
	bundlePath, archivePath, _, _ := writeSignedBundleFile(t, dir, []byte("archive-mismatch"), []string{"pw1"})

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	got, err := LookupFileSource(context.Background(), FileSource{
		Path:      bundlePath,
		PublicKey: hex.EncodeToString(otherPub),
	}, archivePath)
	if err == nil {
		t.Fatalf("expected error on public key mismatch, got nil; passwords=%v", got)
	}
	if !strings.Contains(err.Error(), "public") {
		t.Fatalf("expected public-key mismatch error, got: %v", err)
	}
}

func TestLookupFileSourceAllowsEmptyPublicKeyConfig(t *testing.T) {
	// When the user does not configure a pinned PublicKey, we still verify the
	// signature embedded in the bundle, but do not enforce a specific signer.
	dir := t.TempDir()
	bundlePath, archivePath, _, _ := writeSignedBundleFile(t, dir, []byte("archive-allow-any"), []string{"pw1"})

	got, err := LookupFileSource(context.Background(), FileSource{Path: bundlePath}, archivePath)
	if err != nil {
		t.Fatalf("LookupFileSource: %v", err)
	}
	if len(got) != 1 || got[0] != "pw1" {
		t.Fatalf("got = %v, want [pw1]", got)
	}
}

func TestLookupFileSourceErrorsOnMissingBundlePath(t *testing.T) {
	if _, err := LookupFileSource(context.Background(), FileSource{Path: ""}, "/no/such/archive"); err == nil {
		t.Fatalf("expected error on empty Path")
	}
}

func TestLookupFileSourceErrorsOnMissingArchive(t *testing.T) {
	dir := t.TempDir()
	bundlePath, _, pubHex, _ := writeSignedBundleFile(t, dir, []byte("archive-missing-target"), []string{"pw1"})

	_, err := LookupFileSource(context.Background(), FileSource{Path: bundlePath, PublicKey: pubHex}, filepath.Join(dir, "nope.zip"))
	if err == nil {
		t.Fatalf("expected error on missing archive")
	}
}

func TestLookupFileSourceErrorsOnInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "a.zip")
	if err := os.WriteFile(archivePath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if _, err := LookupFileSource(context.Background(), FileSource{Path: bundlePath}, archivePath); err == nil {
		t.Fatalf("expected error on invalid JSON")
	}
}

func TestLookupFileSourceErrorsOnInvalidSignature(t *testing.T) {
	dir := t.TempDir()
	bundlePath, archivePath, pubHex, priv := writeSignedBundleFile(t, dir, []byte("archive-tamper"), []string{"pw1"})
	_ = priv

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	signed, err := ParseSignedBundle(data)
	if err != nil {
		t.Fatalf("ParseSignedBundle: %v", err)
	}
	// Tamper with signature
	sigBytes, err := hex.DecodeString(signed.Signature)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sigBytes[0] ^= 0xff
	signed.Signature = hex.EncodeToString(sigBytes)
	tampered, err := MarshalSignedBundle(signed)
	if err != nil {
		t.Fatalf("MarshalSignedBundle: %v", err)
	}
	if err := os.WriteFile(bundlePath, tampered, 0o644); err != nil {
		t.Fatalf("rewrite bundle: %v", err)
	}

	if _, err := LookupFileSource(context.Background(), FileSource{Path: bundlePath, PublicKey: pubHex}, archivePath); err == nil {
		t.Fatalf("expected error on invalid signature")
	}
}
