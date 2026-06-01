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

func TestAppendSignedBundleRecordsCreatesNewBundle(t *testing.T) {
	dir := t.TempDir()
	a := writeArchive(t, dir, "a.zip", []byte("ARCHIVE-A"))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bundlePath := filepath.Join(dir, "nested", "bundle.json")

	signed, err := AppendSignedBundleRecords(context.Background(), bundlePath, "local", []ArchivePassword{
		{ArchivePath: a, Password: "pw-A"},
	}, priv)
	if err != nil {
		t.Fatalf("AppendSignedBundleRecords: %v", err)
	}
	if signed.PublicKey != hex.EncodeToString(pub) {
		t.Fatalf("signed.PublicKey mismatch")
	}
	if len(signed.Bundle.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(signed.Bundle.Records))
	}

	info, err := os.Stat(bundlePath)
	if err != nil {
		t.Fatalf("stat bundle: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Fatalf("mode = %o, want 0644", mode)
	}

	// Lookup roundtrip.
	got, err := LookupFileSource(context.Background(), FileSource{
		Path:      bundlePath,
		PublicKey: hex.EncodeToString(pub),
	}, a)
	if err != nil {
		t.Fatalf("LookupFileSource: %v", err)
	}
	if len(got) != 1 || got[0] != "pw-A" {
		t.Fatalf("got = %v, want [pw-A]", got)
	}
}

func TestAppendSignedBundleRecordsAppendsToExistingBundle(t *testing.T) {
	dir := t.TempDir()
	a := writeArchive(t, dir, "a.zip", []byte("ARCH-A"))
	b := writeArchive(t, dir, "b.zip", []byte("ARCH-B"))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")

	if _, err := AppendSignedBundleRecords(context.Background(), bundlePath, "local", []ArchivePassword{
		{ArchivePath: a, Password: "pw-A1"},
	}, priv); err != nil {
		t.Fatalf("first append: %v", err)
	}

	signed, err := AppendSignedBundleRecords(context.Background(), bundlePath, "local", []ArchivePassword{
		{ArchivePath: a, Password: "pw-A2"}, // distinct password, same archive -> kept
		{ArchivePath: b, Password: "pw-B"},
	}, priv)
	if err != nil {
		t.Fatalf("second append: %v", err)
	}
	if signed.PublicKey != hex.EncodeToString(pub) {
		t.Fatalf("signed.PublicKey mismatch")
	}
	if len(signed.Bundle.Records) != 3 {
		t.Fatalf("records = %d, want 3", len(signed.Bundle.Records))
	}

	digestA := archiveDigestOf(t, a)
	wantRecA := RecordID(digestA).Hex()
	if signed.Bundle.Records[0].RecordID != wantRecA {
		t.Fatalf("records[0] = %s, want %s (existing preserved first)", signed.Bundle.Records[0].RecordID, wantRecA)
	}

	gotA, err := LookupFileSource(context.Background(), FileSource{
		Path:      bundlePath,
		PublicKey: hex.EncodeToString(pub),
	}, a)
	if err != nil {
		t.Fatalf("LookupFileSource A: %v", err)
	}
	if len(gotA) != 2 || gotA[0] != "pw-A1" || gotA[1] != "pw-A2" {
		t.Fatalf("got A = %v, want [pw-A1 pw-A2]", gotA)
	}

	gotB, err := LookupFileSource(context.Background(), FileSource{
		Path:      bundlePath,
		PublicKey: hex.EncodeToString(pub),
	}, b)
	if err != nil {
		t.Fatalf("LookupFileSource B: %v", err)
	}
	if len(gotB) != 1 || gotB[0] != "pw-B" {
		t.Fatalf("got B = %v, want [pw-B]", gotB)
	}
}

func TestAppendSignedBundleRecordsDedupesExisting(t *testing.T) {
	dir := t.TempDir()
	a := writeArchive(t, dir, "a.zip", []byte("dup-archive"))
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")

	if _, err := AppendSignedBundleRecords(context.Background(), bundlePath, "local", []ArchivePassword{
		{ArchivePath: a, Password: "same-pw"},
	}, priv); err != nil {
		t.Fatalf("first append: %v", err)
	}
	signed, err := AppendSignedBundleRecords(context.Background(), bundlePath, "local", []ArchivePassword{
		{ArchivePath: a, Password: "same-pw"}, // duplicate of existing -> dropped
		{ArchivePath: a, Password: "same-pw"}, // duplicate within new inputs -> dropped
	}, priv)
	if err != nil {
		t.Fatalf("second append: %v", err)
	}
	if len(signed.Bundle.Records) != 1 {
		t.Fatalf("records = %d, want 1 (duplicates removed)", len(signed.Bundle.Records))
	}
}

func TestAppendSignedBundleRecordsKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	a := writeArchive(t, dir, "a.zip", []byte("xyz"))
	_, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")

	if _, err := AppendSignedBundleRecords(context.Background(), bundlePath, "local", []ArchivePassword{
		{ArchivePath: a, Password: "pw"},
	}, priv1); err != nil {
		t.Fatalf("first append: %v", err)
	}
	_, err = AppendSignedBundleRecords(context.Background(), bundlePath, "local", []ArchivePassword{
		{ArchivePath: a, Password: "pw2"},
	}, priv2)
	if err == nil {
		t.Fatalf("expected key mismatch error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "key") {
		t.Fatalf("error should mention key; got: %v", err)
	}
}

func TestAppendSignedBundleRecordsNoPlaintextLeak(t *testing.T) {
	dir := t.TempDir()
	a := writeArchive(t, dir, "a.zip", []byte("leak-check-archive"))
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	signed, err := AppendSignedBundleRecords(context.Background(), bundlePath, "local", []ArchivePassword{
		{ArchivePath: a, Password: "PLAINTEXT-PW"},
	}, priv)
	if err != nil {
		t.Fatalf("AppendSignedBundleRecords: %v", err)
	}
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if strings.Contains(string(data), "PLAINTEXT-PW") {
		t.Fatalf("bundle file contains plaintext password")
	}
	digest := archiveDigestOf(t, a)
	if strings.Contains(string(data), digest.Hex()) {
		t.Fatalf("bundle file contains raw archive hash hex")
	}
	if len(signed.Bundle.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(signed.Bundle.Records))
	}
}

func TestAppendSignedBundleRecordsCorruptExisting(t *testing.T) {
	dir := t.TempDir()
	a := writeArchive(t, dir, "a.zip", []byte("c"))
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte("not json"), 0o644); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	_, err = AppendSignedBundleRecords(context.Background(), bundlePath, "local", []ArchivePassword{
		{ArchivePath: a, Password: "pw"},
	}, priv)
	if err == nil {
		t.Fatalf("expected error on corrupt existing bundle")
	}
}
