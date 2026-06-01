package hashdb

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeArchive(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatalf("write archive %s: %v", name, err)
	}
	return p
}

func archiveDigestOf(t *testing.T, path string) ArchiveDigest {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer f.Close()
	return ArchiveHash(f)
}

func TestBuildBundleFromArchivePasswordsBuildsRecords(t *testing.T) {
	dir := t.TempDir()
	a := writeArchive(t, dir, "a.zip", []byte("AAA"))
	b := writeArchive(t, dir, "b.zip", []byte("BBB"))

	inputs := []ArchivePassword{
		{ArchivePath: a, Password: "pwA1", Source: "src-A"},
		{ArchivePath: a, Password: "pwA2"}, // empty Source -> fallback to bundle source
		{ArchivePath: b, Password: "pwB"},
	}
	bundle, err := BuildBundleFromArchivePasswords(context.Background(), "test-bundle", inputs)
	if err != nil {
		t.Fatalf("BuildBundleFromArchivePasswords: %v", err)
	}
	if bundle.Source != "test-bundle" {
		t.Fatalf("bundle.Source = %q, want %q", bundle.Source, "test-bundle")
	}
	if len(bundle.Records) != 3 {
		t.Fatalf("len(records) = %d, want 3", len(bundle.Records))
	}

	digestA := archiveDigestOf(t, a)
	digestB := archiveDigestOf(t, b)
	wantIDA := RecordID(digestA).Hex()
	wantIDB := RecordID(digestB).Hex()

	if bundle.Records[0].RecordID != wantIDA || bundle.Records[0].Source != "src-A" {
		t.Fatalf("record[0] = %+v, want id=%s source=src-A", bundle.Records[0], wantIDA)
	}
	if bundle.Records[1].RecordID != wantIDA || bundle.Records[1].Source != "test-bundle" {
		t.Fatalf("record[1] = %+v, want id=%s source=test-bundle (fallback)", bundle.Records[1], wantIDA)
	}
	if bundle.Records[2].RecordID != wantIDB || bundle.Records[2].Source != "test-bundle" {
		t.Fatalf("record[2] = %+v, want id=%s source=test-bundle", bundle.Records[2], wantIDB)
	}

	// decrypt sanity
	pw, err := DecryptRecord(digestA, bundle.Records[0])
	if err != nil || pw != "pwA1" {
		t.Fatalf("decrypt records[0]: %q err=%v", pw, err)
	}
	pw, err = DecryptRecord(digestA, bundle.Records[1])
	if err != nil || pw != "pwA2" {
		t.Fatalf("decrypt records[1]: %q err=%v", pw, err)
	}
	pw, err = DecryptRecord(digestB, bundle.Records[2])
	if err != nil || pw != "pwB" {
		t.Fatalf("decrypt records[2]: %q err=%v", pw, err)
	}
}

func TestBuildBundleFromArchivePasswordsDedupesSameArchivePassword(t *testing.T) {
	dir := t.TempDir()
	a := writeArchive(t, dir, "a.zip", []byte("AAA"))
	b := writeArchive(t, dir, "b.zip", []byte("BBB"))

	inputs := []ArchivePassword{
		{ArchivePath: a, Password: "pw1", Source: "first"},
		{ArchivePath: a, Password: "pw2"},
		{ArchivePath: a, Password: "pw1", Source: "second"}, // dup of first -> dropped, source preserved
		{ArchivePath: b, Password: "pw1"},                   // different archive, allowed
	}
	bundle, err := BuildBundleFromArchivePasswords(context.Background(), "bundle-src", inputs)
	if err != nil {
		t.Fatalf("BuildBundleFromArchivePasswords: %v", err)
	}
	if len(bundle.Records) != 3 {
		t.Fatalf("len(records) = %d, want 3 (dup removed)", len(bundle.Records))
	}

	digestA := archiveDigestOf(t, a)
	// First should be pw1 with source "first"
	if bundle.Records[0].Source != "first" {
		t.Fatalf("records[0].Source = %q, want first", bundle.Records[0].Source)
	}
	pw, err := DecryptRecord(digestA, bundle.Records[0])
	if err != nil || pw != "pw1" {
		t.Fatalf("decrypt records[0]: %q err=%v", pw, err)
	}
	// Second should be pw2 (preserves multi-password order for same archive)
	pw, err = DecryptRecord(digestA, bundle.Records[1])
	if err != nil || pw != "pw2" {
		t.Fatalf("decrypt records[1]: %q err=%v", pw, err)
	}
}

func TestBuildBundleFromArchivePasswordsRejectsEmptyArchivePath(t *testing.T) {
	_, err := BuildBundleFromArchivePasswords(context.Background(), "src", []ArchivePassword{
		{ArchivePath: "", Password: "pw"},
	})
	if err == nil {
		t.Fatalf("expected error on empty ArchivePath")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "archive") {
		t.Fatalf("error should mention archive path; got: %v", err)
	}
}

func TestBuildBundleFromArchivePasswordsRejectsEmptyPassword(t *testing.T) {
	dir := t.TempDir()
	a := writeArchive(t, dir, "a.zip", []byte("AAA"))
	_, err := BuildBundleFromArchivePasswords(context.Background(), "src", []ArchivePassword{
		{ArchivePath: a, Password: ""},
	})
	if err == nil {
		t.Fatalf("expected error on empty Password")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "password") {
		t.Fatalf("error should mention password; got: %v", err)
	}
}

func TestBuildBundleFromArchivePasswordsMissingArchive(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.zip")
	_, err := BuildBundleFromArchivePasswords(context.Background(), "src", []ArchivePassword{
		{ArchivePath: missing, Password: "pw"},
	})
	if err == nil {
		t.Fatalf("expected error on missing archive")
	}
	if !strings.Contains(err.Error(), missing) && !strings.Contains(strings.ToLower(err.Error()), "open") {
		t.Fatalf("error should reference path or open failure; got: %v", err)
	}
}

func TestBuildSignedBundleFromArchivePasswordsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a := writeArchive(t, dir, "a.zip", []byte("round-trip-bytes"))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signed, err := BuildSignedBundleFromArchivePasswords(context.Background(), "trip", []ArchivePassword{
		{ArchivePath: a, Password: "secret-pw", Source: "donor"},
	}, priv)
	if err != nil {
		t.Fatalf("BuildSignedBundleFromArchivePasswords: %v", err)
	}

	if signed.PublicKey != hex.EncodeToString(pub) {
		t.Fatalf("signed.PublicKey mismatch")
	}

	bundle, err := VerifySignedBundle(signed)
	if err != nil {
		t.Fatalf("VerifySignedBundle: %v", err)
	}
	if len(bundle.Records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(bundle.Records))
	}

	digest := archiveDigestOf(t, a)
	pw, err := DecryptRecord(digest, bundle.Records[0])
	if err != nil || pw != "secret-pw" {
		t.Fatalf("decrypt: %q err=%v", pw, err)
	}

	// Serialized signed bundle JSON must not contain the plaintext password
	// or the raw archive hash hex.
	data, err := MarshalSignedBundle(signed)
	if err != nil {
		t.Fatalf("MarshalSignedBundle: %v", err)
	}
	if strings.Contains(string(data), "secret-pw") {
		t.Fatalf("signed JSON should not contain plaintext password; got: %s", string(data))
	}
	if strings.Contains(string(data), digest.Hex()) {
		t.Fatalf("signed JSON should not contain raw archive hash hex; got: %s", string(data))
	}

	// Confirm JSON has the expected envelope keys.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		t.Fatalf("unmarshal probe: %v", err)
	}
	if _, ok := probe["bundle"]; !ok {
		t.Fatalf("signed JSON missing 'bundle'")
	}
	if _, ok := probe["signature"]; !ok {
		t.Fatalf("signed JSON missing 'signature'")
	}
}

func TestBuildSignedBundleFromArchivePasswordsRejectsBadKey(t *testing.T) {
	dir := t.TempDir()
	a := writeArchive(t, dir, "a.zip", []byte("x"))
	_, err := BuildSignedBundleFromArchivePasswords(context.Background(), "src", []ArchivePassword{
		{ArchivePath: a, Password: "pw"},
	}, ed25519.PrivateKey(nil))
	if err == nil {
		t.Fatalf("expected error on bad private key")
	}
}

func TestWriteSignedBundleFileRoundTripViaLookup(t *testing.T) {
	dir := t.TempDir()
	a := writeArchive(t, dir, "a.zip", []byte("write-and-lookup"))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signed, err := BuildSignedBundleFromArchivePasswords(context.Background(), "wrt", []ArchivePassword{
		{ArchivePath: a, Password: "alpha"},
		{ArchivePath: a, Password: "beta"},
	}, priv)
	if err != nil {
		t.Fatalf("BuildSignedBundleFromArchivePasswords: %v", err)
	}

	// Path inside a not-yet-existing nested directory.
	bundlePath := filepath.Join(dir, "nested", "deeper", "bundle.json")
	if err := WriteSignedBundleFile(context.Background(), bundlePath, signed); err != nil {
		t.Fatalf("WriteSignedBundleFile: %v", err)
	}

	info, err := os.Stat(bundlePath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Fatalf("mode = %o, want 0644", mode)
	}

	got, err := LookupFileSource(context.Background(), FileSource{
		Path:      bundlePath,
		PublicKey: hex.EncodeToString(pub),
	}, a)
	if err != nil {
		t.Fatalf("LookupFileSource: %v", err)
	}
	want := []string{"alpha", "beta"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got = %v, want %v", got, want)
	}
}

func TestWriteSignedBundleFileErrorsOnUnwritablePath(t *testing.T) {
	dir := t.TempDir()
	a := writeArchive(t, dir, "a.zip", []byte("u"))
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signed, err := BuildSignedBundleFromArchivePasswords(context.Background(), "u", []ArchivePassword{
		{ArchivePath: a, Password: "pw"},
	}, priv)
	if err != nil {
		t.Fatalf("BuildSignedBundleFromArchivePasswords: %v", err)
	}

	// A file at the target path that blocks creating a nested file underneath it.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	bad := filepath.Join(blocker, "sub", "bundle.json")
	if err := WriteSignedBundleFile(context.Background(), bad, signed); err == nil {
		t.Fatalf("expected error writing under a file blocker")
	}
}
