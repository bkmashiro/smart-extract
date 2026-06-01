package hashdb

import (
	"bytes"
	"testing"
)

func TestArchiveHashIsSHA256Digest(t *testing.T) {
	hash := ArchiveHash(bytes.NewBufferString("archive-bytes"))

	wantHex := "0c982986710a026635603031674053ca851fc0e3ea760094a34f59b84f7f6da6"
	if hash.Hex() != wantHex {
		t.Fatalf("ArchiveHash hex = %s, want %s", hash.Hex(), wantHex)
	}
	if len(hash.Bytes()) != 32 {
		t.Fatalf("ArchiveHash length = %d, want 32", len(hash.Bytes()))
	}
}

func TestRecordIDIsDeterministicAndDomainSeparated(t *testing.T) {
	hash := MustArchiveHashFromHex(t, "05fb7d3d02cfb2d2ad24e770fbe72a9a26e42541a4e3f625164768209e07e9d0")

	first := RecordID(hash)
	second := RecordID(hash)

	if first.Hex() != second.Hex() {
		t.Fatalf("RecordID not deterministic: %s != %s", first.Hex(), second.Hex())
	}
	if first.Hex() == hash.Hex() {
		t.Fatalf("RecordID should be domain-separated from archive hash")
	}
	if len(first.Bytes()) != 32 {
		t.Fatalf("RecordID length = %d, want 32", len(first.Bytes()))
	}
}

func TestEncryptDecryptPasswordBoundToArchiveHash(t *testing.T) {
	archiveHash := ArchiveHash(bytes.NewBufferString("same archive bytes"))

	record, err := EncryptPassword(archiveHash, "secret-password")
	if err != nil {
		t.Fatalf("EncryptPassword returned error: %v", err)
	}
	if len(record.Nonce) == 0 {
		t.Fatalf("nonce should be set")
	}
	if bytes.Contains(record.Ciphertext, []byte("secret-password")) {
		t.Fatalf("ciphertext should not contain plaintext password")
	}

	password, err := DecryptPassword(archiveHash, record)
	if err != nil {
		t.Fatalf("DecryptPassword returned error: %v", err)
	}
	if password != "secret-password" {
		t.Fatalf("password = %q, want %q", password, "secret-password")
	}
}

func TestDecryptPasswordFailsWithDifferentArchiveHash(t *testing.T) {
	archiveHash := ArchiveHash(bytes.NewBufferString("archive A"))
	otherArchiveHash := ArchiveHash(bytes.NewBufferString("archive B"))

	record, err := EncryptPassword(archiveHash, "secret-password")
	if err != nil {
		t.Fatalf("EncryptPassword returned error: %v", err)
	}

	if _, err := DecryptPassword(otherArchiveHash, record); err == nil {
		t.Fatalf("DecryptPassword with another archive hash succeeded; want failure")
	}
}

func TestArchiveHashHexValidation(t *testing.T) {
	if _, err := ArchiveHashFromHex("not-hex"); err == nil {
		t.Fatalf("ArchiveHashFromHex accepted non-hex input")
	}
	if _, err := ArchiveHashFromHex("abcd"); err == nil {
		t.Fatalf("ArchiveHashFromHex accepted wrong digest length")
	}
}

func MustArchiveHashFromHex(t *testing.T, s string) ArchiveDigest {
	t.Helper()
	hash, err := ArchiveHashFromHex(s)
	if err != nil {
		t.Fatalf("ArchiveHashFromHex(%q): %v", s, err)
	}
	return hash
}
