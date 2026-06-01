package hashdb

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildRecordRoundTrip(t *testing.T) {
	archiveHash := ArchiveHash(bytes.NewBufferString("archive bytes 1"))
	password := "hunter2"

	record, err := BuildRecord(archiveHash, password, "test-source")
	if err != nil {
		t.Fatalf("BuildRecord returned error: %v", err)
	}

	if record.RecordID != RecordID(archiveHash).Hex() {
		t.Fatalf("Record.RecordID = %s, want %s", record.RecordID, RecordID(archiveHash).Hex())
	}
	if record.Nonce == "" || record.Ciphertext == "" {
		t.Fatalf("nonce/ciphertext should be set; got %+v", record)
	}
	if record.Source != "test-source" {
		t.Fatalf("Record.Source = %q, want %q", record.Source, "test-source")
	}

	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal record: %v", err)
	}
	if strings.Contains(string(encoded), password) {
		t.Fatalf("encoded record leaks plaintext password: %s", encoded)
	}
	if strings.Contains(string(encoded), archiveHash.Hex()) {
		t.Fatalf("encoded record leaks archive hash: %s", encoded)
	}

	got, err := DecryptRecord(archiveHash, record)
	if err != nil {
		t.Fatalf("DecryptRecord returned error: %v", err)
	}
	if got != password {
		t.Fatalf("DecryptRecord = %q, want %q", got, password)
	}
}

func TestDecryptRecordRejectsWrongArchiveHash(t *testing.T) {
	archiveHash := ArchiveHash(bytes.NewBufferString("archive A"))
	otherHash := ArchiveHash(bytes.NewBufferString("archive B"))

	record, err := BuildRecord(archiveHash, "secret", "")
	if err != nil {
		t.Fatalf("BuildRecord: %v", err)
	}

	if _, err := DecryptRecord(otherHash, record); err == nil {
		t.Fatalf("DecryptRecord with wrong archive hash should fail")
	}
}

func TestDecryptRecordRejectsMismatchedRecordID(t *testing.T) {
	archiveHash := ArchiveHash(bytes.NewBufferString("archive bytes"))

	record, err := BuildRecord(archiveHash, "secret", "")
	if err != nil {
		t.Fatalf("BuildRecord: %v", err)
	}

	// tamper with record id
	record.RecordID = strings.Repeat("0", len(record.RecordID))

	if _, err := DecryptRecord(archiveHash, record); err == nil {
		t.Fatalf("DecryptRecord with mismatched record_id should fail")
	}
}

func TestParseBundleRejectsMalformedJSON(t *testing.T) {
	if _, err := ParseBundle([]byte("{not json")); err == nil {
		t.Fatalf("ParseBundle accepted malformed JSON")
	}
}

func TestParseBundleRejectsUnsupportedVersion(t *testing.T) {
	raw := []byte(`{"version":99,"records":[]}`)
	if _, err := ParseBundle(raw); err == nil {
		t.Fatalf("ParseBundle accepted unsupported version")
	}
}

func TestParseBundleRejectsRecordMissingFields(t *testing.T) {
	validID := strings.Repeat("0", 64)
	cases := []string{
		`{"version":1,"records":[{"nonce":"aa","ciphertext":"bb"}]}`,                  // no record_id
		`{"version":1,"records":[{"record_id":"` + validID + `","ciphertext":"bb"}]}`, // no nonce
		`{"version":1,"records":[{"record_id":"` + validID + `","nonce":"bb"}]}`,      // no ciphertext
	}
	for _, raw := range cases {
		if _, err := ParseBundle([]byte(raw)); err == nil {
			t.Fatalf("ParseBundle accepted record with missing fields: %s", raw)
		}
	}
}

func TestParseBundleRejectsInvalidRecordHex(t *testing.T) {
	validID := strings.Repeat("0", 64)
	cases := []string{
		`{"version":1,"records":[{"record_id":"not-hex","nonce":"aa","ciphertext":"bb"}]}`,
		`{"version":1,"records":[{"record_id":"abcd","nonce":"aa","ciphertext":"bb"}]}`,
		`{"version":1,"records":[{"record_id":"` + validID + `","nonce":"not-hex","ciphertext":"bb"}]}`,
		`{"version":1,"records":[{"record_id":"` + validID + `","nonce":"aa","ciphertext":"not-hex"}]}`,
	}
	for _, raw := range cases {
		if _, err := ParseBundle([]byte(raw)); err == nil {
			t.Fatalf("ParseBundle accepted invalid hex record: %s", raw)
		}
	}
}

func TestMarshalBundleFillsVersionAndRoundTrips(t *testing.T) {
	archiveHash := ArchiveHash(bytes.NewBufferString("archive xyz"))
	rec, err := BuildRecord(archiveHash, "pw", "src")
	if err != nil {
		t.Fatalf("BuildRecord: %v", err)
	}

	bundle := Bundle{
		Source:  "official",
		Records: []Record{rec},
	}

	data, err := MarshalBundle(bundle)
	if err != nil {
		t.Fatalf("MarshalBundle: %v", err)
	}

	parsed, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if parsed.Version != 1 {
		t.Fatalf("parsed.Version = %d, want 1", parsed.Version)
	}
	if parsed.Source != "official" {
		t.Fatalf("parsed.Source = %q, want %q", parsed.Source, "official")
	}
	if len(parsed.Records) != 1 {
		t.Fatalf("parsed.Records length = %d, want 1", len(parsed.Records))
	}
	if parsed.Records[0].RecordID != rec.RecordID {
		t.Fatalf("RecordID mismatch after roundtrip")
	}
}

func TestLookupBundleReturnsMatchingRecordsInOrder(t *testing.T) {
	archiveA := ArchiveHash(bytes.NewBufferString("archive A"))
	archiveB := ArchiveHash(bytes.NewBufferString("archive B"))

	recA1, err := BuildRecord(archiveA, "pwA1", "src1")
	if err != nil {
		t.Fatalf("BuildRecord A1: %v", err)
	}
	recB, err := BuildRecord(archiveB, "pwB", "src2")
	if err != nil {
		t.Fatalf("BuildRecord B: %v", err)
	}
	recA2, err := BuildRecord(archiveA, "pwA2", "src3")
	if err != nil {
		t.Fatalf("BuildRecord A2: %v", err)
	}

	bundle := Bundle{
		Version: 1,
		Records: []Record{recA1, recB, recA2},
	}

	matches, err := LookupBundle(bundle, archiveA)
	if err != nil {
		t.Fatalf("LookupBundle: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2", len(matches))
	}
	if matches[0].Source != "src1" || matches[1].Source != "src3" {
		t.Fatalf("LookupBundle did not preserve order: %+v", matches)
	}

	noMatch, err := LookupBundle(bundle, ArchiveHash(bytes.NewBufferString("archive C")))
	if err != nil {
		t.Fatalf("LookupBundle no-match: %v", err)
	}
	if len(noMatch) != 0 {
		t.Fatalf("expected no matches, got %d", len(noMatch))
	}
}
