package hashdb

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// BundleVersion is the current supported bundle format version.
const BundleVersion = 1

// Record is the JSON-safe shape of an encrypted HashDB password record.
type Record struct {
	RecordID   string `json:"record_id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Source     string `json:"source,omitempty"`
}

// Bundle is a collection of encrypted password records from a single source.
type Bundle struct {
	Version int      `json:"version"`
	Source  string   `json:"source,omitempty"`
	Records []Record `json:"records"`
}

// BuildRecord constructs an encrypted Record bound to archiveHash. The
// archive hash and plaintext password are never stored on the returned Record.
func BuildRecord(archiveHash ArchiveDigest, password string, source string) (Record, error) {
	enc, err := EncryptPassword(archiveHash, password)
	if err != nil {
		return Record{}, err
	}
	return Record{
		RecordID:   RecordID(archiveHash).Hex(),
		Nonce:      hex.EncodeToString(enc.Nonce),
		Ciphertext: hex.EncodeToString(enc.Ciphertext),
		Source:     source,
	}, nil
}

// DecryptRecord validates the record's RecordID against archiveHash and
// returns the recovered plaintext password.
func DecryptRecord(archiveHash ArchiveDigest, record Record) (string, error) {
	expected := RecordID(archiveHash).Hex()
	if record.RecordID != expected {
		return "", fmt.Errorf("record_id mismatch: record has %s, archive hash derives %s", record.RecordID, expected)
	}
	nonce, err := decodeHexField(record.Nonce, "nonce")
	if err != nil {
		return "", err
	}
	ciphertext, err := decodeHexField(record.Ciphertext, "ciphertext")
	if err != nil {
		return "", err
	}
	return DecryptPassword(archiveHash, EncryptedPassword{Nonce: nonce, Ciphertext: ciphertext})
}

// MarshalBundle serializes b as JSON, filling Version=1 when zero.
func MarshalBundle(b Bundle) ([]byte, error) {
	if b.Version == 0 {
		b.Version = BundleVersion
	}
	if b.Records == nil {
		b.Records = []Record{}
	}
	return json.Marshal(b)
}

// ParseBundle decodes a bundle and validates version and record structure.
func ParseBundle(data []byte) (Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return Bundle{}, fmt.Errorf("decode bundle: %w", err)
	}
	if b.Version != BundleVersion {
		return Bundle{}, fmt.Errorf("unsupported bundle version %d, want %d", b.Version, BundleVersion)
	}
	for i, r := range b.Records {
		if err := validateRecord(r); err != nil {
			return Bundle{}, fmt.Errorf("record %d: %w", i, err)
		}
	}
	return b, nil
}

func validateRecord(r Record) error {
	if r.RecordID == "" {
		return errors.New("missing record_id")
	}
	if _, err := decodeFixedHex(r.RecordID, len(RecordIDDigest{}), "record_id"); err != nil {
		return err
	}
	if r.Nonce == "" {
		return errors.New("missing nonce")
	}
	if _, err := decodeHexField(r.Nonce, "nonce"); err != nil {
		return err
	}
	if r.Ciphertext == "" {
		return errors.New("missing ciphertext")
	}
	if _, err := decodeHexField(r.Ciphertext, "ciphertext"); err != nil {
		return err
	}
	return nil
}

func decodeFixedHex(s string, wantBytes int, field string) ([]byte, error) {
	b, err := decodeHexField(s, field)
	if err != nil {
		return nil, err
	}
	if len(b) != wantBytes {
		return nil, fmt.Errorf("%s length %d bytes, want %d", field, len(b), wantBytes)
	}
	return b, nil
}

func decodeHexField(s, field string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode %s hex: %w", field, err)
	}
	return b, nil
}

// LookupBundle returns all records in bundle whose RecordID matches
// archiveHash, preserving bundle order.
func LookupBundle(bundle Bundle, archiveHash ArchiveDigest) ([]Record, error) {
	want := RecordID(archiveHash).Hex()
	var out []Record
	for _, r := range bundle.Records {
		if r.RecordID == want {
			out = append(out, r)
		}
	}
	return out, nil
}
