package hashdb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// FileSource describes a local signed HashDB bundle file to consult for
// password candidates. No network access is performed.
type FileSource struct {
	// Name is a human-readable label for logs and diagnostics.
	Name string
	// Path is the filesystem path to a signed bundle JSON file.
	Path string
	// PublicKey, if non-empty, is the lowercase hex Ed25519 public key that
	// the signed bundle must declare. Used to pin the trusted signer.
	PublicKey string
}

// LookupFileSource opens archivePath, hashes its bytes, loads and verifies
// the signed bundle at source.Path, and returns the deduplicated decrypted
// passwords whose record_id matches the archive hash. Bundle record order is
// preserved.
//
// LookupFileSource performs no network access.
func LookupFileSource(ctx context.Context, source FileSource, archivePath string) ([]string, error) {
	if source.Path == "" {
		return nil, errors.New("hashdb file source: empty Path")
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("hashdb file source: open archive: %w", err)
	}
	digest := ArchiveHash(f)
	f.Close()

	data, err := os.ReadFile(source.Path)
	if err != nil {
		return nil, fmt.Errorf("hashdb file source: read bundle: %w", err)
	}
	signed, err := ParseSignedBundle(data)
	if err != nil {
		return nil, fmt.Errorf("hashdb file source: parse bundle: %w", err)
	}

	if source.PublicKey != "" {
		want := strings.ToLower(source.PublicKey)
		got := strings.ToLower(signed.PublicKey)
		if got != want {
			return nil, fmt.Errorf("hashdb file source: public key mismatch: bundle %s, configured %s", got, want)
		}
	}

	bundle, err := VerifySignedBundle(signed)
	if err != nil {
		return nil, fmt.Errorf("hashdb file source: verify signature: %w", err)
	}

	matches, err := LookupBundle(bundle, digest)
	if err != nil {
		return nil, fmt.Errorf("hashdb file source: lookup: %w", err)
	}

	out := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, rec := range matches {
		pw, err := DecryptRecord(digest, rec)
		if err != nil {
			return nil, fmt.Errorf("hashdb file source: decrypt: %w", err)
		}
		if _, ok := seen[pw]; ok {
			continue
		}
		seen[pw] = struct{}{}
		out = append(out, pw)
	}
	return out, nil
}
