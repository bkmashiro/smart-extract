package hashdb

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ArchivePassword pairs a local archive file with a known password and an
// optional per-record source label.
type ArchivePassword struct {
	ArchivePath string
	Password    string
	Source      string
}

// BuildBundleFromArchivePasswords hashes each archive at inputs[i].ArchivePath,
// encrypts the paired password under that archive hash, and returns a Bundle
// whose Source is bundleSource. Per-record Source falls back to bundleSource
// when the input leaves Source empty.
//
// Identical (archive-digest, password) pairs are deduplicated, preserving the
// first occurrence (and its Source). Multiple distinct passwords for the same
// archive are kept in input order.
func BuildBundleFromArchivePasswords(ctx context.Context, bundleSource string, inputs []ArchivePassword) (Bundle, error) {
	records := make([]Record, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))

	for i, in := range inputs {
		if err := ctx.Err(); err != nil {
			return Bundle{}, err
		}
		if in.ArchivePath == "" {
			return Bundle{}, fmt.Errorf("input %d: empty archive path", i)
		}
		if in.Password == "" {
			return Bundle{}, fmt.Errorf("input %d (%s): empty password", i, in.ArchivePath)
		}

		digest, err := hashArchiveFile(in.ArchivePath)
		if err != nil {
			return Bundle{}, fmt.Errorf("input %d: %w", i, err)
		}

		dedupeKey := digest.Hex() + "\x00" + in.Password
		if _, ok := seen[dedupeKey]; ok {
			continue
		}
		seen[dedupeKey] = struct{}{}

		source := in.Source
		if source == "" {
			source = bundleSource
		}
		rec, err := BuildRecord(digest, in.Password, source)
		if err != nil {
			return Bundle{}, fmt.Errorf("input %d: build record: %w", i, err)
		}
		records = append(records, rec)
	}

	return Bundle{
		Version: BundleVersion,
		Source:  bundleSource,
		Records: records,
	}, nil
}

// BuildSignedBundleFromArchivePasswords builds a Bundle from inputs and signs
// it with privateKey, returning the SignedBundle.
func BuildSignedBundleFromArchivePasswords(ctx context.Context, bundleSource string, inputs []ArchivePassword, privateKey ed25519.PrivateKey) (SignedBundle, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedBundle{}, fmt.Errorf("invalid ed25519 private key length %d, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	bundle, err := BuildBundleFromArchivePasswords(ctx, bundleSource, inputs)
	if err != nil {
		return SignedBundle{}, err
	}
	return SignBundle(bundle, privateKey)
}

// WriteSignedBundleFile serializes signed to JSON and writes it to path with
// mode 0644, creating parent directories as needed.
func WriteSignedBundleFile(ctx context.Context, path string, signed SignedBundle) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if path == "" {
		return errors.New("write signed bundle: empty path")
	}
	data, err := MarshalSignedBundle(signed)
	if err != nil {
		return fmt.Errorf("write signed bundle: marshal: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("write signed bundle: create parent dir %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write signed bundle: %w", err)
	}
	return nil
}

func hashArchiveFile(path string) (ArchiveDigest, error) {
	f, err := os.Open(path)
	if err != nil {
		return ArchiveDigest{}, fmt.Errorf("open archive %s: %w", path, err)
	}
	defer f.Close()
	return ArchiveHash(f), nil
}
