package hashdb

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AppendSignedBundleRecords appends inputs to the signed bundle at bundlePath,
// creating it if absent. If the bundle exists, its signature is verified and
// its declared public key must match the one derived from privateKey;
// otherwise the call fails without mutating the file.
//
// Records are merged in order: existing records first, then new records that
// are not exact (record_id, password) duplicates of existing ones. Multiple
// distinct passwords for the same archive are preserved. The serialized
// bundle never contains plaintext passwords or raw archive hash hex.
//
// AppendSignedBundleRecords performs no network access.
func AppendSignedBundleRecords(ctx context.Context, bundlePath string, source string, inputs []ArchivePassword, privateKey ed25519.PrivateKey) (SignedBundle, error) {
	if err := ctx.Err(); err != nil {
		return SignedBundle{}, err
	}
	if bundlePath == "" {
		return SignedBundle{}, errors.New("append signed bundle: empty path")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedBundle{}, fmt.Errorf("append signed bundle: invalid ed25519 private key length %d, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	pubAny := privateKey.Public()
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return SignedBundle{}, errors.New("append signed bundle: derive public key")
	}
	pubHex := hex.EncodeToString(pub)

	var existing Bundle
	existed := false
	if data, err := os.ReadFile(bundlePath); err == nil {
		signed, err := ParseSignedBundle(data)
		if err != nil {
			return SignedBundle{}, fmt.Errorf("append signed bundle: parse existing: %w", err)
		}
		if !strings.EqualFold(signed.PublicKey, pubHex) {
			return SignedBundle{}, fmt.Errorf("append signed bundle: existing bundle public key %s does not match signing key %s", signed.PublicKey, pubHex)
		}
		verified, err := VerifySignedBundle(signed)
		if err != nil {
			return SignedBundle{}, fmt.Errorf("append signed bundle: verify existing: %w", err)
		}
		existing = verified
		existed = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return SignedBundle{}, fmt.Errorf("append signed bundle: read %s: %w", bundlePath, err)
	}

	bundleSource := source
	if existed && existing.Source != "" {
		bundleSource = existing.Source
	}

	out := Bundle{
		Version: BundleVersion,
		Source:  bundleSource,
		Records: append([]Record(nil), existing.Records...),
	}

	type newItem struct {
		digest   ArchiveDigest
		password string
		source   string
	}
	newItems := make([]newItem, 0, len(inputs))
	seenNew := make(map[string]struct{}, len(inputs))
	for i, in := range inputs {
		if err := ctx.Err(); err != nil {
			return SignedBundle{}, err
		}
		if in.ArchivePath == "" {
			return SignedBundle{}, fmt.Errorf("append signed bundle: input %d: empty archive path", i)
		}
		if in.Password == "" {
			return SignedBundle{}, fmt.Errorf("append signed bundle: input %d (%s): empty password", i, in.ArchivePath)
		}
		digest, err := hashArchiveFile(in.ArchivePath)
		if err != nil {
			return SignedBundle{}, fmt.Errorf("append signed bundle: input %d: %w", i, err)
		}
		key := digest.Hex() + "\x00" + in.Password
		if _, ok := seenNew[key]; ok {
			continue
		}
		seenNew[key] = struct{}{}
		s := in.Source
		if s == "" {
			s = bundleSource
		}
		newItems = append(newItems, newItem{digest: digest, password: in.Password, source: s})
	}

	for _, ni := range newItems {
		if err := ctx.Err(); err != nil {
			return SignedBundle{}, err
		}
		recID := RecordID(ni.digest).Hex()
		dup := false
		for _, er := range existing.Records {
			if er.RecordID != recID {
				continue
			}
			pw, err := DecryptRecord(ni.digest, er)
			if err != nil {
				continue
			}
			if pw == ni.password {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		rec, err := BuildRecord(ni.digest, ni.password, ni.source)
		if err != nil {
			return SignedBundle{}, fmt.Errorf("append signed bundle: build record: %w", err)
		}
		out.Records = append(out.Records, rec)
	}

	signed, err := SignBundle(out, privateKey)
	if err != nil {
		return SignedBundle{}, fmt.Errorf("append signed bundle: sign: %w", err)
	}
	data, err := MarshalSignedBundle(signed)
	if err != nil {
		return SignedBundle{}, fmt.Errorf("append signed bundle: marshal: %w", err)
	}
	if err := writeSignedBundleAtomic(ctx, bundlePath, data); err != nil {
		return SignedBundle{}, err
	}
	return signed, nil
}

// writeSignedBundleAtomic writes data to path via a temp file in the same
// directory, then renames it into place with mode 0644.
func writeSignedBundleAtomic(ctx context.Context, path string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("append signed bundle: create parent dir %s: %w", dir, err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".bundle-*.json.tmp")
	if err != nil {
		return fmt.Errorf("append signed bundle: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("append signed bundle: write temp: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("append signed bundle: chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("append signed bundle: close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("append signed bundle: rename: %w", err)
	}
	return nil
}
