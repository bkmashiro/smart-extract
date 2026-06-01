package hashdb

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AppendShardedSourceRecords contributes archive/password pairs to a local
// sharded HashDB source rooted at baseDir, creating it when absent and
// updating only the affected shards and the manifest otherwise.
//
// If baseDir/manifest.json does not exist, a new sharded source is built from
// inputs and persisted with the supplied prefixLen.
//
// If the manifest exists, it must validate via ParseManifest and its
// ShardPrefixLength must equal prefixLen (when prefixLen is 0 the existing
// length is inherited). Each affected shard's existing file is read, its
// SHA256 checked against the manifest, its signature verified, and its
// declared public key required to match the one derived from privateKey;
// any failure aborts the call before any file is written. New records are
// appended after existing records, with exact (record_id, password)
// duplicates dropped. Multiple distinct passwords for the same archive are
// preserved. Unaffected shards are not rewritten.
//
// AppendShardedSourceRecords performs no network access.
func AppendShardedSourceRecords(ctx context.Context, baseDir, source string, inputs []ArchivePassword, privateKey ed25519.PrivateKey, prefixLen int) (Manifest, error) {
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	if baseDir == "" {
		return Manifest{}, errors.New("append sharded source: empty baseDir")
	}
	if len(inputs) == 0 {
		return Manifest{}, errors.New("append sharded source: no inputs")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return Manifest{}, fmt.Errorf("append sharded source: invalid ed25519 private key length %d, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	if prefixLen < 0 || prefixLen > 64 {
		return Manifest{}, fmt.Errorf("append sharded source: prefix length %d out of range (0..64)", prefixLen)
	}
	pubAny := privateKey.Public()
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return Manifest{}, errors.New("append sharded source: derive public key")
	}
	pubHex := hex.EncodeToString(pub)

	manifestPath := filepath.Join(baseDir, "manifest.json")
	existingData, readErr := os.ReadFile(manifestPath)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return Manifest{}, fmt.Errorf("append sharded source: read manifest: %w", readErr)
	}

	if errors.Is(readErr, os.ErrNotExist) {
		if prefixLen <= 0 {
			return Manifest{}, errors.New("append sharded source: prefix length required when manifest does not exist")
		}
		return createShardedSource(ctx, baseDir, manifestPath, source, inputs, privateKey, prefixLen)
	}

	manifest, err := ParseManifest(existingData)
	if err != nil {
		return Manifest{}, fmt.Errorf("append sharded source: parse manifest: %w", err)
	}
	if prefixLen == 0 {
		prefixLen = manifest.ShardPrefixLength
	} else if prefixLen != manifest.ShardPrefixLength {
		return Manifest{}, fmt.Errorf("append sharded source: prefix length %d does not match manifest %d", prefixLen, manifest.ShardPrefixLength)
	}

	bundleSource := source
	if manifest.Source != "" {
		bundleSource = manifest.Source
	}

	type newItem struct {
		digest   ArchiveDigest
		password string
		source   string
	}
	grouped := map[string][]newItem{}
	affectedOrder := []string{}
	seenInputs := make(map[string]struct{}, len(inputs))
	for i, in := range inputs {
		if err := ctx.Err(); err != nil {
			return Manifest{}, err
		}
		if in.ArchivePath == "" {
			return Manifest{}, fmt.Errorf("append sharded source: input %d: empty archive path", i)
		}
		if in.Password == "" {
			return Manifest{}, fmt.Errorf("append sharded source: input %d (%s): empty password", i, in.ArchivePath)
		}
		digest, err := hashArchiveFile(in.ArchivePath)
		if err != nil {
			return Manifest{}, fmt.Errorf("append sharded source: input %d: %w", i, err)
		}
		recID := RecordID(digest).Hex()
		if len(recID) < prefixLen {
			return Manifest{}, fmt.Errorf("append sharded source: record id shorter than prefix length")
		}
		dupKey := recID + "\x00" + in.Password
		if _, ok := seenInputs[dupKey]; ok {
			continue
		}
		seenInputs[dupKey] = struct{}{}
		s := in.Source
		if s == "" {
			s = bundleSource
		}
		prefix := strings.ToLower(recID[:prefixLen])
		if _, ok := grouped[prefix]; !ok {
			affectedOrder = append(affectedOrder, prefix)
		}
		grouped[prefix] = append(grouped[prefix], newItem{digest: digest, password: in.Password, source: s})
	}

	// Phase 1: load and verify each affected existing shard. Abort on any
	// failure before mutating anything.
	existingRecords := map[string][]Record{}
	for _, prefix := range affectedOrder {
		if err := ctx.Err(); err != nil {
			return Manifest{}, err
		}
		shard, ok := manifest.Shards[prefix]
		if !ok {
			continue
		}
		shardFull := filepath.Join(baseDir, shard.Path)
		data, err := os.ReadFile(shardFull)
		if err != nil {
			return Manifest{}, fmt.Errorf("append sharded source: read shard %s: %w", prefix, err)
		}
		gotSum := sha256.Sum256(data)
		if hex.EncodeToString(gotSum[:]) != strings.ToLower(shard.SHA256) {
			return Manifest{}, fmt.Errorf("append sharded source: shard %s sha256 mismatch", prefix)
		}
		signed, err := ParseSignedBundle(data)
		if err != nil {
			return Manifest{}, fmt.Errorf("append sharded source: parse shard %s: %w", prefix, err)
		}
		if !strings.EqualFold(signed.PublicKey, pubHex) {
			return Manifest{}, fmt.Errorf("append sharded source: shard %s public key %s does not match signing key %s", prefix, signed.PublicKey, pubHex)
		}
		bundle, err := VerifySignedBundle(signed)
		if err != nil {
			return Manifest{}, fmt.Errorf("append sharded source: verify shard %s: %w", prefix, err)
		}
		existingRecords[prefix] = bundle.Records
	}

	// Phase 2: build merged record lists per affected prefix.
	mergedShards := make(map[string][]Record, len(affectedOrder))
	for _, prefix := range affectedOrder {
		if err := ctx.Err(); err != nil {
			return Manifest{}, err
		}
		base := existingRecords[prefix]
		merged := append([]Record(nil), base...)
		for _, ni := range grouped[prefix] {
			recID := RecordID(ni.digest).Hex()
			dup := false
			for _, er := range base {
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
				return Manifest{}, fmt.Errorf("append sharded source: build record: %w", err)
			}
			merged = append(merged, rec)
		}
		mergedShards[prefix] = merged
	}

	// Phase 3: sign, marshal, and write each affected shard atomically;
	// update manifest entries.
	shardsDir := filepath.Join(baseDir, "shards")
	if err := os.MkdirAll(shardsDir, 0o755); err != nil {
		return Manifest{}, fmt.Errorf("append sharded source: create shards dir: %w", err)
	}
	for _, prefix := range affectedOrder {
		if err := ctx.Err(); err != nil {
			return Manifest{}, err
		}
		bundle := Bundle{Version: BundleVersion, Source: bundleSource, Records: mergedShards[prefix]}
		signed, err := SignBundle(bundle, privateKey)
		if err != nil {
			return Manifest{}, fmt.Errorf("append sharded source: sign shard %s: %w", prefix, err)
		}
		data, err := MarshalSignedBundle(signed)
		if err != nil {
			return Manifest{}, fmt.Errorf("append sharded source: marshal shard %s: %w", prefix, err)
		}
		relPath := "shards/" + prefix + ".json"
		fullPath := filepath.Join(baseDir, relPath)
		if err := writeFileAtomic(fullPath, data); err != nil {
			return Manifest{}, fmt.Errorf("append sharded source: write shard %s: %w", prefix, err)
		}
		sum := sha256.Sum256(data)
		manifest.Shards[prefix] = ShardInfo{
			Path:   relPath,
			SHA256: hex.EncodeToString(sum[:]),
			Count:  len(mergedShards[prefix]),
		}
	}

	if manifest.Source == "" {
		manifest.Source = source
	}

	manifestBytes, err := MarshalManifest(manifest)
	if err != nil {
		return Manifest{}, fmt.Errorf("append sharded source: marshal manifest: %w", err)
	}
	if err := writeFileAtomic(manifestPath, manifestBytes); err != nil {
		return Manifest{}, fmt.Errorf("append sharded source: write manifest: %w", err)
	}
	return manifest, nil
}

func createShardedSource(ctx context.Context, baseDir, manifestPath, source string, inputs []ArchivePassword, privateKey ed25519.PrivateKey, prefixLen int) (Manifest, error) {
	records := make([]Record, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for i, in := range inputs {
		if err := ctx.Err(); err != nil {
			return Manifest{}, err
		}
		if in.ArchivePath == "" {
			return Manifest{}, fmt.Errorf("append sharded source: input %d: empty archive path", i)
		}
		if in.Password == "" {
			return Manifest{}, fmt.Errorf("append sharded source: input %d (%s): empty password", i, in.ArchivePath)
		}
		digest, err := hashArchiveFile(in.ArchivePath)
		if err != nil {
			return Manifest{}, fmt.Errorf("append sharded source: input %d: %w", i, err)
		}
		key := digest.Hex() + "\x00" + in.Password
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		s := in.Source
		if s == "" {
			s = source
		}
		rec, err := BuildRecord(digest, in.Password, s)
		if err != nil {
			return Manifest{}, fmt.Errorf("append sharded source: build record: %w", err)
		}
		records = append(records, rec)
	}
	manifest, err := BuildShardedSourceFromRecords(ctx, baseDir, source, records, privateKey, prefixLen)
	if err != nil {
		return Manifest{}, err
	}
	data, err := MarshalManifest(manifest)
	if err != nil {
		return Manifest{}, fmt.Errorf("append sharded source: marshal manifest: %w", err)
	}
	if err := writeFileAtomic(manifestPath, data); err != nil {
		return Manifest{}, fmt.Errorf("append sharded source: write manifest: %w", err)
	}
	return manifest, nil
}

// writeFileAtomic writes data to path via a temp file in the same directory,
// then renames it into place with mode 0644.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create parent dir %s: %w", dir, err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".sharded-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
