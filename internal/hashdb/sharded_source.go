package hashdb

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ManifestVersion is the current supported sharded manifest format version.
const ManifestVersion = 1

// ShardInfo describes a single shard file referenced from a Manifest.
//
// SHA256 covers the raw on-disk shard bytes when Compression is empty
// (legacy/local case). When Compression is non-empty, SHA256 covers the
// compressed bytes as fetched from a mirror; cached/local files reflect the
// decompressed signed bundle, whose integrity is then anchored by its
// signature.
type ShardInfo struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Count       int    `json:"count,omitempty"`
	Compression string `json:"compression,omitempty"`
}

// Manifest is the top-level index for a local sharded HashDB source. Shard
// keys are lowercase hex prefixes of record_id with length ShardPrefixLength.
type Manifest struct {
	Version           int                  `json:"version"`
	Source            string               `json:"source,omitempty"`
	ShardPrefixLength int                  `json:"shard_prefix_length"`
	Shards            map[string]ShardInfo `json:"shards"`
}

// ShardedFileSource describes a local sharded HashDB source on disk. No
// network access is performed when consulting one.
type ShardedFileSource struct {
	// Name is a human-readable label for logs and diagnostics.
	Name string
	// BaseDir is the root directory containing shards and (by default) the
	// manifest. Shard paths in the manifest are resolved relative to BaseDir.
	BaseDir string
	// ManifestPath, when set, overrides the default BaseDir/manifest.json
	// location for the manifest file.
	ManifestPath string
	// PublicKey, if non-empty, is the lowercase hex Ed25519 public key that
	// each shard's signed bundle must declare. Used to pin the trusted signer.
	PublicKey string
}

// MarshalManifest serializes m as JSON, filling Version=1 when zero and
// initializing nil shard maps to empty.
func MarshalManifest(m Manifest) ([]byte, error) {
	if m.Version == 0 {
		m.Version = ManifestVersion
	}
	if m.Shards == nil {
		m.Shards = map[string]ShardInfo{}
	}
	return json.Marshal(m)
}

// ParseManifest decodes a Manifest from JSON and validates structure.
func ParseManifest(data []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if m.Version != ManifestVersion {
		return Manifest{}, fmt.Errorf("unsupported manifest version %d, want %d", m.Version, ManifestVersion)
	}
	if m.ShardPrefixLength <= 0 || m.ShardPrefixLength > 64 {
		return Manifest{}, fmt.Errorf("shard_prefix_length %d out of range (1..64)", m.ShardPrefixLength)
	}
	if len(m.Shards) == 0 {
		return Manifest{}, errors.New("manifest has no shards")
	}
	for key, shard := range m.Shards {
		if len(key) != m.ShardPrefixLength {
			return Manifest{}, fmt.Errorf("shard key %q length %d, want %d", key, len(key), m.ShardPrefixLength)
		}
		if _, err := hex.DecodeString(key); err != nil {
			return Manifest{}, fmt.Errorf("shard key %q not hex: %w", key, err)
		}
		if shard.Path == "" {
			return Manifest{}, fmt.Errorf("shard %s: missing path", key)
		}
		if err := validateRelativeShardPath(shard.Path); err != nil {
			return Manifest{}, fmt.Errorf("shard %s: %w", key, err)
		}
		shaBytes, err := hex.DecodeString(shard.SHA256)
		if err != nil {
			return Manifest{}, fmt.Errorf("shard %s: decode sha256 hex: %w", key, err)
		}
		if len(shaBytes) != sha256.Size {
			return Manifest{}, fmt.Errorf("shard %s: sha256 length %d bytes, want %d", key, len(shaBytes), sha256.Size)
		}
	}
	return m, nil
}

func validateRelativeShardPath(path string) error {
	if filepath.IsAbs(path) {
		return fmt.Errorf("shard path %q must be relative", path)
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("shard path %q escapes base directory", path)
	}
	return nil
}

// BuildShardedSourceFromRecords splits records into shard files under
// baseDir/shards keyed by the first prefixLen hex chars of each record_id,
// signs each shard's bundle with privateKey, writes them to disk, and returns
// a Manifest indexing the shards. The manifest is NOT written to disk; the
// caller is responsible for persisting it (typically as baseDir/manifest.json).
func BuildShardedSourceFromRecords(ctx context.Context, baseDir, source string, records []Record, privateKey ed25519.PrivateKey, prefixLen int) (Manifest, error) {
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	if baseDir == "" {
		return Manifest{}, errors.New("build sharded source: empty baseDir")
	}
	if len(records) == 0 {
		return Manifest{}, errors.New("build sharded source: no records")
	}
	if prefixLen <= 0 || prefixLen > 64 {
		return Manifest{}, fmt.Errorf("build sharded source: prefix length %d out of range (1..64)", prefixLen)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return Manifest{}, fmt.Errorf("build sharded source: invalid ed25519 private key length %d, want %d", len(privateKey), ed25519.PrivateKeySize)
	}

	// Bucket records into shards in input order.
	buckets := map[string][]Record{}
	order := []string{}
	for i, rec := range records {
		if len(rec.RecordID) < prefixLen {
			return Manifest{}, fmt.Errorf("record %d: record_id %q shorter than prefix length %d", i, rec.RecordID, prefixLen)
		}
		prefix := strings.ToLower(rec.RecordID[:prefixLen])
		if _, err := hex.DecodeString(prefix); err != nil {
			return Manifest{}, fmt.Errorf("record %d: prefix %q not hex: %w", i, prefix, err)
		}
		if _, ok := buckets[prefix]; !ok {
			order = append(order, prefix)
		}
		buckets[prefix] = append(buckets[prefix], rec)
	}

	shardsDir := filepath.Join(baseDir, "shards")
	if err := os.MkdirAll(shardsDir, 0o755); err != nil {
		return Manifest{}, fmt.Errorf("build sharded source: create shards dir: %w", err)
	}

	shards := make(map[string]ShardInfo, len(buckets))
	for _, prefix := range order {
		if err := ctx.Err(); err != nil {
			return Manifest{}, err
		}
		bundle := Bundle{Version: BundleVersion, Source: source, Records: buckets[prefix]}
		signed, err := SignBundle(bundle, privateKey)
		if err != nil {
			return Manifest{}, fmt.Errorf("build sharded source: sign shard %s: %w", prefix, err)
		}
		data, err := MarshalSignedBundle(signed)
		if err != nil {
			return Manifest{}, fmt.Errorf("build sharded source: marshal shard %s: %w", prefix, err)
		}
		relPath := "shards/" + prefix + ".json"
		fullPath := filepath.Join(baseDir, relPath)
		if err := os.WriteFile(fullPath, data, 0o644); err != nil {
			return Manifest{}, fmt.Errorf("build sharded source: write shard %s: %w", prefix, err)
		}
		sum := sha256.Sum256(data)
		shards[prefix] = ShardInfo{
			Path:   relPath,
			SHA256: hex.EncodeToString(sum[:]),
			Count:  len(buckets[prefix]),
		}
	}

	return Manifest{
		Version:           ManifestVersion,
		Source:            source,
		ShardPrefixLength: prefixLen,
		Shards:            shards,
	}, nil
}

// LookupShardedFileSource hashes archivePath, loads the manifest, opens only
// the matching shard, verifies its SHA256 and signature, and returns the
// deduplicated decrypted passwords whose record_id matches the archive hash.
//
// A missing matching shard yields an empty result, not an error. No network
// access is performed.
func LookupShardedFileSource(ctx context.Context, source ShardedFileSource, archivePath string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source.BaseDir == "" && source.ManifestPath == "" {
		return nil, errors.New("hashdb sharded source: empty BaseDir and ManifestPath")
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("hashdb sharded source: open archive: %w", err)
	}
	digest := ArchiveHash(f)
	f.Close()

	manifestPath := source.ManifestPath
	if manifestPath == "" {
		manifestPath = filepath.Join(source.BaseDir, "manifest.json")
	}
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("hashdb sharded source: read manifest: %w", err)
	}
	manifest, err := ParseManifest(manifestData)
	if err != nil {
		return nil, fmt.Errorf("hashdb sharded source: parse manifest: %w", err)
	}

	recordIDHex := RecordID(digest).Hex()
	if len(recordIDHex) < manifest.ShardPrefixLength {
		return nil, fmt.Errorf("hashdb sharded source: record_id shorter than prefix length")
	}
	prefix := strings.ToLower(recordIDHex[:manifest.ShardPrefixLength])
	shard, ok := manifest.Shards[prefix]
	if !ok {
		return []string{}, nil
	}

	shardFull := filepath.Join(source.BaseDir, shard.Path)
	shardData, err := os.ReadFile(shardFull)
	if err != nil {
		return nil, fmt.Errorf("hashdb sharded source: read shard %s: %w", prefix, err)
	}
	// When Compression is empty, shard.SHA256 covers the raw on-disk bytes
	// (legacy/local case). When Compression is set, the cached on-disk file
	// holds decompressed bytes whose integrity is anchored by the bundle
	// signature below; the manifest sha256 covers the compressed mirror
	// bytes, which have already been verified at download time.
	if shard.Compression == "" {
		gotSum := sha256.Sum256(shardData)
		if hex.EncodeToString(gotSum[:]) != strings.ToLower(shard.SHA256) {
			return nil, fmt.Errorf("hashdb sharded source: shard %s sha256 mismatch", prefix)
		}
	}

	signed, err := ParseSignedBundle(shardData)
	if err != nil {
		return nil, fmt.Errorf("hashdb sharded source: parse shard %s: %w", prefix, err)
	}
	if source.PublicKey != "" {
		want := strings.ToLower(source.PublicKey)
		got := strings.ToLower(signed.PublicKey)
		if got != want {
			return nil, fmt.Errorf("hashdb sharded source: public key mismatch: shard %s, configured %s", got, want)
		}
	}
	bundle, err := VerifySignedBundle(signed)
	if err != nil {
		return nil, fmt.Errorf("hashdb sharded source: verify shard %s: %w", prefix, err)
	}

	matches, err := LookupBundle(bundle, digest)
	if err != nil {
		return nil, fmt.Errorf("hashdb sharded source: lookup: %w", err)
	}
	out := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, rec := range matches {
		pw, err := DecryptRecord(digest, rec)
		if err != nil {
			return nil, fmt.Errorf("hashdb sharded source: decrypt: %w", err)
		}
		if _, ok := seen[pw]; ok {
			continue
		}
		seen[pw] = struct{}{}
		out = append(out, pw)
	}
	return out, nil
}
