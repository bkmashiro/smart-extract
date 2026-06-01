package hashdb

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustGenKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func recordForArchive(t *testing.T, archivePath, password, source string) Record {
	t.Helper()
	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	digest := ArchiveHash(f)
	f.Close()
	rec, err := BuildRecord(digest, password, source)
	if err != nil {
		t.Fatalf("BuildRecord: %v", err)
	}
	return rec
}

func TestMarshalManifestFillsVersion(t *testing.T) {
	m := Manifest{
		ShardPrefixLength: 2,
		Shards: map[string]ShardInfo{
			"ab": {Path: "shards/ab.json", SHA256: strings.Repeat("00", 32)},
		},
	}
	data, err := MarshalManifest(m)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		t.Fatalf("unmarshal probe: %v", err)
	}
	var version int
	if err := json.Unmarshal(probe["version"], &version); err != nil {
		t.Fatalf("unmarshal version: %v", err)
	}
	if version != ManifestVersion {
		t.Fatalf("version = %d, want %d", version, ManifestVersion)
	}
}

func TestParseManifestRoundTrip(t *testing.T) {
	m := Manifest{
		Version:           ManifestVersion,
		Source:            "src",
		ShardPrefixLength: 2,
		Shards: map[string]ShardInfo{
			"ab": {Path: "shards/ab.json", SHA256: strings.Repeat("aa", 32), Count: 3},
		},
	}
	data, err := MarshalManifest(m)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}
	got, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if got.ShardPrefixLength != 2 || got.Source != "src" {
		t.Fatalf("unexpected manifest: %+v", got)
	}
	if got.Shards["ab"].Path != "shards/ab.json" || got.Shards["ab"].Count != 3 {
		t.Fatalf("unexpected shard: %+v", got.Shards["ab"])
	}
}

func TestParseManifestRejectsBadJSON(t *testing.T) {
	if _, err := ParseManifest([]byte("{not json")); err == nil {
		t.Fatalf("expected error on bad JSON")
	}
}

func TestParseManifestRejectsBadVersion(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"version":             999,
		"shard_prefix_length": 2,
		"shards": map[string]any{
			"ab": map[string]any{"path": "shards/ab.json", "sha256": strings.Repeat("00", 32)},
		},
	})
	if _, err := ParseManifest(data); err == nil {
		t.Fatalf("expected error on unsupported version")
	}
}

func TestParseManifestRejectsBadPrefixLength(t *testing.T) {
	cases := []int{0, -1, 65}
	for _, n := range cases {
		data, _ := json.Marshal(map[string]any{
			"version":             ManifestVersion,
			"shard_prefix_length": n,
			"shards": map[string]any{
				strings.Repeat("a", max(n, 1)): map[string]any{
					"path":   "p",
					"sha256": strings.Repeat("00", 32),
				},
			},
		})
		if _, err := ParseManifest(data); err == nil {
			t.Fatalf("expected error on prefix length %d", n)
		}
	}
}

func TestParseManifestRejectsEmptyShards(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"version":             ManifestVersion,
		"shard_prefix_length": 2,
		"shards":              map[string]any{},
	})
	if _, err := ParseManifest(data); err == nil {
		t.Fatalf("expected error on empty shards")
	}
}

func TestParseManifestRejectsMissingShardPath(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"version":             ManifestVersion,
		"shard_prefix_length": 2,
		"shards": map[string]any{
			"ab": map[string]any{"path": "", "sha256": strings.Repeat("00", 32)},
		},
	})
	if _, err := ParseManifest(data); err == nil {
		t.Fatalf("expected error on missing shard path")
	}
}

func TestParseManifestRejectsUnsafeShardPath(t *testing.T) {
	for _, path := range []string{"/tmp/ab.json", "../ab.json", "shards/../../ab.json"} {
		data, _ := json.Marshal(map[string]any{
			"version":             ManifestVersion,
			"shard_prefix_length": 2,
			"shards": map[string]any{
				"ab": map[string]any{"path": path, "sha256": strings.Repeat("00", 32)},
			},
		})
		if _, err := ParseManifest(data); err == nil {
			t.Fatalf("expected error on unsafe shard path %q", path)
		}
	}
}

func TestParseManifestRejectsBadShardSHA256(t *testing.T) {
	bad := []string{"zz", strings.Repeat("0", 63), strings.Repeat("0", 65), ""}
	for _, sha := range bad {
		data, _ := json.Marshal(map[string]any{
			"version":             ManifestVersion,
			"shard_prefix_length": 2,
			"shards": map[string]any{
				"ab": map[string]any{"path": "p", "sha256": sha},
			},
		})
		if _, err := ParseManifest(data); err == nil {
			t.Fatalf("expected error on bad sha256 %q", sha)
		}
	}
}

func TestParseManifestRejectsShardKeyWrongLength(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"version":             ManifestVersion,
		"shard_prefix_length": 2,
		"shards": map[string]any{
			"abc": map[string]any{"path": "p", "sha256": strings.Repeat("00", 32)},
		},
	})
	if _, err := ParseManifest(data); err == nil {
		t.Fatalf("expected error on wrong shard key length")
	}
}

func TestParseManifestRoundTripWithShardCompression(t *testing.T) {
	m := Manifest{
		Version:           ManifestVersion,
		Source:            "src",
		ShardPrefixLength: 2,
		Shards: map[string]ShardInfo{
			"ab": {Path: "shards/ab.json.gz", SHA256: strings.Repeat("bb", 32), Count: 1, Compression: "gzip"},
		},
	}
	data, err := MarshalManifest(m)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}
	got, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if got.Shards["ab"].Compression != "gzip" {
		t.Fatalf("Compression = %q, want gzip", got.Shards["ab"].Compression)
	}
	if got.Shards["ab"].Path != "shards/ab.json.gz" {
		t.Fatalf("Path = %q", got.Shards["ab"].Path)
	}
}

func TestParseManifestAcceptsLegacyShardWithoutCompression(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"version":             ManifestVersion,
		"shard_prefix_length": 2,
		"shards": map[string]any{
			"ab": map[string]any{
				"path":   "shards/ab.json",
				"sha256": strings.Repeat("00", 32),
				"count":  2,
			},
		},
	})
	got, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("ParseManifest legacy: %v", err)
	}
	if got.Shards["ab"].Compression != "" {
		t.Fatalf("legacy Compression = %q, want empty", got.Shards["ab"].Compression)
	}
}

func TestParseManifestRejectsNonHexShardKey(t *testing.T) {
	data, _ := json.Marshal(map[string]any{
		"version":             ManifestVersion,
		"shard_prefix_length": 2,
		"shards": map[string]any{
			"zz": map[string]any{"path": "p", "sha256": strings.Repeat("00", 32)},
		},
	})
	if _, err := ParseManifest(data); err == nil {
		t.Fatalf("expected error on non-hex shard key")
	}
}

func TestBuildShardedSourceFromRecordsWritesShards(t *testing.T) {
	dir := t.TempDir()

	a := filepath.Join(dir, "a.zip")
	b := filepath.Join(dir, "b.zip")
	c := filepath.Join(dir, "c.zip")
	for _, p := range []struct {
		path    string
		content []byte
	}{
		{a, []byte("AAA-content")},
		{b, []byte("BBB-content")},
		{c, []byte("CCC-content")},
	} {
		if err := os.WriteFile(p.path, p.content, 0o644); err != nil {
			t.Fatalf("write %s: %v", p.path, err)
		}
	}

	recA := recordForArchive(t, a, "pwA", "srcA")
	recB := recordForArchive(t, b, "pwB", "srcB")
	recC := recordForArchive(t, c, "pwC", "srcC")
	records := []Record{recA, recB, recC}

	_, priv := mustGenKey(t)
	manifest, err := BuildShardedSourceFromRecords(context.Background(), dir, "test-source", records, priv, 2)
	if err != nil {
		t.Fatalf("BuildShardedSourceFromRecords: %v", err)
	}
	if manifest.Version != ManifestVersion {
		t.Fatalf("manifest.Version = %d, want %d", manifest.Version, ManifestVersion)
	}
	if manifest.ShardPrefixLength != 2 {
		t.Fatalf("manifest.ShardPrefixLength = %d, want 2", manifest.ShardPrefixLength)
	}
	if manifest.Source != "test-source" {
		t.Fatalf("manifest.Source = %q, want test-source", manifest.Source)
	}
	if len(manifest.Shards) == 0 {
		t.Fatalf("expected non-empty shards")
	}

	// Sum of counts across shards must equal total records.
	total := 0
	for prefix, shard := range manifest.Shards {
		if shard.Path == "" {
			t.Fatalf("shard %s has empty path", prefix)
		}
		expectedName := "shards/" + prefix + ".json"
		if shard.Path != expectedName {
			t.Fatalf("shard %s path = %q, want %q", prefix, shard.Path, expectedName)
		}
		// Verify file exists and SHA256 matches.
		full := filepath.Join(dir, shard.Path)
		data, err := os.ReadFile(full)
		if err != nil {
			t.Fatalf("read shard %s: %v", full, err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != shard.SHA256 {
			t.Fatalf("shard %s sha256 mismatch", prefix)
		}
		// Verify shard is a parseable signed bundle.
		signed, err := ParseSignedBundle(data)
		if err != nil {
			t.Fatalf("ParseSignedBundle shard %s: %v", prefix, err)
		}
		bundle, err := VerifySignedBundle(signed)
		if err != nil {
			t.Fatalf("VerifySignedBundle shard %s: %v", prefix, err)
		}
		if shard.Count != len(bundle.Records) {
			t.Fatalf("shard %s Count = %d, bundle records = %d", prefix, shard.Count, len(bundle.Records))
		}
		// All records in this shard must share the prefix.
		for _, r := range bundle.Records {
			if r.RecordID[:2] != prefix {
				t.Fatalf("shard %s contains record with prefix %s", prefix, r.RecordID[:2])
			}
		}
		total += shard.Count
	}
	if total != 3 {
		t.Fatalf("sum of shard counts = %d, want 3", total)
	}
}

func TestBuildShardedSourceFromRecordsDeterministicBytes(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	a := filepath.Join(dir1, "a.zip")
	if err := os.WriteFile(a, []byte("payload-A"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a2 := filepath.Join(dir2, "a.zip")
	if err := os.WriteFile(a2, []byte("payload-A"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	rec1 := recordForArchive(t, a, "pw", "")
	// Force same nonce by reusing the record object across both builds.
	records := []Record{rec1}
	_, priv := mustGenKey(t)

	m1, err := BuildShardedSourceFromRecords(context.Background(), dir1, "src", records, priv, 2)
	if err != nil {
		t.Fatalf("build1: %v", err)
	}
	m2, err := BuildShardedSourceFromRecords(context.Background(), dir2, "src", records, priv, 2)
	if err != nil {
		t.Fatalf("build2: %v", err)
	}
	// Manifests for identical input should reference identical shard bytes.
	for prefix, s1 := range m1.Shards {
		s2, ok := m2.Shards[prefix]
		if !ok {
			t.Fatalf("missing shard %s in second build", prefix)
		}
		if s1.SHA256 != s2.SHA256 {
			t.Fatalf("shard %s sha mismatch: %s vs %s", prefix, s1.SHA256, s2.SHA256)
		}
	}
}

func TestBuildShardedSourceFromRecordsRejectsBadInputs(t *testing.T) {
	dir := t.TempDir()
	_, priv := mustGenKey(t)
	if _, err := BuildShardedSourceFromRecords(context.Background(), dir, "src", nil, priv, 2); err == nil {
		t.Fatalf("expected error on empty records")
	}

	a := filepath.Join(dir, "a.zip")
	if err := os.WriteFile(a, []byte("X"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	rec := recordForArchive(t, a, "pw", "")
	if _, err := BuildShardedSourceFromRecords(context.Background(), dir, "src", []Record{rec}, priv, 0); err == nil {
		t.Fatalf("expected error on prefix length 0")
	}
	if _, err := BuildShardedSourceFromRecords(context.Background(), dir, "src", []Record{rec}, priv, 65); err == nil {
		t.Fatalf("expected error on prefix length 65")
	}
	if _, err := BuildShardedSourceFromRecords(context.Background(), dir, "src", []Record{rec}, ed25519.PrivateKey(nil), 2); err == nil {
		t.Fatalf("expected error on invalid private key")
	}
	if _, err := BuildShardedSourceFromRecords(context.Background(), "", "src", []Record{rec}, priv, 2); err == nil {
		t.Fatalf("expected error on empty baseDir")
	}
}

func TestLookupShardedFileSourceLoadsMatchingShard(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.zip")
	b := filepath.Join(dir, "b.zip")
	if err := os.WriteFile(a, []byte("archive-A-bytes"), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(b, []byte("archive-B-bytes"), 0o644); err != nil {
		t.Fatalf("write b: %v", err)
	}
	records := []Record{
		recordForArchive(t, a, "pwA1", ""),
		recordForArchive(t, a, "pwA2", ""),
		recordForArchive(t, b, "pwB", ""),
	}

	pub, priv := mustGenKey(t)
	if _, err := BuildShardedSourceFromRecords(context.Background(), dir, "src", records, priv, 2); err != nil {
		t.Fatalf("BuildShardedSourceFromRecords: %v", err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	// BuildShardedSourceFromRecords does not write the manifest; the caller does.
	// But we provide a default location via convention: ManifestPath empty => BaseDir/manifest.json.
	// For the test we will write it ourselves.
	manifest, err := BuildShardedSourceFromRecords(context.Background(), dir, "src", records, priv, 2)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	data, err := MarshalManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	got, err := LookupShardedFileSource(context.Background(), ShardedFileSource{
		Name:      "sharded",
		BaseDir:   dir,
		PublicKey: hex.EncodeToString(pub),
	}, a)
	if err != nil {
		t.Fatalf("LookupShardedFileSource: %v", err)
	}
	want := []string{"pwA1", "pwA2"}
	if len(got) != len(want) {
		t.Fatalf("got = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLookupShardedFileSourceEmptyOnNoShard(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.zip")
	other := filepath.Join(dir, "other.zip")
	if err := os.WriteFile(a, []byte("X"), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(other, []byte("different"), 0o644); err != nil {
		t.Fatalf("write other: %v", err)
	}
	records := []Record{recordForArchive(t, a, "pw", "")}

	pub, priv := mustGenKey(t)
	manifest, err := BuildShardedSourceFromRecords(context.Background(), dir, "src", records, priv, 2)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Force the "other" archive's prefix to not exist in manifest by ensuring
	// it differs. If by coincidence it shares prefix, this test would be weak;
	// however, with 2-hex prefix the collision space is small enough that the
	// "other" content above is chosen to avoid clashes. We assert behavior by
	// rewriting manifest to drop the shard that matches "other" if present.
	otherF, err := os.Open(other)
	if err != nil {
		t.Fatalf("open other: %v", err)
	}
	otherDigest := ArchiveHash(otherF)
	otherF.Close()
	otherPrefix := RecordID(otherDigest).Hex()[:2]
	if _, exists := manifest.Shards[otherPrefix]; exists {
		delete(manifest.Shards, otherPrefix)
	}
	data, err := MarshalManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	got, err := LookupShardedFileSource(context.Background(), ShardedFileSource{
		BaseDir:   dir,
		PublicKey: hex.EncodeToString(pub),
	}, other)
	if err != nil {
		t.Fatalf("LookupShardedFileSource: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty result, got %v", got)
	}
}

func TestLookupShardedFileSourceRejectsTamperedShard(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.zip")
	if err := os.WriteFile(a, []byte("tamper-test"), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	records := []Record{recordForArchive(t, a, "pw", "")}
	pub, priv := mustGenKey(t)
	manifest, err := BuildShardedSourceFromRecords(context.Background(), dir, "src", records, priv, 2)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	data, err := MarshalManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	// Tamper with the matching shard file (rewrite contents to garbage that
	// won't match the manifest sha256).
	for _, shard := range manifest.Shards {
		full := filepath.Join(dir, shard.Path)
		if err := os.WriteFile(full, []byte("tampered-junk"), 0o644); err != nil {
			t.Fatalf("rewrite shard: %v", err)
		}
	}

	_, err = LookupShardedFileSource(context.Background(), ShardedFileSource{
		BaseDir:   dir,
		PublicKey: hex.EncodeToString(pub),
	}, a)
	if err == nil {
		t.Fatalf("expected error on tampered shard")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "sha") {
		t.Fatalf("expected sha-mismatch error, got: %v", err)
	}
}

func TestLookupShardedFileSourceRejectsPublicKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.zip")
	if err := os.WriteFile(a, []byte("pk-mismatch"), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	records := []Record{recordForArchive(t, a, "pw", "")}
	_, priv := mustGenKey(t)
	manifest, err := BuildShardedSourceFromRecords(context.Background(), dir, "src", records, priv, 2)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	data, err := MarshalManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, err = LookupShardedFileSource(context.Background(), ShardedFileSource{
		BaseDir:   dir,
		PublicKey: hex.EncodeToString(otherPub),
	}, a)
	if err == nil {
		t.Fatalf("expected error on public key mismatch")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "public") {
		t.Fatalf("expected public-key error, got: %v", err)
	}
}

func TestLookupShardedFileSourceUsesExplicitManifestPath(t *testing.T) {
	dir := t.TempDir()
	manifestDir := t.TempDir()
	a := filepath.Join(dir, "a.zip")
	if err := os.WriteFile(a, []byte("explicit-manifest"), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	records := []Record{recordForArchive(t, a, "the-pw", "")}
	pub, priv := mustGenKey(t)
	manifest, err := BuildShardedSourceFromRecords(context.Background(), dir, "src", records, priv, 2)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	data, err := MarshalManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}
	mpath := filepath.Join(manifestDir, "manifest.json")
	if err := os.WriteFile(mpath, data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	got, err := LookupShardedFileSource(context.Background(), ShardedFileSource{
		BaseDir:      dir,
		ManifestPath: mpath,
		PublicKey:    hex.EncodeToString(pub),
	}, a)
	if err != nil {
		t.Fatalf("LookupShardedFileSource: %v", err)
	}
	if len(got) != 1 || got[0] != "the-pw" {
		t.Fatalf("got = %v, want [the-pw]", got)
	}
}

func TestLookupShardedFileSourceDedupes(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.zip")
	if err := os.WriteFile(a, []byte("dedupe-bytes"), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	rec1 := recordForArchive(t, a, "pw1", "")
	rec2 := recordForArchive(t, a, "pw2", "")
	rec3 := recordForArchive(t, a, "pw1", "")
	records := []Record{rec1, rec2, rec3}

	pub, priv := mustGenKey(t)
	manifest, err := BuildShardedSourceFromRecords(context.Background(), dir, "src", records, priv, 2)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	data, err := MarshalManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	got, err := LookupShardedFileSource(context.Background(), ShardedFileSource{
		BaseDir:   dir,
		PublicKey: hex.EncodeToString(pub),
	}, a)
	if err != nil {
		t.Fatalf("LookupShardedFileSource: %v", err)
	}
	want := []string{"pw1", "pw2"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got = %v, want %v", got, want)
	}
}
