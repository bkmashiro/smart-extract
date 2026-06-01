package hashdb

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pickDistinctPrefixArchives creates n archive files in dir whose RecordID
// prefixes of length prefixLen are pairwise distinct, returning their paths.
func pickDistinctPrefixArchives(t *testing.T, dir string, prefixLen, n int) []string {
	t.Helper()
	paths := make([]string, 0, n)
	seen := make(map[string]struct{}, n)
	for i := 0; len(paths) < n; i++ {
		if i > 10000 {
			t.Fatalf("could not find %d archives with distinct %d-hex prefixes", n, prefixLen)
		}
		name := fmt.Sprintf("arc-%d.bin", i)
		path := filepath.Join(dir, name)
		content := []byte(fmt.Sprintf("archive-bytes-%d", i))
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatalf("write archive: %v", err)
		}
		digest := archiveDigestOf(t, path)
		prefix := RecordID(digest).Hex()[:prefixLen]
		if _, ok := seen[prefix]; ok {
			_ = os.Remove(path)
			continue
		}
		seen[prefix] = struct{}{}
		paths = append(paths, path)
	}
	return paths
}

func prefixOf(t *testing.T, archivePath string, prefixLen int) string {
	t.Helper()
	digest := archiveDigestOf(t, archivePath)
	return RecordID(digest).Hex()[:prefixLen]
}

func TestAppendShardedSourceRecordsCreatesManifest(t *testing.T) {
	dir := t.TempDir()
	archives := pickDistinctPrefixArchives(t, dir, 2, 2)
	a, b := archives[0], archives[1]

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	manifest, err := AppendShardedSourceRecords(context.Background(), dir, "local-src", []ArchivePassword{
		{ArchivePath: a, Password: "pw-A"},
		{ArchivePath: b, Password: "pw-B"},
	}, priv, 2)
	if err != nil {
		t.Fatalf("AppendShardedSourceRecords: %v", err)
	}
	if manifest.Version != ManifestVersion {
		t.Fatalf("manifest.Version = %d, want %d", manifest.Version, ManifestVersion)
	}
	if manifest.ShardPrefixLength != 2 {
		t.Fatalf("manifest.ShardPrefixLength = %d, want 2", manifest.ShardPrefixLength)
	}
	if manifest.Source != "local-src" {
		t.Fatalf("manifest.Source = %q, want local-src", manifest.Source)
	}
	if len(manifest.Shards) != 2 {
		t.Fatalf("len(shards) = %d, want 2", len(manifest.Shards))
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	info, err := os.Stat(manifestPath)
	if err != nil {
		t.Fatalf("stat manifest: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Fatalf("manifest mode = %o, want 0644", mode)
	}

	// Roundtrip lookup.
	got, err := LookupShardedFileSource(context.Background(), ShardedFileSource{
		BaseDir:   dir,
		PublicKey: hex.EncodeToString(pub),
	}, a)
	if err != nil {
		t.Fatalf("LookupShardedFileSource A: %v", err)
	}
	if len(got) != 1 || got[0] != "pw-A" {
		t.Fatalf("got A = %v, want [pw-A]", got)
	}
}

func TestAppendShardedSourceRecordsAppendsNewShard(t *testing.T) {
	dir := t.TempDir()
	archives := pickDistinctPrefixArchives(t, dir, 2, 2)
	a, b := archives[0], archives[1]

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: a, Password: "pw-A"},
	}, priv, 2); err != nil {
		t.Fatalf("first append: %v", err)
	}

	manifest, err := AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: b, Password: "pw-B"},
	}, priv, 2)
	if err != nil {
		t.Fatalf("second append: %v", err)
	}
	if len(manifest.Shards) != 2 {
		t.Fatalf("len(shards) = %d, want 2", len(manifest.Shards))
	}

	for _, archive := range []string{a, b} {
		want := "pw-A"
		if archive == b {
			want = "pw-B"
		}
		got, err := LookupShardedFileSource(context.Background(), ShardedFileSource{
			BaseDir:   dir,
			PublicKey: hex.EncodeToString(pub),
		}, archive)
		if err != nil {
			t.Fatalf("Lookup %s: %v", archive, err)
		}
		if len(got) != 1 || got[0] != want {
			t.Fatalf("got %v, want [%s]", got, want)
		}
	}
}

func TestAppendShardedSourceRecordsMergesIntoExistingShard(t *testing.T) {
	dir := t.TempDir()
	archives := pickDistinctPrefixArchives(t, dir, 2, 1)
	a := archives[0]

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: a, Password: "pw-1"},
	}, priv, 2); err != nil {
		t.Fatalf("first append: %v", err)
	}

	manifest, err := AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: a, Password: "pw-2"}, // distinct pw same archive -> kept
		{ArchivePath: a, Password: "pw-1"}, // duplicate -> dropped
	}, priv, 2)
	if err != nil {
		t.Fatalf("second append: %v", err)
	}
	if len(manifest.Shards) != 1 {
		t.Fatalf("len(shards) = %d, want 1", len(manifest.Shards))
	}
	for prefix, shard := range manifest.Shards {
		if shard.Count != 2 {
			t.Fatalf("shard %s Count = %d, want 2", prefix, shard.Count)
		}
	}

	got, err := LookupShardedFileSource(context.Background(), ShardedFileSource{
		BaseDir:   dir,
		PublicKey: hex.EncodeToString(pub),
	}, a)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 2 || got[0] != "pw-1" || got[1] != "pw-2" {
		t.Fatalf("got = %v, want [pw-1 pw-2]", got)
	}
}

func TestAppendShardedSourceRecordsDoesNotRewriteUnaffectedShards(t *testing.T) {
	dir := t.TempDir()
	archives := pickDistinctPrefixArchives(t, dir, 2, 2)
	a, b := archives[0], archives[1]

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: a, Password: "pw-A"},
	}, priv, 2); err != nil {
		t.Fatalf("first append: %v", err)
	}

	aPrefix := prefixOf(t, a, 2)
	aShardPath := filepath.Join(dir, "shards", aPrefix+".json")
	beforeBytes, err := os.ReadFile(aShardPath)
	if err != nil {
		t.Fatalf("read unaffected shard: %v", err)
	}
	beforeSum := sha256.Sum256(beforeBytes)
	beforeInfo, err := os.Stat(aShardPath)
	if err != nil {
		t.Fatalf("stat unaffected: %v", err)
	}
	beforeMod := beforeInfo.ModTime()

	// Sleep 10ms so modtimes are clearly distinguishable if the file changes.
	time.Sleep(10 * time.Millisecond)

	if _, err := AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: b, Password: "pw-B"},
	}, priv, 2); err != nil {
		t.Fatalf("second append: %v", err)
	}

	afterBytes, err := os.ReadFile(aShardPath)
	if err != nil {
		t.Fatalf("read unaffected shard after: %v", err)
	}
	afterSum := sha256.Sum256(afterBytes)
	if afterSum != beforeSum {
		t.Fatalf("unaffected shard %s content changed after append to a different prefix", aPrefix)
	}
	afterInfo, err := os.Stat(aShardPath)
	if err != nil {
		t.Fatalf("stat unaffected after: %v", err)
	}
	if !afterInfo.ModTime().Equal(beforeMod) {
		t.Fatalf("unaffected shard %s modtime changed (%v -> %v)", aPrefix, beforeMod, afterInfo.ModTime())
	}
}

func TestAppendShardedSourceRecordsRejectsKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	archives := pickDistinctPrefixArchives(t, dir, 2, 1)
	a := archives[0]

	_, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: a, Password: "pw"},
	}, priv1, 2); err != nil {
		t.Fatalf("first append: %v", err)
	}
	_, err = AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: a, Password: "pw-2"},
	}, priv2, 2)
	if err == nil {
		t.Fatalf("expected key mismatch error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "key") {
		t.Fatalf("expected key-mismatch error, got: %v", err)
	}
}

func TestAppendShardedSourceRecordsRejectsTamperedShardWithoutMutating(t *testing.T) {
	dir := t.TempDir()
	archives := pickDistinctPrefixArchives(t, dir, 2, 1)
	a := archives[0]

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: a, Password: "pw-1"},
	}, priv, 2); err != nil {
		t.Fatalf("first append: %v", err)
	}

	prefix := prefixOf(t, a, 2)
	shardPath := filepath.Join(dir, "shards", prefix+".json")
	if err := os.WriteFile(shardPath, []byte("tampered-junk"), 0o644); err != nil {
		t.Fatalf("tamper shard: %v", err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	manifestBefore, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest before: %v", err)
	}
	shardBefore, err := os.ReadFile(shardPath)
	if err != nil {
		t.Fatalf("read shard before: %v", err)
	}

	_, err = AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: a, Password: "pw-2"},
	}, priv, 2)
	if err == nil {
		t.Fatalf("expected error on tampered shard")
	}

	manifestAfter, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest after: %v", err)
	}
	if string(manifestBefore) != string(manifestAfter) {
		t.Fatalf("manifest mutated after rejected append")
	}
	shardAfter, err := os.ReadFile(shardPath)
	if err != nil {
		t.Fatalf("read shard after: %v", err)
	}
	if string(shardBefore) != string(shardAfter) {
		t.Fatalf("shard mutated after rejected append")
	}
}

func TestAppendShardedSourceRecordsRejectsPrefixLengthMismatch(t *testing.T) {
	dir := t.TempDir()
	archives := pickDistinctPrefixArchives(t, dir, 2, 1)
	a := archives[0]

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: a, Password: "pw-1"},
	}, priv, 2); err != nil {
		t.Fatalf("first append: %v", err)
	}
	_, err = AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: a, Password: "pw-2"},
	}, priv, 4)
	if err == nil {
		t.Fatalf("expected prefix length mismatch error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "prefix") {
		t.Fatalf("expected prefix-length error, got: %v", err)
	}
}

func TestAppendShardedSourceRecordsZeroPrefixUsesExisting(t *testing.T) {
	dir := t.TempDir()
	archives := pickDistinctPrefixArchives(t, dir, 2, 1)
	a := archives[0]

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: a, Password: "pw-1"},
	}, priv, 2); err != nil {
		t.Fatalf("first append: %v", err)
	}
	manifest, err := AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: a, Password: "pw-2"},
	}, priv, 0)
	if err != nil {
		t.Fatalf("append with prefixLen=0: %v", err)
	}
	if manifest.ShardPrefixLength != 2 {
		t.Fatalf("ShardPrefixLength = %d, want 2 (inherited)", manifest.ShardPrefixLength)
	}
	got, err := LookupShardedFileSource(context.Background(), ShardedFileSource{
		BaseDir:   dir,
		PublicKey: hex.EncodeToString(pub),
	}, a)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 2 || got[0] != "pw-1" || got[1] != "pw-2" {
		t.Fatalf("got = %v, want [pw-1 pw-2]", got)
	}
}

func TestAppendShardedSourceRecordsRejectsInvalidManifest(t *testing.T) {
	dir := t.TempDir()
	archives := pickDistinctPrefixArchives(t, dir, 2, 1)
	a := archives[0]
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("not json"), 0o644); err != nil {
		t.Fatalf("write bad manifest: %v", err)
	}
	_, err = AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: a, Password: "pw"},
	}, priv, 2)
	if err == nil {
		t.Fatalf("expected error on invalid manifest")
	}
}

func TestAppendShardedSourceRecordsNoPlaintextLeak(t *testing.T) {
	dir := t.TempDir()
	archives := pickDistinctPrefixArchives(t, dir, 2, 1)
	a := archives[0]
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: a, Password: "PLAIN-PW"},
	}, priv, 2); err != nil {
		t.Fatalf("append: %v", err)
	}
	digest := archiveDigestOf(t, a)
	rawHashHex := digest.Hex()
	prefix := prefixOf(t, a, 2)
	shardPath := filepath.Join(dir, "shards", prefix+".json")
	shardBytes, err := os.ReadFile(shardPath)
	if err != nil {
		t.Fatalf("read shard: %v", err)
	}
	if strings.Contains(string(shardBytes), "PLAIN-PW") {
		t.Fatalf("shard contains plaintext password")
	}
	if strings.Contains(string(shardBytes), rawHashHex) {
		t.Fatalf("shard contains raw archive hash hex")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if strings.Contains(string(manifestBytes), "PLAIN-PW") {
		t.Fatalf("manifest contains plaintext password")
	}
	if strings.Contains(string(manifestBytes), rawHashHex) {
		t.Fatalf("manifest contains raw archive hash hex")
	}
}

func TestAppendShardedSourceRecordsRejectsBadInputs(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := AppendShardedSourceRecords(context.Background(), "", "src", nil, priv, 2); err == nil {
		t.Fatalf("expected error on empty baseDir")
	}
	if _, err := AppendShardedSourceRecords(context.Background(), dir, "src", nil, priv, 2); err == nil {
		t.Fatalf("expected error on no inputs")
	}
	archives := pickDistinctPrefixArchives(t, dir, 2, 1)
	if _, err := AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: archives[0], Password: "pw"},
	}, ed25519.PrivateKey(nil), 2); err == nil {
		t.Fatalf("expected error on invalid private key")
	}
	if _, err := AppendShardedSourceRecords(context.Background(), dir, "src", []ArchivePassword{
		{ArchivePath: archives[0], Password: "pw"},
	}, priv, 65); err == nil {
		t.Fatalf("expected error on prefix length out of range")
	}
}
