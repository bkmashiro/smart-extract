package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bkmashiro/smart-extract/internal/config"
	"github.com/bkmashiro/smart-extract/internal/hashdb"
)

// HashDBVerifyResult is the outcome of verifying a single configured HashDB
// source. Status is one of "ok", "error", or "missing_cache".
//
// HashDBVerifyResult is intentionally redacted-friendly: Path and Message are
// produced from filesystem paths and underlying error text, so callers that
// surface them in user-facing output should still run them through
// sanitizeDebugLine before printing.
type HashDBVerifyResult struct {
	Name     string
	Type     string
	Status   string
	Message  string
	Path     string
	Records  int
	Shards   int
	Disabled bool
}

// HashDBVerifySource verifies a single configured HashDB source by name. The
// call is offline and read-only: no network I/O, no cache mutation, no
// learning observation, no config write.
func HashDBVerifySource(name string) (HashDBVerifyResult, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return HashDBVerifyResult{}, fmt.Errorf("source name is required")
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return HashDBVerifyResult{}, err
	}
	for _, src := range cfg.HashDB.Sources {
		if src.Name == name {
			return verifyHashDBSource(src), nil
		}
	}
	return HashDBVerifyResult{}, fmt.Errorf("hashdb source %q not found", name)
}

// HashDBVerifyAllSources verifies every configured HashDB source in config
// order. The call is offline and read-only (see HashDBVerifySource).
func HashDBVerifyAllSources() ([]HashDBVerifyResult, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}
	out := make([]HashDBVerifyResult, 0, len(cfg.HashDB.Sources))
	for _, src := range cfg.HashDB.Sources {
		out = append(out, verifyHashDBSource(src))
	}
	return out, nil
}

// FormatHashDBVerifyResult renders a single result as a sanitized one-line
// text record suitable for the CLI. Paths and error text are passed through
// sanitizeDebugLine.
func FormatHashDBVerifyResult(r HashDBVerifyResult) string {
	mark := "✓"
	if r.Status != "ok" {
		mark = "✗"
	}
	disabled := ""
	if r.Disabled {
		disabled = " [disabled]"
	}
	head := fmt.Sprintf("%s %s (%s)%s:", mark, sanitizeDebugLine(r.Name), sanitizeDebugLine(r.Type), disabled)
	switch r.Status {
	case "ok":
		if r.Type == "sharded" {
			return fmt.Sprintf("%s ok shards=%d records=%d manifest=%s", head, r.Shards, r.Records, sanitizeDebugLine(r.Path))
		}
		return fmt.Sprintf("%s ok records=%d path=%s", head, r.Records, sanitizeDebugLine(r.Path))
	case "missing_cache":
		return fmt.Sprintf("%s missing_cache cache=%s", head, sanitizeDebugLine(r.Path))
	default:
		return fmt.Sprintf("%s error: %s", head, sanitizeDebugLine(r.Message))
	}
}

func verifyHashDBSource(src config.HashDBSource) HashDBVerifyResult {
	res := HashDBVerifyResult{
		Name:     src.Name,
		Type:     sourceTypeOrDefault(src.Type),
		Disabled: src.Disabled,
	}
	switch res.Type {
	case "bundle":
		verifyHashDBBundleSource(src, &res)
	case "sharded":
		verifyHashDBShardedSource(src, &res)
	default:
		res.Status = "error"
		res.Message = fmt.Sprintf("unsupported source type %q", src.Type)
	}
	return res
}

func verifyHashDBBundleSource(src config.HashDBSource, res *HashDBVerifyResult) {
	path := strings.TrimSpace(src.Path)
	if path == "" {
		if strings.TrimSpace(src.URL) == "" {
			res.Status = "error"
			res.Message = "bundle source has no path or url"
			return
		}
		cacheRoot, err := hashDBSourceCacheRoot(src)
		if err != nil {
			res.Status = "error"
			res.Message = err.Error()
			return
		}
		cachedPath := filepath.Join(cacheRoot, "bundle.json")
		if _, err := os.Stat(cachedPath); err != nil {
			res.Status = "missing_cache"
			res.Path = cachedPath
			res.Message = "no cached bundle"
			return
		}
		path = cachedPath
	}
	res.Path = path
	data, err := os.ReadFile(path)
	if err != nil {
		res.Status = "error"
		res.Message = err.Error()
		return
	}
	signed, err := hashdb.ParseSignedBundle(data)
	if err != nil {
		res.Status = "error"
		res.Message = err.Error()
		return
	}
	if pinned := strings.TrimSpace(src.PublicKey); pinned != "" {
		want := strings.ToLower(pinned)
		got := strings.ToLower(signed.PublicKey)
		if want != got {
			res.Status = "error"
			res.Message = fmt.Sprintf("public key mismatch: bundle %s, configured %s", got, want)
			return
		}
	}
	bundle, err := hashdb.VerifySignedBundle(signed)
	if err != nil {
		res.Status = "error"
		res.Message = err.Error()
		return
	}
	res.Status = "ok"
	res.Records = len(bundle.Records)
}

func verifyHashDBShardedSource(src config.HashDBSource, res *HashDBVerifyResult) {
	baseDir := strings.TrimSpace(src.BaseDir)
	manifestPath := strings.TrimSpace(src.ManifestPath)
	isHTTP := false
	if baseDir == "" && manifestPath == "" {
		if strings.TrimSpace(src.ManifestURL) == "" {
			res.Status = "error"
			res.Message = "sharded source has no base_dir, manifest_path, or manifest_url"
			return
		}
		isHTTP = true
	} else if baseDir == "" && manifestPath != "" {
		baseDir = filepath.Dir(manifestPath)
	}
	if isHTTP {
		cacheRoot, err := hashDBSourceCacheRoot(src)
		if err != nil {
			res.Status = "error"
			res.Message = err.Error()
			return
		}
		baseDir = cacheRoot
		manifestPath = filepath.Join(cacheRoot, "manifest.json")
		if _, err := os.Stat(manifestPath); err != nil {
			res.Status = "missing_cache"
			res.Path = cacheRoot
			res.Message = "no cached manifest"
			return
		}
	}
	if manifestPath == "" {
		manifestPath = filepath.Join(baseDir, "manifest.json")
	}
	res.Path = manifestPath
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		res.Status = "error"
		res.Message = err.Error()
		return
	}
	manifest, err := hashdb.ParseManifest(data)
	if err != nil {
		res.Status = "error"
		res.Message = err.Error()
		return
	}

	verifiedShards := 0
	totalRecords := 0
	pinned := strings.ToLower(strings.TrimSpace(src.PublicKey))
	for prefix, shard := range manifest.Shards {
		shardPath := filepath.Join(baseDir, shard.Path)
		shardData, readErr := os.ReadFile(shardPath)
		if readErr != nil {
			if isHTTP && os.IsNotExist(readErr) {
				continue
			}
			res.Status = "error"
			res.Message = fmt.Sprintf("shard %s: %v", prefix, readErr)
			return
		}
		if shard.Compression == "" {
			sum := sha256.Sum256(shardData)
			if hex.EncodeToString(sum[:]) != strings.ToLower(shard.SHA256) {
				res.Status = "error"
				res.Message = fmt.Sprintf("shard %s: sha256 mismatch", prefix)
				return
			}
		}
		signed, err := hashdb.ParseSignedBundle(shardData)
		if err != nil {
			res.Status = "error"
			res.Message = fmt.Sprintf("shard %s: %v", prefix, err)
			return
		}
		if pinned != "" {
			got := strings.ToLower(signed.PublicKey)
			if got != pinned {
				res.Status = "error"
				res.Message = fmt.Sprintf("shard %s: public key mismatch: shard %s, configured %s", prefix, got, pinned)
				return
			}
		}
		bundle, err := hashdb.VerifySignedBundle(signed)
		if err != nil {
			res.Status = "error"
			res.Message = fmt.Sprintf("shard %s: %v", prefix, err)
			return
		}
		recCount := len(bundle.Records)
		if shard.Count != 0 && recCount != shard.Count {
			res.Status = "error"
			res.Message = fmt.Sprintf("shard %s: record count %d, manifest declares %d", prefix, recCount, shard.Count)
			return
		}
		verifiedShards++
		totalRecords += recCount
	}
	res.Status = "ok"
	res.Shards = verifiedShards
	res.Records = totalRecords
}
