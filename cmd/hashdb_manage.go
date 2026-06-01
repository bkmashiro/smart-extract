package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/bkmashiro/smart-extract/internal/config"
)

// HashDBSourceSummary describes a single configured HashDB source for
// inspection. It is derived from config.HashDB.Sources without performing
// any network or cryptographic verification.
type HashDBSourceSummary struct {
	Name        string
	Type        string
	Location    string
	CacheDir    string
	PublicKey   string
	Disabled    bool
	Compression string
	SHA256      string
	CachePath   string
	CacheExists bool
}

// HashDBCacheRemoval describes one cache-clear attempt against a HashDB
// HTTP source.
type HashDBCacheRemoval struct {
	Name    string
	Path    string
	Existed bool
}

// HashDBListSources returns one summary per configured HashDB source, in
// configuration order. CachePath is populated for sources backed by a URL
// or manifest_url and reflects the same cache root the lookup path uses.
func HashDBListSources() ([]HashDBSourceSummary, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}
	out := make([]HashDBSourceSummary, 0, len(cfg.HashDB.Sources))
	for _, src := range cfg.HashDB.Sources {
		summary := HashDBSourceSummary{
			Name:        src.Name,
			Type:        sourceTypeOrDefault(src.Type),
			Location:    sourceLocation(src),
			CacheDir:    src.CacheDir,
			PublicKey:   src.PublicKey,
			Disabled:    src.Disabled,
			Compression: src.Compression,
			SHA256:      src.SHA256,
		}
		if sourceHasHTTPCache(src) {
			cachePath, err := hashDBSourceCacheRoot(src)
			if err != nil {
				return nil, err
			}
			summary.CachePath = cachePath
			if _, statErr := os.Stat(cachePath); statErr == nil {
				summary.CacheExists = true
			}
		}
		out = append(out, summary)
	}
	return out, nil
}

// HashDBClearSourceCache removes the cache root for the named HashDB
// source. The source must use a URL or manifest_url; local-only sources
// have no cache to clear. Returns the path that was targeted and whether
// it existed before removal.
func HashDBClearSourceCache(name string) (string, bool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false, fmt.Errorf("source name is required")
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return "", false, err
	}
	for _, src := range cfg.HashDB.Sources {
		if src.Name != name {
			continue
		}
		if !sourceHasHTTPCache(src) {
			return "", false, fmt.Errorf("hashdb source %q has no HTTP cache to clear", name)
		}
		cachePath, err := hashDBSourceCacheRoot(src)
		if err != nil {
			return "", false, err
		}
		existed := false
		if _, statErr := os.Stat(cachePath); statErr == nil {
			existed = true
		}
		if err := os.RemoveAll(cachePath); err != nil {
			return cachePath, existed, fmt.Errorf("remove hashdb cache %s: %w", cachePath, err)
		}
		return cachePath, existed, nil
	}
	return "", false, fmt.Errorf("hashdb source %q not found", name)
}

// HashDBClearAllSourceCaches removes the cache root of every configured
// HTTP HashDB source. Duplicate cache roots are removed once and reported
// once (under the first source that referenced them).
func HashDBClearAllSourceCaches() ([]HashDBCacheRemoval, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	removals := make([]HashDBCacheRemoval, 0)
	for _, src := range cfg.HashDB.Sources {
		if !sourceHasHTTPCache(src) {
			continue
		}
		cachePath, err := hashDBSourceCacheRoot(src)
		if err != nil {
			return removals, err
		}
		if seen[cachePath] {
			continue
		}
		seen[cachePath] = true
		existed := false
		if _, statErr := os.Stat(cachePath); statErr == nil {
			existed = true
		}
		if err := os.RemoveAll(cachePath); err != nil {
			return removals, fmt.Errorf("remove hashdb cache %s: %w", cachePath, err)
		}
		removals = append(removals, HashDBCacheRemoval{
			Name:    src.Name,
			Path:    cachePath,
			Existed: existed,
		})
	}
	return removals, nil
}

func sourceTypeOrDefault(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" {
		return "bundle"
	}
	return t
}

func sourceLocation(src config.HashDBSource) string {
	for _, candidate := range []string{src.Path, src.URL, src.BaseDir, src.ManifestURL} {
		if strings.TrimSpace(candidate) != "" {
			return candidate
		}
	}
	return ""
}

func sourceHasHTTPCache(src config.HashDBSource) bool {
	return strings.TrimSpace(src.URL) != "" || strings.TrimSpace(src.ManifestURL) != ""
}
