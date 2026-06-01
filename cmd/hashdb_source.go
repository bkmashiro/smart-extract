package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/bkmashiro/smart-extract/internal/config"
	"github.com/bkmashiro/smart-extract/internal/hashdb"
)

// HashDBAddLocalSourceOptions describes a local signed HashDB source to add to
// config.yaml for lookup. Type is "bundle" or "sharded".
type HashDBAddLocalSourceOptions struct {
	Name    string
	Type    string
	Path    string
	BaseDir string
	KeyPath string
}

// HashDBAddLocalSource loads or creates key_path, enables HashDB lookup, and
// upserts a local bundle/sharded source in config.yaml. It returns the hex
// Ed25519 public key written to hashdb.sources[].public_key.
func HashDBAddLocalSource(opts HashDBAddLocalSourceOptions) (string, error) {
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return "", fmt.Errorf("source name is required")
	}
	typ := strings.ToLower(strings.TrimSpace(opts.Type))
	if typ == "" {
		typ = "bundle"
	}
	keyPath := strings.TrimSpace(opts.KeyPath)
	if keyPath == "" {
		return "", fmt.Errorf("key path is required")
	}

	src := config.HashDBSource{Name: name, Type: typ}
	switch typ {
	case "bundle":
		path := strings.TrimSpace(opts.Path)
		if path == "" {
			return "", fmt.Errorf("bundle source path is required")
		}
		src.Path = path
	case "sharded":
		baseDir := strings.TrimSpace(opts.BaseDir)
		if baseDir == "" {
			return "", fmt.Errorf("sharded source base_dir is required")
		}
		src.BaseDir = baseDir
	default:
		return "", fmt.Errorf("unsupported HashDB source type %q", opts.Type)
	}

	pub, _, err := hashdb.LoadOrCreateSigningKey(context.Background(), keyPath)
	if err != nil {
		return "", err
	}
	src.PublicKey = hex.EncodeToString(pub)

	cfg, err := config.LoadConfig()
	if err != nil {
		return "", err
	}
	cfg.HashDB.Mode = "lookup"

	replaced := false
	for i := range cfg.HashDB.Sources {
		if cfg.HashDB.Sources[i].Name == name {
			cfg.HashDB.Sources[i] = src
			replaced = true
			break
		}
	}
	if !replaced {
		cfg.HashDB.Sources = append(cfg.HashDB.Sources, src)
	}
	if err := config.SaveConfig(cfg); err != nil {
		return "", err
	}
	return src.PublicKey, nil
}
