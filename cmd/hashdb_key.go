package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/bkmashiro/smart-extract/internal/hashdb"
)

// HashDBPublicKey loads or creates a local HashDB signing key file and returns
// the hex-encoded Ed25519 public key used for hashdb.sources[].public_key.
func HashDBPublicKey(keyPath string) (string, error) {
	keyPath = strings.TrimSpace(keyPath)
	if keyPath == "" {
		return "", fmt.Errorf("key path is required")
	}
	pub, _, err := hashdb.LoadOrCreateSigningKey(context.Background(), keyPath)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub), nil
}
