package hashdb

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SigningKeyVersion is the current supported signing key file format version.
const SigningKeyVersion = 1

// signingKeyFile is the on-disk JSON shape of a HashDB Ed25519 signing key.
type signingKeyFile struct {
	Version    int    `json:"version"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// LoadOrCreateSigningKey loads an Ed25519 signing key from path, or generates
// a new one and writes it with 0600 permissions if the file does not exist.
//
// The returned key is validated: hex fields must decode, lengths must match
// ed25519 sizes, and the public key must match the one derived from the
// private key. LoadOrCreateSigningKey performs no network access.
func LoadOrCreateSigningKey(ctx context.Context, path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if path == "" {
		return nil, nil, errors.New("signing key: empty path")
	}

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		return parseSigningKeyFile(data)
	case errors.Is(err, os.ErrNotExist):
		return createSigningKey(ctx, path)
	default:
		return nil, nil, fmt.Errorf("signing key: read %s: %w", path, err)
	}
}

func parseSigningKeyFile(data []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	var f signingKeyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, nil, fmt.Errorf("signing key: decode json: %w", err)
	}
	if f.Version != SigningKeyVersion {
		return nil, nil, fmt.Errorf("signing key: unsupported version %d, want %d", f.Version, SigningKeyVersion)
	}
	pub, err := hex.DecodeString(f.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("signing key: decode public_key hex: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("signing key: public_key length %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	priv, err := hex.DecodeString(f.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("signing key: decode private_key hex: %w", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("signing key: private_key length %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	derived, ok := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("signing key: derive public key")
	}
	if hex.EncodeToString(derived) != hex.EncodeToString(pub) {
		return nil, nil, errors.New("signing key: public_key/private_key mismatch")
	}
	return ed25519.PublicKey(pub), ed25519.PrivateKey(priv), nil
}

func createSigningKey(ctx context.Context, path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, nil, fmt.Errorf("signing key: create parent dir %s: %w", dir, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("signing key: generate: %w", err)
	}
	body := signingKeyFile{
		Version:    SigningKeyVersion,
		PublicKey:  hex.EncodeToString(pub),
		PrivateKey: hex.EncodeToString(priv),
	}
	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("signing key: encode: %w", err)
	}
	if err := writeFile0600(path, data); err != nil {
		return nil, nil, fmt.Errorf("signing key: write %s: %w", path, err)
	}
	return pub, priv, nil
}

// writeFile0600 writes data to path with 0600 permissions, replacing any
// existing file. The file is created with the restrictive mode rather than
// being chmodded after the fact.
func writeFile0600(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
