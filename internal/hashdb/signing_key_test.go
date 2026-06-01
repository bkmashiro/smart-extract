package hashdb

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadOrCreateSigningKeyCreatesNewKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "key.json")

	pub, priv, err := LoadOrCreateSigningKey(context.Background(), path)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("pub size = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("priv size = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	// Public derived from private matches returned public.
	derived, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("priv.Public() not ed25519.PublicKey")
	}
	if hex.EncodeToString(derived) != hex.EncodeToString(pub) {
		t.Fatalf("derived pub differs from returned pub")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("key file mode = %o, want 0600", mode)
		}
	}

	// Loading again returns identical key material.
	pub2, priv2, err := LoadOrCreateSigningKey(context.Background(), path)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey (load): %v", err)
	}
	if hex.EncodeToString(pub2) != hex.EncodeToString(pub) {
		t.Fatalf("reloaded pub differs")
	}
	if hex.EncodeToString(priv2) != hex.EncodeToString(priv) {
		t.Fatalf("reloaded priv differs")
	}
}

func TestLoadOrCreateSigningKeyEmptyPath(t *testing.T) {
	_, _, err := LoadOrCreateSigningKey(context.Background(), "")
	if err == nil {
		t.Fatalf("expected error on empty path")
	}
}

func TestLoadOrCreateSigningKeyMalformedHex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")
	data, _ := json.Marshal(map[string]any{
		"version":     1,
		"public_key":  "notvalidhex!!",
		"private_key": "alsonothex",
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	_, _, err := LoadOrCreateSigningKey(context.Background(), path)
	if err == nil {
		t.Fatalf("expected error on malformed hex")
	}
}

func TestLoadOrCreateSigningKeyWrongLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")
	data, _ := json.Marshal(map[string]any{
		"version":     1,
		"public_key":  hex.EncodeToString([]byte{1, 2, 3}),
		"private_key": hex.EncodeToString([]byte{4, 5, 6}),
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	_, _, err := LoadOrCreateSigningKey(context.Background(), path)
	if err == nil {
		t.Fatalf("expected error on wrong-length key")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "length") {
		t.Fatalf("error should mention length; got: %v", err)
	}
}

func TestLoadOrCreateSigningKeyPubPrivMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	data, _ := json.Marshal(map[string]any{
		"version":     1,
		"public_key":  hex.EncodeToString(otherPub),
		"private_key": hex.EncodeToString(priv),
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	_, _, err = LoadOrCreateSigningKey(context.Background(), path)
	if err == nil {
		t.Fatalf("expected error on pub/priv mismatch")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "mismatch") &&
		!strings.Contains(strings.ToLower(err.Error()), "match") {
		t.Fatalf("error should mention mismatch; got: %v", err)
	}
}
