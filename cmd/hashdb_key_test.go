package cmd

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestHashDBPublicKeyCreatesKeyAndReturnsHexPublicKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "hashdb", "signing.key.json")

	got, err := HashDBPublicKey(keyPath)
	if err != nil {
		t.Fatalf("HashDBPublicKey: %v", err)
	}
	decoded, err := hex.DecodeString(got)
	if err != nil {
		t.Fatalf("public key is not hex: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("public key length = %d, want 32", len(decoded))
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file missing: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("key mode = %v, want 0600", mode)
	}

	again, err := HashDBPublicKey(keyPath)
	if err != nil {
		t.Fatalf("HashDBPublicKey second call: %v", err)
	}
	if again != got {
		t.Fatalf("public key changed: first %q second %q", got, again)
	}
}

func TestHashDBPublicKeyRejectsEmptyPath(t *testing.T) {
	if _, err := HashDBPublicKey("   "); err == nil {
		t.Fatalf("expected empty key path error")
	}
}
