package hashdb

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// SignedBundle is a JSON-safe wrapper that binds a Bundle to an Ed25519
// signature over its canonical MarshalBundle bytes.
type SignedBundle struct {
	Bundle    Bundle `json:"bundle"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// SignBundle returns a SignedBundle whose signature covers the canonical
// MarshalBundle bytes of the version-normalized bundle.
func SignBundle(bundle Bundle, privateKey ed25519.PrivateKey) (SignedBundle, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedBundle{}, fmt.Errorf("invalid ed25519 private key length %d, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	if bundle.Version == 0 {
		bundle.Version = BundleVersion
	}
	if bundle.Records == nil {
		bundle.Records = []Record{}
	}
	data, err := MarshalBundle(bundle)
	if err != nil {
		return SignedBundle{}, fmt.Errorf("marshal bundle: %w", err)
	}
	sig := ed25519.Sign(privateKey, data)
	pub, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return SignedBundle{}, fmt.Errorf("derive ed25519 public key")
	}
	return SignedBundle{
		Bundle:    bundle,
		PublicKey: hex.EncodeToString(pub),
		Signature: hex.EncodeToString(sig),
	}, nil
}

// VerifySignedBundle validates the signature and embedded bundle, returning
// the version-normalized bundle on success.
func VerifySignedBundle(signed SignedBundle) (Bundle, error) {
	pubBytes, err := hex.DecodeString(signed.PublicKey)
	if err != nil {
		return Bundle{}, fmt.Errorf("decode public_key hex: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return Bundle{}, fmt.Errorf("public_key length %d bytes, want %d", len(pubBytes), ed25519.PublicKeySize)
	}
	sigBytes, err := hex.DecodeString(signed.Signature)
	if err != nil {
		return Bundle{}, fmt.Errorf("decode signature hex: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return Bundle{}, fmt.Errorf("signature length %d bytes, want %d", len(sigBytes), ed25519.SignatureSize)
	}
	data, err := MarshalBundle(signed.Bundle)
	if err != nil {
		return Bundle{}, fmt.Errorf("marshal embedded bundle: %w", err)
	}
	parsed, err := ParseBundle(data)
	if err != nil {
		return Bundle{}, fmt.Errorf("validate embedded bundle: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), data, sigBytes) {
		return Bundle{}, fmt.Errorf("signature verification failed")
	}
	return parsed, nil
}

// MarshalSignedBundle serializes a SignedBundle to JSON.
func MarshalSignedBundle(s SignedBundle) ([]byte, error) {
	return json.Marshal(s)
}

// ParseSignedBundle decodes a SignedBundle from JSON without verifying it.
func ParseSignedBundle(data []byte) (SignedBundle, error) {
	var s SignedBundle
	if err := json.Unmarshal(data, &s); err != nil {
		return SignedBundle{}, fmt.Errorf("decode signed bundle: %w", err)
	}
	return s, nil
}
