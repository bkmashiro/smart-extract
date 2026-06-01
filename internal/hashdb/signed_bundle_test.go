package hashdb

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func newTestSignedBundle(t *testing.T) (Bundle, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	archiveHash := ArchiveHash(bytes.NewBufferString("archive signed 1"))
	rec, err := BuildRecord(archiveHash, "pw1", "src")
	if err != nil {
		t.Fatalf("BuildRecord: %v", err)
	}
	bundle := Bundle{
		Source:  "official",
		Records: []Record{rec},
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return bundle, pub, priv
}

func TestSignBundleVerifyRoundTrip(t *testing.T) {
	bundle, pub, priv := newTestSignedBundle(t)

	signed, err := SignBundle(bundle, priv)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	if signed.PublicKey != hex.EncodeToString(pub) {
		t.Fatalf("SignedBundle.PublicKey = %s, want %s", signed.PublicKey, hex.EncodeToString(pub))
	}
	if signed.Signature == "" {
		t.Fatalf("SignedBundle.Signature is empty")
	}
	if signed.Bundle.Version != BundleVersion {
		t.Fatalf("signed.Bundle.Version = %d, want %d", signed.Bundle.Version, BundleVersion)
	}

	verified, err := VerifySignedBundle(signed)
	if err != nil {
		t.Fatalf("VerifySignedBundle: %v", err)
	}
	if verified.Version != BundleVersion {
		t.Fatalf("verified.Version = %d, want %d", verified.Version, BundleVersion)
	}
	if len(verified.Records) != 1 {
		t.Fatalf("verified.Records len = %d, want 1", len(verified.Records))
	}
	if verified.Records[0].RecordID != bundle.Records[0].RecordID {
		t.Fatalf("verified record_id mismatch")
	}
}

func TestVerifySignedBundleRejectsTamperedRecord(t *testing.T) {
	bundle, _, priv := newTestSignedBundle(t)

	signed, err := SignBundle(bundle, priv)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	tampered := signed
	tampered.Bundle.Records = append([]Record{}, signed.Bundle.Records...)
	// flip one hex char of the ciphertext
	orig := tampered.Bundle.Records[0].Ciphertext
	if len(orig) < 2 {
		t.Fatalf("ciphertext too short to tamper")
	}
	var flipped byte = '0'
	if orig[0] == '0' {
		flipped = '1'
	}
	tampered.Bundle.Records[0].Ciphertext = string(flipped) + orig[1:]

	if _, err := VerifySignedBundle(tampered); err == nil {
		t.Fatalf("VerifySignedBundle accepted tampered ciphertext")
	}

	tampered2 := signed
	tampered2.Bundle.Source = "evil-source"
	if _, err := VerifySignedBundle(tampered2); err == nil {
		t.Fatalf("VerifySignedBundle accepted tampered source")
	}
}

func TestVerifySignedBundleRejectsTamperedSignature(t *testing.T) {
	bundle, _, priv := newTestSignedBundle(t)

	signed, err := SignBundle(bundle, priv)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	sigBytes, err := hex.DecodeString(signed.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	sigBytes[0] ^= 0xff
	tampered := signed
	tampered.Signature = hex.EncodeToString(sigBytes)

	if _, err := VerifySignedBundle(tampered); err == nil {
		t.Fatalf("VerifySignedBundle accepted tampered signature")
	}
}

func TestVerifySignedBundleRejectsInvalidPublicKey(t *testing.T) {
	bundle, _, priv := newTestSignedBundle(t)
	signed, err := SignBundle(bundle, priv)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	bad := signed
	bad.PublicKey = "not-hex-zz"
	if _, err := VerifySignedBundle(bad); err == nil {
		t.Fatalf("VerifySignedBundle accepted non-hex public_key")
	}

	bad2 := signed
	bad2.PublicKey = strings.Repeat("ab", 10) // wrong length
	if _, err := VerifySignedBundle(bad2); err == nil {
		t.Fatalf("VerifySignedBundle accepted wrong-length public_key")
	}
}

func TestVerifySignedBundleRejectsInvalidSignature(t *testing.T) {
	bundle, _, priv := newTestSignedBundle(t)
	signed, err := SignBundle(bundle, priv)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	bad := signed
	bad.Signature = "zzz"
	if _, err := VerifySignedBundle(bad); err == nil {
		t.Fatalf("VerifySignedBundle accepted non-hex signature")
	}

	bad2 := signed
	bad2.Signature = strings.Repeat("ab", 10) // wrong length
	if _, err := VerifySignedBundle(bad2); err == nil {
		t.Fatalf("VerifySignedBundle accepted wrong-length signature")
	}
}

func TestVerifySignedBundleRejectsInvalidEmbeddedBundle(t *testing.T) {
	_, _, priv := newTestSignedBundle(t)

	// build a bundle with an invalid record (missing ciphertext)
	invalidBundle := Bundle{
		Version: BundleVersion,
		Records: []Record{
			{
				RecordID: strings.Repeat("0", 64),
				Nonce:    "aa",
				// Ciphertext intentionally missing
			},
		},
	}

	// Sign whatever bytes MarshalBundle produces; the signature itself will be
	// valid, but Verify must still reject the embedded invalid bundle.
	pub := priv.Public().(ed25519.PublicKey)
	data, err := MarshalBundle(invalidBundle)
	if err != nil {
		t.Fatalf("MarshalBundle: %v", err)
	}
	sig := ed25519.Sign(priv, data)
	signed := SignedBundle{
		Bundle:    invalidBundle,
		PublicKey: hex.EncodeToString(pub),
		Signature: hex.EncodeToString(sig),
	}

	if _, err := VerifySignedBundle(signed); err == nil {
		t.Fatalf("VerifySignedBundle accepted bundle with invalid record")
	}
}

func TestSignBundleRejectsInvalidPrivateKey(t *testing.T) {
	bundle, _, _ := newTestSignedBundle(t)

	if _, err := SignBundle(bundle, ed25519.PrivateKey(nil)); err == nil {
		t.Fatalf("SignBundle accepted nil private key")
	}
	if _, err := SignBundle(bundle, ed25519.PrivateKey(make([]byte, 10))); err == nil {
		t.Fatalf("SignBundle accepted short private key")
	}
}

func TestMarshalParseSignedBundleRoundTrip(t *testing.T) {
	bundle, _, priv := newTestSignedBundle(t)
	signed, err := SignBundle(bundle, priv)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	data, err := MarshalSignedBundle(signed)
	if err != nil {
		t.Fatalf("MarshalSignedBundle: %v", err)
	}
	parsed, err := ParseSignedBundle(data)
	if err != nil {
		t.Fatalf("ParseSignedBundle: %v", err)
	}
	if parsed.PublicKey != signed.PublicKey || parsed.Signature != signed.Signature {
		t.Fatalf("ParseSignedBundle mismatch")
	}
	if _, err := VerifySignedBundle(parsed); err != nil {
		t.Fatalf("VerifySignedBundle on parsed signed bundle: %v", err)
	}
}
