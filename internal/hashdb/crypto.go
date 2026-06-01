package hashdb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	recordIDLabel    = "smart-extract hashdb record id v1"
	passwordKeyLabel = "smart-extract hashdb password key v1"
)

// ArchiveDigest is a fixed-size SHA-256 digest of archive bytes.
type ArchiveDigest [sha256.Size]byte

// RecordIDDigest is the source lookup key derived from an ArchiveDigest.
type RecordIDDigest [sha256.Size]byte

// EncryptedPassword stores an archive-bound encrypted password.
type EncryptedPassword struct {
	Nonce      []byte
	Ciphertext []byte
}

// ArchiveHash streams data from r and returns its SHA-256 digest.
func ArchiveHash(r io.Reader) ArchiveDigest {
	h := sha256.New()
	_, _ = io.Copy(h, r)
	var digest ArchiveDigest
	copy(digest[:], h.Sum(nil))
	return digest
}

// ArchiveHashFromHex parses a 32-byte SHA-256 archive digest.
func ArchiveHashFromHex(s string) (ArchiveDigest, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return ArchiveDigest{}, fmt.Errorf("decode archive hash hex: %w", err)
	}
	if len(b) != sha256.Size {
		return ArchiveDigest{}, fmt.Errorf("archive hash length %d bytes, want %d", len(b), sha256.Size)
	}
	var digest ArchiveDigest
	copy(digest[:], b)
	return digest, nil
}

// Bytes returns a copy of the archive digest bytes.
func (d ArchiveDigest) Bytes() []byte {
	out := make([]byte, len(d))
	copy(out, d[:])
	return out
}

// Hex returns the lowercase hex encoding of the archive digest.
func (d ArchiveDigest) Hex() string {
	return hex.EncodeToString(d[:])
}

// Bytes returns a copy of the record-id digest bytes.
func (d RecordIDDigest) Bytes() []byte {
	out := make([]byte, len(d))
	copy(out, d[:])
	return out
}

// Hex returns the lowercase hex encoding of the record-id digest.
func (d RecordIDDigest) Hex() string {
	return hex.EncodeToString(d[:])
}

// RecordID derives a domain-separated lookup key from an archive hash.
func RecordID(archiveHash ArchiveDigest) RecordIDDigest {
	mac := hmac.New(sha256.New, []byte(recordIDLabel))
	mac.Write(archiveHash[:])
	var id RecordIDDigest
	copy(id[:], mac.Sum(nil))
	return id
}

// EncryptPassword encrypts password with a key derived from archiveHash.
func EncryptPassword(archiveHash ArchiveDigest, password string) (EncryptedPassword, error) {
	aead, err := passwordAEAD(archiveHash)
	if err != nil {
		return EncryptedPassword{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPassword{}, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, []byte(password), nil)
	return EncryptedPassword{Nonce: nonce, Ciphertext: ciphertext}, nil
}

// DecryptPassword decrypts a password record using the same archive hash.
func DecryptPassword(archiveHash ArchiveDigest, record EncryptedPassword) (string, error) {
	aead, err := passwordAEAD(archiveHash)
	if err != nil {
		return "", err
	}
	plaintext, err := aead.Open(nil, record.Nonce, record.Ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt password: %w", err)
	}
	return string(plaintext), nil
}

func passwordAEAD(archiveHash ArchiveDigest) (cipher.AEAD, error) {
	key := derivePasswordKey(archiveHash)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	return aead, nil
}

func derivePasswordKey(archiveHash ArchiveDigest) [sha256.Size]byte {
	mac := hmac.New(sha256.New, archiveHash[:])
	mac.Write([]byte(passwordKeyLabel))
	var key [sha256.Size]byte
	copy(key[:], mac.Sum(nil))
	return key
}
