// Package crypto implements the envelope-crypto contract of secrets-spec.md §1:
// AES-256-GCM per value, an exact 32-byte key, one fresh 12-byte crypto/rand
// nonce per record, and AAD binding the ciphertext to a path and to the
// client/server side (DECISIONS.md D12). Ciphertext and nonce travel as two
// separate slices; the nonce is never prepended to the ciphertext.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// Domain selects which side of the protocol a value is sealed for. Seal and
// Open reject the reserved zero value, so a caller that forgot to pick a side
// fails instead of silently encrypting with the wrong AAD.
type Domain uint8

const (
	// ServerDomain is for ciphertext stored by the server.
	ServerDomain Domain = iota + 1
	// LocalDomain is for ciphertext produced on the client; it is deliberately
	// not interchangeable with ServerDomain ciphertext.
	LocalDomain
)

const (
	// keySize is the AES-256 key length.
	keySize = 32
	// schemaID is the mandatory AAD prefix. Changing the crypto scheme means a
	// new schemaID (DECISIONS.md D12), never a partial decrypt of old records.
	schemaID = "secrets/v1"
)

// String returns the wire-independent name of the domain, for error messages.
func (d Domain) String() string {
	switch d {
	case ServerDomain:
		return "server"
	case LocalDomain:
		return "local"
	default:
		return fmt.Sprintf("Domain(%d)", uint8(d))
	}
}

// aad builds the additional authenticated data for one record. It is the only
// place in the codebase that knows the AAD layout (DECISIONS.md D12).
func (d Domain) aad(path string) ([]byte, error) {
	switch d {
	case ServerDomain:
		return []byte(schemaID + "|" + path), nil
	case LocalDomain:
		return []byte("local|" + schemaID + "|" + path), nil
	default:
		return nil, fmt.Errorf("unknown domain %s", d)
	}
}

// newGCM validates the key length before touching AES and returns the AEAD.
// op names the calling operation for the error message.
func newGCM(key []byte, op string) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("crypto: %s: key must be %d bytes, got %d", op, keySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: %s: %w", op, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: %s: %w", op, err)
	}
	return gcm, nil
}

// Seal encrypts plaintext with key (exactly 32 bytes) for the given domain and
// path. It returns the ciphertext (GCM tag appended to the plaintext, no nonce)
// and a freshly generated nonce as separate slices.
func Seal(key []byte, d Domain, path string, plaintext []byte) (ciphertext, nonce []byte, err error) {
	aad, err := d.aad(path)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: seal: %w", err)
	}
	gcm, err := newGCM(key, "seal")
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("crypto: seal: read nonce: %w", err)
	}

	return gcm.Seal(nil, nonce, plaintext, aad), nonce, nil
}

// Open decrypts ciphertext with key (exactly 32 bytes) for the domain and path
// it was sealed with. A key of the wrong length, an unknown domain, a nonce
// that is not gcm.NonceSize() bytes or any authentication failure is rejected
// with no plaintext returned.
func Open(key []byte, d Domain, path string, ciphertext, nonce []byte) ([]byte, error) {
	aad, err := d.aad(path)
	if err != nil {
		return nil, fmt.Errorf("crypto: open: %w", err)
	}
	gcm, err := newGCM(key, "open")
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("crypto: open %s %q: nonce must be %d bytes, got %d", d, path, gcm.NonceSize(), len(nonce))
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		// The stdlib error is constant text (cipher: message authentication
		// failed) and never echoes plaintext, key, ciphertext or nonce.
		return nil, fmt.Errorf("crypto: open %s %q: %w", d, path, err)
	}
	return plaintext, nil
}
