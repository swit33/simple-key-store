// Package crypto pins the envelope-crypto contract for M1-T2 (test-first, no
// implementation yet): secrets-spec.md §1 (AES-256-GCM per value, exact 32-byte
// key, fresh 12-byte crypto/rand nonce per record, AAD binding the ciphertext
// to a path and to the client/server side), DECISIONS.md D12 (AAD is
// "secrets/v1|"+path on the server and "local|secrets/v1|"+path on the client,
// built by one helper inside this package only) and agent-loop-guide.md §3.2
// ("crypto: nonce уникален, AAD-префикс local| ломает несовместимую запись").
//
// These tests are the API: Domain is a basic-kind type with the exported
// constants ServerDomain and LocalDomain (never a bool), the zero value of
// Domain is reserved and must be rejected, Seal/Open get the key/domain/path
// context per call, and ciphertext and nonce travel as two separate slices.
// Swapping any of domain, path, key, ciphertext or nonce bytes must make Open
// fail, and no error may echo the plaintext or the key.
package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	testKeyLen   = 32 // AES-256
	testNonceLen = 12 // GCM standard nonce size — the only one Seal may generate
	testTagLen   = 16 // GCM authentication tag appended to the ciphertext

	testPath = "prod/pullmd/token"
	// plaintextMarker is a value that must never survive into ciphertext, an
	// error string or any log line (spec §1: stderr/логи значений не содержат).
	plaintextMarker = "PLAINTEXT-MARKER-OPENAI-KEY"
)

// testKey returns a deterministic, recognisable 32-byte key so that a leak of
// key material into an error string is detectable.
func testKey() []byte { return bytes.Repeat([]byte("0123456789abcdef"), testKeyLen/16) }

// otherKey is a valid-length key that is not testKey.
func otherKey() []byte { return bytes.Repeat([]byte("fedcba9876543210"), 2) }

func allBytes() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func seal(t *testing.T, key []byte, d Domain, path string, plaintext []byte) (ciphertext, nonce []byte) {
	t.Helper()
	ciphertext, nonce, err := Seal(key, d, path, plaintext)
	if err != nil {
		t.Fatalf("Seal(%q): %v", path, err)
	}
	return ciphertext, nonce
}

func open(t *testing.T, key []byte, d Domain, path string, ciphertext, nonce []byte) []byte {
	t.Helper()
	plaintext, err := Open(key, d, path, ciphertext, nonce)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	return plaintext
}

// openMustFail asserts Open rejects the input and returns no plaintext at all.
func openMustFail(t *testing.T, key []byte, d Domain, path string, ciphertext, nonce []byte) error {
	t.Helper()
	plaintext, err := Open(key, d, path, ciphertext, nonce)
	if err == nil {
		t.Fatalf("Open(%q) succeeded, want error; plaintext = %q", path, plaintext)
	}
	if len(plaintext) != 0 {
		t.Fatalf("Open(%q) returned %q alongside %v, want no plaintext", path, plaintext, err)
	}
	return err
}

func TestRoundTripPreservesBytes(t *testing.T) {
	key := testKey()
	plaintexts := map[string][]byte{
		"empty":     {},
		"nul only":  {0},
		"newline":   []byte("line1\nline2\n"),
		"inner nul": []byte("a\x00b"),
		"all 256":   allBytes(),
		"utf8":      []byte("ключ-🔑"),
		"marker":    []byte(plaintextMarker),
	}
	domains := map[string]Domain{"server": ServerDomain, "local": LocalDomain}

	for domainName, domain := range domains {
		for name, plaintext := range plaintexts {
			t.Run(domainName+"/"+name, func(t *testing.T) {
				ciphertext, nonce := seal(t, key, domain, testPath, plaintext)

				if len(nonce) != testNonceLen {
					t.Fatalf("nonce length = %d, want %d bytes", len(nonce), testNonceLen)
				}
				// The nonce is returned separately: the ciphertext must be
				// exactly the GCM tag plus the plaintext, nothing else.
				if len(ciphertext) != len(plaintext)+testTagLen {
					t.Fatalf("ciphertext length = %d, want %d (plaintext %d + tag %d)",
						len(ciphertext), len(plaintext)+testTagLen, len(plaintext), testTagLen)
				}

				got := open(t, key, domain, testPath, ciphertext, nonce)
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("Open = %q, want %q", got, plaintext)
				}
			})
		}
	}
}

func TestCiphertextDoesNotContainPlaintext(t *testing.T) {
	ciphertext, nonce := seal(t, testKey(), ServerDomain, testPath, []byte(plaintextMarker))
	if bytes.Contains(ciphertext, []byte(plaintextMarker)) {
		t.Fatalf("ciphertext %x contains the plaintext marker", ciphertext)
	}
	if bytes.Contains(nonce, []byte(plaintextMarker)) {
		t.Fatalf("nonce %x contains the plaintext marker", nonce)
	}
}

func TestSealNoncesAreUnique(t *testing.T) {
	const seals = 128
	key := testKey()
	seen := make(map[string]int, seals)

	for i := range seals {
		_, nonce := seal(t, key, ServerDomain, testPath, []byte("identical value"))
		if len(nonce) != testNonceLen {
			t.Fatalf("seal %d: nonce length = %d, want %d", i, len(nonce), testNonceLen)
		}
		if prev, dup := seen[string(nonce)]; dup {
			t.Fatalf("nonce reused at seal %d (already at %d): %x — GCM breaks on reuse", i, prev, nonce)
		}
		seen[string(nonce)] = i
	}

	if len(seen) != seals {
		t.Fatalf("unique nonces = %d, want %d", len(seen), seals)
	}
}

func TestSamePlaintextProducesDifferentCiphertext(t *testing.T) {
	key := testKey()
	plaintext := []byte("same value, twice")

	firstCiphertext, firstNonce := seal(t, key, ServerDomain, testPath, plaintext)
	secondCiphertext, secondNonce := seal(t, key, ServerDomain, testPath, plaintext)

	if bytes.Equal(firstNonce, secondNonce) {
		t.Fatalf("nonce reused: %x", firstNonce)
	}
	if bytes.Equal(firstCiphertext, secondCiphertext) {
		t.Fatalf("ciphertext repeated for identical plaintext: %x", firstCiphertext)
	}
}

func TestOpenRejectsMismatchedContext(t *testing.T) {
	key := testKey()
	plaintext := []byte("context-bound value")

	tests := []struct {
		name       string
		sealDomain Domain
		sealPath   string
		sealKey    []byte
		openDomain Domain
		openPath   string
		openKey    []byte
	}{
		{
			name:       "wrong path",
			sealDomain: ServerDomain, sealPath: "prod/a", sealKey: key,
			openDomain: ServerDomain, openPath: "prod/b", openKey: key,
		},
		{
			name:       "path is a prefix of the sealed one",
			sealDomain: ServerDomain, sealPath: testPath, sealKey: key,
			openDomain: ServerDomain, openPath: "prod", openKey: key,
		},
		{
			name:       "empty path",
			sealDomain: ServerDomain, sealPath: testPath, sealKey: key,
			openDomain: ServerDomain, openPath: "", openKey: key,
		},
		{
			name:       "server ciphertext opened as local",
			sealDomain: ServerDomain, sealPath: testPath, sealKey: key,
			openDomain: LocalDomain, openPath: testPath, openKey: key,
		},
		{
			name:       "local ciphertext opened as server",
			sealDomain: LocalDomain, sealPath: testPath, sealKey: key,
			openDomain: ServerDomain, openPath: testPath, openKey: key,
		},
		{
			name:       "wrong key",
			sealDomain: ServerDomain, sealPath: testPath, sealKey: key,
			openDomain: ServerDomain, openPath: testPath, openKey: otherKey(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, nonce := seal(t, tc.sealKey, tc.sealDomain, tc.sealPath, plaintext)

			// The honest context must still work, so a stub that always
			// errors cannot pass this test.
			if got := open(t, tc.sealKey, tc.sealDomain, tc.sealPath, ciphertext, nonce); !bytes.Equal(got, plaintext) {
				t.Fatalf("Open with the sealing context = %q, want %q", got, plaintext)
			}

			_ = openMustFail(t, tc.openKey, tc.openDomain, tc.openPath, ciphertext, nonce)
		})
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	key := testKey()
	ciphertext, nonce := seal(t, key, ServerDomain, testPath, []byte("tamper me"))

	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"first byte flipped", func(c []byte) []byte { out := bytes.Clone(c); out[0] ^= 0x01; return out }},
		{"last tag byte flipped", func(c []byte) []byte { out := bytes.Clone(c); out[len(out)-1] ^= 0x80; return out }},
		{"middle byte flipped", func(c []byte) []byte { out := bytes.Clone(c); out[len(out)/2] ^= 0xff; return out }},
		{"truncated", func(c []byte) []byte { return bytes.Clone(c)[:len(c)-1] }},
		{"empty", func(c []byte) []byte { return nil }},
		{"tag only", func(c []byte) []byte { return bytes.Clone(c)[len(c)-testTagLen:] }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_ = openMustFail(t, key, ServerDomain, testPath, tc.mutate(ciphertext), nonce)
		})
	}
}

func TestInvalidKeyLength(t *testing.T) {
	for _, n := range []int{0, 1, 16, testKeyLen - 1, testKeyLen + 1, 64} {
		key := bytes.Repeat([]byte("k"), n)

		if _, _, err := Seal(key, ServerDomain, testPath, []byte("value")); err == nil {
			t.Errorf("Seal with a %d-byte key succeeded, want error", n)
		}

		validKey := testKey()
		ciphertext, nonce := seal(t, validKey, ServerDomain, testPath, []byte("value"))
		_ = openMustFail(t, key, ServerDomain, testPath, ciphertext, nonce)
	}
}

func TestInvalidNonceLength(t *testing.T) {
	key := testKey()
	ciphertext, validNonce := seal(t, key, ServerDomain, testPath, []byte("value"))

	for _, n := range []int{0, 1, 11, 13, 16, 32} {
		nonce := make([]byte, n)
		copy(nonce, validNonce)
		_ = openMustFail(t, key, ServerDomain, testPath, ciphertext, nonce)
	}

	_ = openMustFail(t, key, ServerDomain, testPath, ciphertext, nil)
}

func TestUnknownDomainFails(t *testing.T) {
	key := testKey()
	// The zero value of Domain is reserved: it is not ServerDomain and not
	// LocalDomain, so it must be rejected by both Seal and Open.
	var unknown Domain

	if _, _, err := Seal(key, unknown, testPath, []byte("value")); err == nil {
		t.Fatalf("Seal with the zero Domain succeeded, want error")
	}

	ciphertext, nonce := seal(t, key, ServerDomain, testPath, []byte("value"))
	if _, err := Open(key, unknown, testPath, ciphertext, nonce); err == nil {
		t.Fatalf("Open with the zero Domain succeeded, want error")
	}
}

func TestErrorsDoNotLeakPlaintextOrKey(t *testing.T) {
	key := testKey()
	plaintext := []byte(plaintextMarker)
	ciphertext, nonce := seal(t, key, ServerDomain, testPath, plaintext)
	tampered := bytes.Clone(ciphertext)
	tampered[0] ^= 0xff

	leaky := []byte("leaky-secret-value")
	leakyCiphertext, leakyNonce := seal(t, key, ServerDomain, testPath, leaky)

	var unknown Domain
	errs := map[string]error{
		"wrong key":       openMustFail(t, otherKey(), ServerDomain, testPath, ciphertext, nonce),
		"wrong path":      openMustFail(t, key, ServerDomain, "prod/other", ciphertext, nonce),
		"wrong domain":    openMustFail(t, key, LocalDomain, testPath, ciphertext, nonce),
		"tampered":        openMustFail(t, key, ServerDomain, testPath, tampered, nonce),
		"bad nonce":       openMustFail(t, key, ServerDomain, testPath, ciphertext, make([]byte, testNonceLen-1)),
		"bad key length":  openMustFail(t, key[:31], ServerDomain, testPath, ciphertext, nonce),
		"unknown domain":  openMustFail(t, key, unknown, testPath, ciphertext, nonce),
		"leaky plaintext": openMustFail(t, otherKey(), ServerDomain, testPath, leakyCiphertext, leakyNonce),
	}

	for name, err := range errs {
		msg := err.Error()
		if msg == "" {
			t.Errorf("%s: error message is empty", name)
		}
		for label, secret := range map[string]string{
			"plaintext marker": plaintextMarker,
			"plaintext":        string(leaky),
			"key (raw)":        string(key),
			"key (hex)":        hex.EncodeToString(key),
			"ciphertext (hex)": hex.EncodeToString(ciphertext),
		} {
			if strings.Contains(msg, secret) {
				t.Errorf("%s: error %q leaks the %s", name, msg, label)
			}
		}
	}
}
