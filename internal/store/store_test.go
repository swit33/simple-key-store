package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestSetGetRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	ctx := context.Background()
	ciphertext, nonce := []byte{1, 2, 3}, []byte{4, 5, 6}

	if err := s.Set(ctx, "prod/token", ciphertext, nonce); err != nil {
		t.Fatalf("Set: %v", err)
	}

	gotCiphertext, gotNonce, err := s.Get(ctx, "prod/token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(gotCiphertext, ciphertext) || !bytes.Equal(gotNonce, nonce) {
		t.Fatalf("Get = %v/%v, want %v/%v", gotCiphertext, gotNonce, ciphertext, nonce)
	}
}

func TestGetMissingKeyReturnsErrNotFound(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	_, _, err = s.Get(context.Background(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get = %v, want ErrNotFound", err)
	}
}
