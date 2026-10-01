package secret

import (
	"bytes"
	"testing"
)

func TestHasherRotation(t *testing.T) {
	oldKey, newKey := bytes.Repeat([]byte("o"), 32), bytes.Repeat([]byte("n"), 32)
	stored := NewHasher(oldKey, nil).Hash("s3cret")
	h := NewHasher(newKey, oldKey)
	ok, stale := h.Match("s3cret", stored)
	if !ok || !stale {
		t.Fatalf("old-key hash: ok=%v stale=%v", ok, stale)
	}
	ok, stale = h.Match("s3cret", h.Hash("s3cret"))
	if !ok || stale {
		t.Fatalf("new-key hash: ok=%v stale=%v", ok, stale)
	}
	if ok, _ := NewHasher(newKey, nil).Match("s3cret", stored); ok {
		t.Fatal("old hash matched without previous key")
	}
}
