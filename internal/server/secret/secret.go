// Package secret generates and hashes bearer secrets (enrollment tokens,
// agent credentials, session tokens). Only HMAC hashes are stored.
package secret

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"strings"
)

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// Random returns a lowercase base32 string carrying n random bytes.
func Random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return strings.ToLower(enc.EncodeToString(b))
}

// Hasher HMACs secrets with the current key, and can also produce hashes
// under the previous key while a key rotation is in progress.
type Hasher struct {
	current  []byte
	previous []byte
}

func NewHasher(current, previous []byte) *Hasher {
	return &Hasher{current: current, previous: previous}
}

func (h *Hasher) Hash(s string) []byte { return mac(h.current, s) }

// PreviousHash returns nil when no previous key is configured.
func (h *Hasher) PreviousHash(s string) []byte {
	if h.previous == nil {
		return nil
	}
	return mac(h.previous, s)
}

// Match reports whether s matches stored under the current key, or under the
// previous key (stale=true, caller should re-hash and store).
func (h *Hasher) Match(s string, stored []byte) (ok, stale bool) {
	if subtle.ConstantTimeCompare(h.Hash(s), stored) == 1 {
		return true, false
	}
	if p := h.PreviousHash(s); p != nil && subtle.ConstantTimeCompare(p, stored) == 1 {
		return true, true
	}
	return false, false
}

func mac(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}
