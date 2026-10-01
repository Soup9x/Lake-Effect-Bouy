package release

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aead.dev/minisign"
)

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCommittedKeyIsPlaceholder(t *testing.T) {
	// The repo ships a placeholder; make sure it is rejected rather than
	// silently trusted. When a real key is committed this test must be
	// updated together with the key.
	if !strings.Contains(embeddedPubKey, PlaceholderMarker) {
		t.Skip("a real public key is committed")
	}
	if _, err := ParsePublicKey(embeddedPubKey); !errors.Is(err, ErrPlaceholderKey) {
		t.Fatalf("placeholder key: got %v, want ErrPlaceholderKey", err)
	}
}

func TestVerifyFile(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, otherPriv, _ := minisign.GenerateKey(rand.Reader)
	_ = otherPub

	msg := bytes.Repeat([]byte("clamav-agent binary "), 5000)
	file := writeFile(t, dir, "agent", msg)

	r := minisign.NewReader(bytes.NewReader(msg))
	_, _ = r.Read(make([]byte, len(msg)+1))
	hashedSig := r.SignWithComments(priv, "timestamp:1\tfile:agent", "test")
	legacySig := minisign.SignWithComments(priv, msg, "legacy", "test")
	otherSig := minisign.SignWithComments(otherPriv, msg, "x", "test")

	pubText, _ := pub.MarshalText()
	pk, err := ParsePublicKey(string(pubText))
	if err != nil {
		t.Fatal(err)
	}
	// Bare base64 line form, as used in install scripts.
	if _, err := ParsePublicKey(pub.String()); err != nil {
		t.Fatalf("bare key: %v", err)
	}

	t.Run("prehashed ok", func(t *testing.T) {
		res, err := VerifyFileWithKey(pk, file, writeFile(t, dir, "h.minisig", hashedSig))
		if err != nil || !res.Prehashed || res.TrustedComment != "timestamp:1\tfile:agent" {
			t.Fatalf("res=%+v err=%v", res, err)
		}
	})
	t.Run("legacy ok", func(t *testing.T) {
		res, err := VerifyFileWithKey(pk, file, writeFile(t, dir, "l.minisig", legacySig))
		if err != nil || res.Prehashed {
			t.Fatalf("res=%+v err=%v", res, err)
		}
	})
	t.Run("tampered file", func(t *testing.T) {
		bad := append(bytes.Clone(msg), 'x')
		f := writeFile(t, dir, "bad", bad)
		if _, err := VerifyFileWithKey(pk, f, writeFile(t, dir, "h2.minisig", hashedSig)); err == nil {
			t.Fatal("tampered file verified")
		}
	})
	t.Run("tampered trusted comment", func(t *testing.T) {
		s := strings.Replace(string(hashedSig), "file:agent", "file:agenX", 1)
		if _, err := VerifyFileWithKey(pk, file, writeFile(t, dir, "tc.minisig", []byte(s))); err == nil {
			t.Fatal("tampered trusted comment verified")
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		_, err := VerifyFileWithKey(pk, file, writeFile(t, dir, "o.minisig", otherSig))
		if err == nil || !strings.Contains(err.Error(), "key id") {
			t.Fatalf("wrong key: %v", err)
		}
	})
	t.Run("garbage signature", func(t *testing.T) {
		if _, err := VerifyFileWithKey(pk, file, writeFile(t, dir, "g.minisig", []byte("hello"))); err == nil {
			t.Fatal("garbage verified")
		}
	})
}

func TestOverride(t *testing.T) {
	pub, _, _ := minisign.GenerateKey(rand.Reader)
	old := pubKeyOverride
	t.Cleanup(func() { pubKeyOverride = old })
	pubKeyOverride = pub.String()
	pk, err := PublicKey()
	if err != nil || pk.ID() != pub.ID() || !IsTestKey() {
		t.Fatalf("override: %v", err)
	}
}
