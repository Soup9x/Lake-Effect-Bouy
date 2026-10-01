// Package release holds the minisign public key that agent releases are signed
// with, and verifies release files against it.
//
// The secret key never lives on the server or in this repository (see
// docs/release-signing.md). The committed minisign.pub is the only trust
// anchor; it is embedded at build time.
package release

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"aead.dev/minisign"
)

//go:embed minisign.pub
var embeddedPubKey string

// pubKeyOverride replaces the embedded key in throwaway test builds only. It is
// set by scripts/build-dist.sh via -ldflags -X when RELEASE_PUBKEY_FILE is
// given, and must never be used for a real release.
var pubKeyOverride string

// PlaceholderMarker marks the committed placeholder key file. Release tooling
// refuses to build while it is present.
const PlaceholderMarker = "PLACEHOLDER"

// ErrPlaceholderKey means this binary was built without a real release key.
var ErrPlaceholderKey = errors.New("release: this build embeds the placeholder public key; signatures cannot be verified")

// maxLegacyMessage caps the size of a file verified with a legacy (non
// prehashed) signature, which must be held in memory.
const maxLegacyMessage = 512 << 20

// PublicKeyText returns the minisign public key text this binary trusts.
func PublicKeyText() string {
	if pubKeyOverride != "" {
		return pubKeyOverride
	}
	return embeddedPubKey
}

// IsTestKey reports whether the key was injected at build time rather than
// embedded from the committed file.
func IsTestKey() bool { return pubKeyOverride != "" }

// PublicKey parses the trusted public key.
func PublicKey() (minisign.PublicKey, error) {
	return ParsePublicKey(PublicKeyText())
}

// ParsePublicKey parses a minisign public key, either the two-line file form
// or the bare base64 line.
func ParsePublicKey(text string) (minisign.PublicKey, error) {
	var pk minisign.PublicKey
	if strings.Contains(text, PlaceholderMarker) {
		return pk, ErrPlaceholderKey
	}
	if err := pk.UnmarshalText([]byte(strings.TrimSpace(text))); err != nil {
		return pk, fmt.Errorf("release: parse public key: %w", err)
	}
	return pk, nil
}

// Result describes a successful verification.
type Result struct {
	KeyID          string
	TrustedComment string
	Prehashed      bool
}

// VerifyFile checks that sigPath is a valid minisign signature of filePath by
// the trusted key, including the trusted-comment (global) signature.
func VerifyFile(filePath, sigPath string) (Result, error) {
	pk, err := PublicKey()
	if err != nil {
		return Result{}, err
	}
	return VerifyFileWithKey(pk, filePath, sigPath)
}

// VerifyFileWithKey is VerifyFile with an explicit public key.
func VerifyFileWithKey(pk minisign.PublicKey, filePath, sigPath string) (Result, error) {
	sigText, err := readSmall(sigPath, 4096)
	if err != nil {
		return Result{}, fmt.Errorf("release: read signature: %w", err)
	}
	var sig minisign.Signature
	if err := sig.UnmarshalText(sigText); err != nil {
		return Result{}, fmt.Errorf("release: parse signature: %w", err)
	}
	if sig.KeyID != pk.ID() {
		return Result{}, fmt.Errorf("release: signature key id %016X does not match trusted key %016X", sig.KeyID, pk.ID())
	}

	f, err := os.Open(filePath) //nolint:gosec // caller-chosen file to verify
	if err != nil {
		return Result{}, fmt.Errorf("release: open file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var ok bool
	switch sig.Algorithm {
	case minisign.HashEdDSA:
		// Prehashed: stream the file through BLAKE2b-512.
		r := minisign.NewReader(f)
		if _, err := io.Copy(io.Discard, r); err != nil {
			return Result{}, fmt.Errorf("release: read file: %w", err)
		}
		ok = r.Verify(pk, sigText)
	case minisign.EdDSA:
		msg, err := io.ReadAll(io.LimitReader(f, maxLegacyMessage+1))
		if err != nil {
			return Result{}, fmt.Errorf("release: read file: %w", err)
		}
		if len(msg) > maxLegacyMessage {
			return Result{}, errors.New("release: file too large for a legacy signature")
		}
		ok = minisign.Verify(pk, msg, sigText)
	default:
		return Result{}, fmt.Errorf("release: unsupported signature algorithm %#x", sig.Algorithm)
	}
	if !ok {
		return Result{}, errors.New("release: signature verification FAILED")
	}
	return Result{
		KeyID:          fmt.Sprintf("%016X", pk.ID()),
		TrustedComment: sig.TrustedComment,
		Prehashed:      sig.Algorithm == minisign.HashEdDSA,
	}, nil
}

func readSmall(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // caller-chosen signature file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file too large")
	}
	return b, nil
}
