// Package credstore persists the agent credential in a single file.
//
// Writes are atomic (temp file in the same directory + rename), so a crash
// never leaves a truncated credential. On Linux the file is 0600; on Windows
// the install script ACLs the directory so new files inherit access for
// NT SERVICE\ClamAVAgent and Administrators only.
package credstore

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Soup9x/Lake-Effect-Bouy/internal/protocol"
)

const maxCredentialLen = 512

// ErrNotFound means no credential has been stored (the agent is not enrolled).
var ErrNotFound = errors.New("credstore: no credential stored (run `clamav-agent enroll`)")

// Store is a credential file.
type Store struct{ Path string }

// Validate checks the shape of a credential without revealing it in errors.
func Validate(cred string) error {
	if !strings.HasPrefix(cred, protocol.CredentialPrefix) || len(cred) <= len(protocol.CredentialPrefix) {
		return errors.New("credstore: credential has an unexpected format")
	}
	if len(cred) > maxCredentialLen {
		return errors.New("credstore: credential is too long")
	}
	for i := 0; i < len(cred); i++ {
		if c := cred[i]; c <= 0x20 || c >= 0x7f {
			return errors.New("credstore: credential contains invalid characters")
		}
	}
	return nil
}

// Exists reports whether a credential file is present.
func (s Store) Exists() bool {
	_, err := os.Stat(s.Path)
	return err == nil
}

// Load reads and validates the stored credential.
func (s Store) Load() (string, error) {
	f, err := os.Open(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("credstore: %w", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxCredentialLen+2))
	if err != nil {
		return "", fmt.Errorf("credstore: read: %w", err)
	}
	cred := strings.TrimSpace(string(b))
	if err := Validate(cred); err != nil {
		return "", err
	}
	return cred, nil
}

// Save atomically replaces the stored credential.
func (s Store) Save(cred string) error {
	if err := Validate(cred); err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("credstore: create %s: %w", dir, err)
	}
	// CreateTemp creates the file with mode 0600.
	tmp, err := os.CreateTemp(dir, ".credential.tmp-*")
	if err != nil {
		return fmt.Errorf("credstore: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if _, err := tmp.WriteString(cred + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("credstore: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("credstore: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("credstore: close: %w", err)
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		return fmt.Errorf("credstore: rename: %w", err)
	}
	syncDir(dir)
	return nil
}
