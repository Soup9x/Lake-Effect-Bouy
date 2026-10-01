// Package auth implements password hashing and session-based authentication
// for the web UI, with an MFA-ready auth level on each session.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters (OWASP-recommended range).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

const (
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

func ValidatePassword(pw, email string) error {
	n := utf8.RuneCountInString(pw)
	if n < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if len(pw) > MaxPasswordLen {
		return fmt.Errorf("password must be at most %d bytes", MaxPasswordLen)
	}
	if email != "" && strings.Contains(strings.ToLower(pw), strings.ToLower(strings.SplitN(email, "@", 2)[0])) {
		return errors.New("password must not contain your email name")
	}
	return nil
}

func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func CheckPassword(pw, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want))) //nolint:gosec // len(want) is a hash length, far below 2^32
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is checked when the user doesn't exist, so response time doesn't
// reveal which emails have accounts.
var dummyHash, _ = HashPassword("dummy-password-for-timing")

func CheckDummy(pw string) { CheckPassword(pw, dummyHash) }
