// Command release-sign creates minisign keys and signs agent release files.
//
// It is meant to run on an OFFLINE release workstation that holds the
// password-protected secret key. Never copy the secret key to the console
// server or commit it. See docs/release-signing.md.
//
//	release-sign keygen -s minisign.key -p minisign.pub
//	release-sign sign   -s minisign.key [-p minisign.pub] [-t COMMENT] FILE...
//	release-sign verify -p minisign.pub FILE...
//
// The password is read from MINISIGN_PASSWORD if set, otherwise prompted for
// on the terminal. Signatures are standard prehashed minisign signatures
// (FILE.minisig) that the minisign CLI can verify.
package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aead.dev/minisign"
	"golang.org/x/term"

	"github.com/Soup9x/Lake-Effect-Bouy/internal/release"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "release-sign:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  release-sign keygen -s SECRET_KEY_FILE -p PUBLIC_KEY_FILE
  release-sign sign   -s SECRET_KEY_FILE [-p PUBLIC_KEY_FILE] [-t TRUSTED_COMMENT] FILE...
  release-sign verify -p PUBLIC_KEY_FILE FILE...

Password: MINISIGN_PASSWORD env var, else prompted on the terminal.
Run this on an offline release workstation only.
`)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	secPath := fs.String("s", "", "secret key output file")
	pubPath := fs.String("p", "", "public key output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *secPath == "" || *pubPath == "" || fs.NArg() != 0 {
		return errors.New("keygen needs -s and -p")
	}
	for _, p := range []string{*secPath, *pubPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite a key", p)
		}
	}
	password, err := readPassword(true)
	if err != nil {
		return err
	}
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	encrypted, err := minisign.EncryptKey(password, priv)
	if err != nil {
		return err
	}
	pubText, err := pub.MarshalText()
	if err != nil {
		return err
	}
	if err := writeNew(*secPath, encrypted, 0o600); err != nil {
		return err
	}
	if err := writeNew(*pubPath, append(pubText, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("Key ID %016X\nSecret key (password protected): %s\nPublic key: %s\n", pub.ID(), *secPath, *pubPath)
	fmt.Println("Back up the secret key and its password offline now. See docs/release-signing.md.")
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	secPath := fs.String("s", "", "secret key file")
	pubPath := fs.String("p", "", "optional public key file; each signature is verified against it after signing")
	comment := fs.String("t", "", "trusted comment (default: timestamp and file name)")
	// Legacy (non-prehashed) signatures exist only so tests can exercise the
	// install scripts' legacy verification path. Do not use for releases.
	legacy := fs.Bool("legacy-for-testing", false, "produce legacy non-prehashed signatures (testing only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *secPath == "" || fs.NArg() == 0 {
		return errors.New("sign needs -s and at least one file")
	}
	if strings.ContainsAny(*comment, "\r\n") {
		return errors.New("trusted comment must be a single line")
	}
	var expected *minisign.PublicKey
	if *pubPath != "" {
		b, err := os.ReadFile(*pubPath)
		if err != nil {
			return err
		}
		pk, err := release.ParsePublicKey(string(b))
		if err != nil {
			return err
		}
		expected = &pk
	}
	keyBytes, err := os.ReadFile(*secPath)
	if err != nil {
		return err
	}
	if !minisign.IsEncrypted(keyBytes) {
		return errors.New("secret key is not password protected; refusing to use it")
	}
	password, err := readPassword(false)
	if err != nil {
		return err
	}
	priv, err := minisign.DecryptKey(password, keyBytes)
	if err != nil {
		return fmt.Errorf("decrypt secret key: %w", err)
	}
	if expected != nil && expected.ID() != priv.ID() {
		return fmt.Errorf("secret key id %016X does not match public key id %016X", priv.ID(), expected.ID())
	}
	untrusted := "signature from minisign secret key"
	for _, path := range fs.Args() {
		tc := *comment
		if tc == "" {
			tc = "timestamp:" + strconv.FormatInt(time.Now().Unix(), 10) + "\tfile:" + filepath.Base(path)
		}
		var sig []byte
		if *legacy {
			msg, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
			if err != nil {
				return err
			}
			sig = minisign.SignWithComments(priv, msg, tc, untrusted)
		} else {
			f, err := os.Open(path) //nolint:gosec // operator-supplied path on the release workstation
			if err != nil {
				return err
			}
			r := minisign.NewReader(f)
			_, err = io.Copy(io.Discard, r)
			_ = f.Close()
			if err != nil {
				return err
			}
			sig = r.SignWithComments(priv, tc, untrusted)
		}
		sigPath := path + ".minisig"
		if err := os.WriteFile(sigPath, sig, 0o644); err != nil { //nolint:gosec // signatures are public
			return err
		}
		if expected != nil {
			if _, err := release.VerifyFileWithKey(*expected, path, sigPath); err != nil {
				return fmt.Errorf("self-check of %s failed: %w", sigPath, err)
			}
		}
		fmt.Println("signed", path)
	}
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubPath := fs.String("p", "", "public key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pubPath == "" || fs.NArg() == 0 {
		return errors.New("verify needs -p and at least one file")
	}
	b, err := os.ReadFile(*pubPath)
	if err != nil {
		return err
	}
	pk, err := release.ParsePublicKey(string(b))
	if err != nil {
		return err
	}
	failed := false
	for _, path := range fs.Args() {
		res, err := release.VerifyFileWithKey(pk, path, path+".minisig")
		if err != nil {
			fmt.Printf("FAIL %s: %v\n", path, err)
			failed = true
			continue
		}
		fmt.Printf("OK   %s (trusted comment: %s)\n", path, res.TrustedComment)
	}
	if failed {
		return errors.New("one or more signatures failed")
	}
	return nil
}

// readPassword returns MINISIGN_PASSWORD or prompts on the terminal.
func readPassword(confirm bool) (string, error) {
	if p, ok := os.LookupEnv("MINISIGN_PASSWORD"); ok {
		if p == "" {
			return "", errors.New("MINISIGN_PASSWORD is set but empty")
		}
		return p, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// Allow piping the password in (one line), e.g. from a password manager.
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", errors.New("no password: set MINISIGN_PASSWORD or run on a terminal")
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return "", errors.New("empty password")
		}
		return line, nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	p1, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if len(p1) == 0 {
		return "", errors.New("empty password")
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Password (again): ")
		p2, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(p1) != string(p2) {
			return "", errors.New("passwords do not match")
		}
	}
	return string(p1), nil
}

func writeNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) //nolint:gosec // operator-supplied path
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
