package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Local Authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestLoadConsoleCA(t *testing.T) {
	dir := t.TempDir()
	if ca, err := loadConsoleCA(dir); ca != nil || err != nil {
		t.Fatalf("no CA file: %v %v", ca, err)
	}
	if ca, err := loadConsoleCA(""); ca != nil || err != nil {
		t.Fatalf("no downloads dir: %v %v", ca, err)
	}
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	der := testCert(t, true)
	write(ConsoleCAFile, pemCert(der))
	ca, err := loadConsoleCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if ca.fingerprint != hex.EncodeToString(sum[:]) || ca.ps1SHA256 != "" {
		t.Fatalf("got %+v", ca)
	}
	write("install.ps1", []byte("script"))
	ca, _ = loadConsoleCA(dir)
	ps1 := sha256.Sum256([]byte("script"))
	if ca.ps1SHA256 != strings.ToUpper(hex.EncodeToString(ps1[:])) {
		t.Fatalf("install.ps1 hash %q", ca.ps1SHA256)
	}

	for name, b := range map[string][]byte{
		"not a CA":  pemCert(testCert(t, false)),
		"two certs": append(pemCert(der), pemCert(der)...),
		"junk":      []byte("hello"),
		"key":       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}),
	} {
		write(ConsoleCAFile, b)
		if _, err := loadConsoleCA(dir); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

const testToken = "cav_enr_abcdefghijklmnopqrstuvwxyz234567"

func TestInstallCommandsPublicCA(t *testing.T) {
	c := buildInstallCommands("https://console.example.com", testToken, nil)
	if c.CAFingerprint != "" || c.Problem != "" {
		t.Fatalf("%+v", c)
	}
	checkTokenHandling(t, c)
	for _, s := range []string{"--cacert", "-k ", "SkipCertificateCheck", "CaSha256", "--ca-sha256"} {
		if strings.Contains(c.Linux+c.Windows, s) {
			t.Errorf("public-CA commands contain %q", s)
		}
	}
}

func TestInstallCommandsPrivateCA(t *testing.T) {
	ca := &consoleCA{fingerprint: strings.Repeat("ab", 32), ps1SHA256: strings.Repeat("CD", 32)}
	c := buildInstallCommands("https://192.0.2.10", testToken, ca)
	if c.Problem != "" || !strings.HasPrefix(c.CAFingerprint, "AB:AB:") || len(c.CAFingerprint) != 95 {
		t.Fatalf("%+v", c)
	}
	checkTokenHandling(t, c)
	for _, s := range []string{`--cacert "$d/ca.pem"`, "--ca-sha256 " + ca.fingerprint, `= ` + ca.fingerprint + ` ]`} {
		if !strings.Contains(c.Linux, s) {
			t.Errorf("Linux command lacks %q:\n%s", s, c.Linux)
		}
	}
	for _, s := range []string{"-ne '" + ca.ps1SHA256 + "'", "-CaSha256 " + ca.fingerprint} {
		if !strings.Contains(c.Windows, s) {
			t.Errorf("Windows command lacks %q:\n%s", s, c.Windows)
		}
	}

	// Without a published install.ps1 there is nothing to pin on Windows.
	c = buildInstallCommands("https://192.0.2.10", testToken, &consoleCA{fingerprint: ca.fingerprint})
	if c.Windows != "" || c.Problem == "" || c.Linux == "" {
		t.Fatalf("no install.ps1: %+v", c)
	}
}

// checkTokenHandling: the token is only ever piped (Linux) or put in the
// session environment (Windows), never passed as an argument.
func checkTokenHandling(t *testing.T, c installCommands) {
	t.Helper()
	if strings.Count(c.Linux, testToken) != 1 || !strings.Contains(c.Linux, `printf '%s\n' '`+testToken+`' | sudo sh `) {
		t.Errorf("Linux token handling:\n%s", c.Linux)
	}
	if strings.Count(c.Windows, testToken) != 1 || !strings.Contains(c.Windows, `$env:CAV_ENROLL_TOKEN = '`+testToken+`'`) ||
		!strings.Contains(c.Windows, `Remove-Item Env:\CAV_ENROLL_TOKEN`) {
		t.Errorf("Windows token handling:\n%s", c.Windows)
	}
	if !strings.HasPrefix(c.Windows, "& {") || !strings.HasSuffix(c.Windows, "}") {
		t.Errorf("Windows command is not a single script block:\n%s", c.Windows)
	}
}

func TestColonHex(t *testing.T) {
	if got := colonHex("0aff10"); got != "0A:FF:10" {
		t.Fatal(got)
	}
}
