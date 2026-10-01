package transport

import (
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPinning(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://example.com/", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	good := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)

	get := func(c *http.Client, path string) (int, error) {
		resp, err := c.Get(srv.URL + path)
		if err != nil {
			return 0, err
		}
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}
	if code, err := get(NewClient(Options{RootCAs: pool, SPKIPin: good[:]}), "/"); err != nil || code != 204 {
		t.Fatalf("good pin: %d %v", code, err)
	}
	bad := make([]byte, 32)
	if _, err := get(NewClient(Options{RootCAs: pool, SPKIPin: bad}), "/"); err == nil {
		t.Fatal("bad pin accepted")
	}
	// A matching pin must not bypass normal verification.
	if _, err := get(NewClient(Options{SPKIPin: good[:]}), "/"); err == nil {
		t.Fatal("untrusted cert accepted because of pin")
	}
	if code, err := get(NewClient(Options{RootCAs: pool}), "/redirect"); err != nil || code != http.StatusFound {
		t.Fatalf("redirect followed: %d %v", code, err)
	}
}
