// Package transport builds the agent's outbound HTTPS client.
package transport

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"time"
)

// Options configures the HTTP client.
type Options struct {
	// SPKIPin, when non-nil, is a SHA-256 of a SubjectPublicKeyInfo that must
	// appear in the verified chain. Normal verification still applies.
	SPKIPin []byte
	// RootCAs overrides the system trust store (tests only).
	RootCAs *x509.CertPool
	Timeout time.Duration
}

// NewClient returns an HTTP client for talking to the console. It uses the
// system trust store, TLS 1.2+, honours HTTPS_PROXY, and never follows
// redirects (a redirect could send the bearer credential elsewhere).
func NewClient(o Options) *http.Client {
	if o.Timeout == 0 {
		o.Timeout = 30 * time.Second
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.RootCAs}
	if o.SPKIPin != nil {
		pin := o.SPKIPin
		// VerifyConnection runs after the standard chain verification.
		tlsConf.VerifyConnection = func(cs tls.ConnectionState) error {
			return checkPin(cs.VerifiedChains, pin)
		}
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tlsConf,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          2,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   o.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ErrPinMismatch means no certificate in the verified chain matched the pin.
var ErrPinMismatch = errors.New("tls: no certificate in the server's chain matches ca_cert_pin")

func checkPin(chains [][]*x509.Certificate, pin []byte) error {
	for _, chain := range chains {
		for _, c := range chain {
			sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], pin) == 1 {
				return nil
			}
		}
	}
	return ErrPinMismatch
}
