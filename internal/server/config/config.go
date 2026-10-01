// Package config loads server configuration from environment variables.
// Secrets are only ever read from the environment (CLAUDE.md rule 4).
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr  string
	PublicURL   *url.URL
	DatabaseURL string
	// MigrateDatabaseURL, when set, makes `serve` apply migrations on start
	// using this (owner) role. In Compose a separate one-shot migrate
	// container does this instead, so the server never holds owner creds.
	MigrateDatabaseURL string

	// TokenHashKey is the HMAC key for enrollment tokens, agent credentials
	// and session tokens. TokenHashKeyPrevious, when set, is accepted for
	// lookups during a key rotation (see docs/operations.md).
	TokenHashKey         []byte
	TokenHashKeyPrevious []byte

	AgentOfflineAfter time.Duration
	DownloadsDir      string

	// TrustedProxies are the peers whose X-Forwarded-For header is believed.
	TrustedProxies []netip.Prefix
	// AdminAllowedCIDRs restricts the UI to these client networks. Caddy
	// enforces the same list; the server checks it again as defense in depth.
	AdminAllowedCIDRs []netip.Prefix

	SessionIdleTimeout     time.Duration
	SessionAbsoluteTimeout time.Duration
	// CookieSecure must stay true in production; false only for local HTTP dev.
	CookieSecure bool
}

// placeholders from .env.example; refusing them stops a copy-paste deploy.
var placeholders = []string{"change-me", "changeme", "CHANGE_ME", "replace-with"}

func Load() (*Config, error) {
	var errs []error
	c := &Config{
		ListenAddr:             getenv("LISTEN_ADDR", ":8080"),
		DatabaseURL:            os.Getenv("DATABASE_URL"),
		MigrateDatabaseURL:     os.Getenv("MIGRATE_DATABASE_URL"),
		DownloadsDir:           getenv("DOWNLOADS_DIR", "/srv/downloads"),
		SessionIdleTimeout:     30 * time.Minute,
		SessionAbsoluteTimeout: 12 * time.Hour,
		CookieSecure:           os.Getenv("INSECURE_COOKIES_FOR_DEV") != "true",
	}
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}

	pub := os.Getenv("PUBLIC_URL")
	if u, err := url.Parse(pub); err != nil || pub == "" || u.Host == "" {
		errs = append(errs, errors.New("PUBLIC_URL must be an absolute URL, e.g. https://console.example.com"))
	} else {
		if u.Scheme != "https" && c.CookieSecure {
			errs = append(errs, errors.New("PUBLIC_URL must use https"))
		}
		c.PublicURL = u
	}

	var err error
	if c.TokenHashKey, err = loadKey("TOKEN_HASH_KEY", true); err != nil {
		errs = append(errs, err)
	}
	if c.TokenHashKeyPrevious, err = loadKey("TOKEN_HASH_KEY_PREVIOUS", false); err != nil {
		errs = append(errs, err)
	}

	secs, err := strconv.Atoi(getenv("AGENT_OFFLINE_AFTER_SECONDS", "180"))
	if err != nil || secs < 60 || secs > 86400 {
		errs = append(errs, errors.New("AGENT_OFFLINE_AFTER_SECONDS must be 60..86400"))
	}
	c.AgentOfflineAfter = time.Duration(secs) * time.Second

	if c.TrustedProxies, err = parsePrefixes(os.Getenv("TRUSTED_PROXIES")); err != nil {
		errs = append(errs, fmt.Errorf("TRUSTED_PROXIES: %w", err))
	}
	if c.AdminAllowedCIDRs, err = parsePrefixes(os.Getenv("ADMIN_ALLOWED_CIDRS")); err != nil {
		errs = append(errs, fmt.Errorf("ADMIN_ALLOWED_CIDRS: %w", err))
	} else if len(c.AdminAllowedCIDRs) == 0 {
		errs = append(errs, errors.New("ADMIN_ALLOWED_CIDRS is required (space-separated CIDRs, e.g. 100.64.0.0/10)"))
	}
	return c, errors.Join(errs...)
}

// loadKey reads a base64 key of at least 32 bytes.
func loadKey(name string, required bool) ([]byte, error) {
	v := os.Getenv(name)
	if v == "" {
		if required {
			return nil, fmt.Errorf("%s is required (generate with: openssl rand -base64 32)", name)
		}
		return nil, nil
	}
	for _, p := range placeholders {
		if strings.Contains(v, p) {
			return nil, fmt.Errorf("%s still has the placeholder value from .env.example", name)
		}
	}
	k, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("%s must be base64: %w", name, err)
	}
	if len(k) < 32 {
		return nil, fmt.Errorf("%s must decode to at least 32 bytes", name)
	}
	return k, nil
}

func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	// Comma- or space-separated, so the same value works in the Caddyfile.
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if !strings.Contains(part, "/") {
			a, err := netip.ParseAddr(part)
			if err != nil {
				return nil, err
			}
			part = netip.PrefixFrom(a, a.BitLen()).String()
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
