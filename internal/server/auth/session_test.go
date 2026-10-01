package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Browsers drop a __Host- cookie unless it is Secure with Path=/, so a missing
// attribute silently breaks every login in production.
func TestSessionCookieAttributes(t *testing.T) {
	for _, secure := range []bool{true, false} {
		m := &Manager{Secure: secure}
		for name, c := range map[string]*http.Cookie{"session": m.sessionCookie("tok"), "clear": clearedCookie(t, m)} {
			if c.Name != m.CookieName() {
				t.Errorf("secure=%v %s: name %q, want %q", secure, name, c.Name, m.CookieName())
			}
			if c.Path != "/" || !c.HttpOnly || c.Secure != secure || c.SameSite != http.SameSiteStrictMode {
				t.Errorf("secure=%v %s: Path=%q HttpOnly=%v Secure=%v SameSite=%v", secure, name, c.Path, c.HttpOnly, c.Secure, c.SameSite)
			}
		}
	}
	if got := (&Manager{Secure: true}).CookieName(); got != "__Host-cav_session" {
		t.Errorf("secure cookie name %q", got)
	}
}

// clearedCookie parses the Set-Cookie header ClearCookie writes, so the test
// checks what a browser actually receives.
func clearedCookie(t *testing.T, m *Manager) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	m.ClearCookie(rec)
	cs := rec.Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("ClearCookie set %d cookies", len(cs))
	}
	if cs[0].MaxAge >= 0 {
		t.Errorf("ClearCookie MaxAge %d, want < 0", cs[0].MaxAge)
	}
	return cs[0]
}
