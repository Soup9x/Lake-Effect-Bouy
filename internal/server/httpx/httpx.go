// Package httpx has small HTTP helpers shared by the agent API and the UI.
package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type ctxKey int

const (
	keyClientIP ctxKey = iota
	keyRequestID
)

// ClientIP returns the client address resolved by the RealIP middleware.
func ClientIP(r *http.Request) *netip.Addr {
	if a, ok := r.Context().Value(keyClientIP).(netip.Addr); ok {
		return &a
	}
	return nil
}

func RequestID(r *http.Request) string {
	s, _ := r.Context().Value(keyRequestID).(string)
	return s
}

// RealIP resolves the client IP. X-Forwarded-For is believed only when the
// direct peer is a trusted proxy, and then the right-most untrusted hop wins.
func RealIP(trusted []netip.Prefix) func(http.Handler) http.Handler {
	isTrusted := func(a netip.Addr) bool {
		for _, p := range trusted {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			ip, err := netip.ParseAddr(host)
			if err == nil {
				ip = ip.Unmap()
				if isTrusted(ip) {
					hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
					for i := len(hops) - 1; i >= 0; i-- {
						h, perr := netip.ParseAddr(strings.TrimSpace(hops[i]))
						if perr != nil {
							break
						}
						ip = h.Unmap()
						if !isTrusted(ip) {
							break
						}
					}
				}
				r = r.WithContext(context.WithValue(r.Context(), keyClientIP, ip))
			}
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id := hex.EncodeToString(b)
			w.Header().Set("X-Request-Id", id)
			r = r.WithContext(context.WithValue(r.Context(), keyRequestID, id))
			next.ServeHTTP(w, r)
		})
	}
}

// AllowCIDRs rejects requests whose client IP is outside allowed with 404, so
// admin routes look absent from untrusted networks.
func AllowCIDRs(allowed []netip.Prefix, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		if ip != nil {
			for _, p := range allowed {
				if p.Contains(*ip) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		http.NotFound(w, r)
	})
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// SecurityHeaders sets headers common to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
