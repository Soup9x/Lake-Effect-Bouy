package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/audit"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/httpx"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/secret"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/store"
)

// Auth levels. A session reaches LevelMFA only after a second factor; until
// MFA ships, users without a confirmed factor are fully authenticated at
// LevelPassword.
const (
	LevelPassword = 1
	LevelMFA      = 2
)

// BackgroundHeader marks UI auto-refresh requests. They are authenticated
// normally but never extend the idle timeout (design 0a.5).
const BackgroundHeader = "X-Background-Refresh"

const (
	maxFailures = 10
	lockFor     = 15 * time.Minute
	// touchEvery limits last_seen_at writes to one per minute per session.
	touchEvery = time.Minute
)

type Manager struct {
	DB              *pgxpool.Pool
	Hasher          *secret.Hasher
	Log             *slog.Logger
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	Secure          bool
	now             func() time.Time
}

func NewManager(db *pgxpool.Pool, h *secret.Hasher, log *slog.Logger, idle, absolute time.Duration, secure bool) *Manager {
	return &Manager{DB: db, Hasher: h, Log: log, IdleTimeout: idle, AbsoluteTimeout: absolute, Secure: secure, now: time.Now}
}

func (m *Manager) CookieName() string {
	if m.Secure {
		return "__Host-cav_session"
	}
	return "cav_session"
}

var (
	ErrBadCredentials = errors.New("invalid email or password")
	ErrLocked         = errors.New("account temporarily locked")
)

// Login verifies a password and creates a session. Every outcome is audited.
func (m *Manager) Login(ctx context.Context, w http.ResponseWriter, r *http.Request, email, password string) (*store.Session, error) {
	req := audit.Request{IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	fail := func(u *store.User, reason string, err error) (*store.Session, error) {
		e := audit.Entry{Actor: audit.Actor{Type: audit.ActorAnonymous, Label: email}, Request: req,
			Action: audit.LoginFailed, Outcome: audit.Denied, TargetType: "user", Details: map[string]any{"reason": reason}}
		if u != nil {
			e.Actor = audit.Actor{Type: audit.ActorUser, ID: &u.ID, Label: u.Email}
			e.TargetID = u.ID.String()
		}
		if werr := audit.Write(ctx, m.DB, e); werr != nil {
			m.Log.Error("audit write failed", "err", werr)
		}
		return nil, err
	}

	u, err := store.GetUserByEmail(ctx, m.DB, email)
	if errors.Is(err, store.ErrNotFound) {
		CheckDummy(password)
		return fail(nil, "unknown_user", ErrBadCredentials)
	}
	if err != nil {
		return nil, err
	}
	if u.DisabledAt != nil {
		CheckDummy(password)
		return fail(u, "disabled", ErrBadCredentials)
	}
	if u.LockedUntil != nil && u.LockedUntil.After(m.now()) {
		CheckDummy(password)
		return fail(u, "locked", ErrLocked)
	}
	if !CheckPassword(password, u.PasswordHash) {
		locked, err := store.RecordLoginFailure(ctx, m.DB, u.ID, maxFailures, lockFor)
		if err != nil {
			return nil, err
		}
		if locked {
			_ = audit.Write(ctx, m.DB, audit.Entry{Actor: audit.Actor{Type: audit.ActorSystem, Label: "system"}, Request: req,
				Action: audit.LoginLocked, TargetType: "user", TargetID: u.ID.String(), Details: map[string]any{"email": u.Email}})
		}
		return fail(u, "bad_password", ErrBadCredentials)
	}

	mfa, err := store.HasConfirmedMFA(ctx, m.DB, u.ID)
	if err != nil {
		return nil, err
	}
	token := secret.Random(32)
	csrf := secret.Random(24)
	s, err := store.CreateSession(ctx, m.DB, m.Hasher.Hash(token), u.ID, LevelPassword, mfa, csrf,
		m.now().Add(m.AbsoluteTimeout), req.IP, truncate(r.UserAgent(), 500))
	if err != nil {
		return nil, err
	}
	if err := store.RecordLoginSuccess(ctx, m.DB, u.ID); err != nil {
		return nil, err
	}
	if err := audit.Write(ctx, m.DB, audit.Entry{Actor: audit.Actor{Type: audit.ActorUser, ID: &u.ID, Label: u.Email}, Request: req,
		Action: audit.LoginSuccess, TargetType: "session", TargetID: s.ID.String(), Details: map[string]any{"mfa_required": mfa}}); err != nil {
		return nil, err
	}
	// Secure is false only with INSECURE_COOKIES_FOR_DEV=true.
	http.SetCookie(w, &http.Cookie{Name: m.CookieName(), Value: token, //nolint:gosec // see above Path: "/", HttpOnly: true, Secure: m.Secure,
		SameSite: http.SameSiteStrictMode, Expires: s.ExpiresAt})
	s.User = *u
	return s, nil
}

func (m *Manager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: m.CookieName(), Value: "", //nolint:gosec // Secure is false only in dev mode Path: "/", HttpOnly: true, Secure: m.Secure,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

type ctxKey struct{}

// SessionFrom returns the authenticated session, or nil.
func SessionFrom(r *http.Request) *store.Session {
	s, _ := r.Context().Value(ctxKey{}).(*store.Session)
	return s
}

// Load resolves the session cookie, enforcing revocation, absolute expiry,
// idle timeout and disabled users. It does not reject unauthenticated
// requests; use Require for that.
func (m *Manager) Load(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(m.CookieName())
		if err != nil || c.Value == "" || len(c.Value) > 128 {
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		s, err := store.GetActiveSession(ctx, m.DB, m.Hasher.Hash(c.Value))
		if errors.Is(err, store.ErrNotFound) {
			if prev := m.Hasher.PreviousHash(c.Value); prev != nil {
				if s, err = store.GetActiveSession(ctx, m.DB, prev); err == nil {
					_ = store.RehashSession(ctx, m.DB, s.ID, m.Hasher.Hash(c.Value))
				}
			}
		}
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				m.Log.Error("session lookup failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			m.ClearCookie(w)
			next.ServeHTTP(w, r)
			return
		}
		now := m.now()
		if now.Sub(s.LastSeenAt) > m.IdleTimeout {
			_ = store.RevokeSession(ctx, m.DB, s.ID)
			_ = audit.Write(ctx, m.DB, audit.Entry{Actor: audit.Actor{Type: audit.ActorSystem, Label: "system"},
				Request: audit.Request{IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)},
				Action:  audit.SessionExpired, TargetType: "session", TargetID: s.ID.String(), Details: map[string]any{"user": s.User.Email, "reason": "idle"}})
			m.ClearCookie(w)
			next.ServeHTTP(w, r)
			return
		}
		// Background refreshes must not keep a session alive (design 0a.5).
		if r.Header.Get(BackgroundHeader) == "" && now.Sub(s.LastSeenAt) > touchEvery {
			if err := store.TouchSession(ctx, m.DB, s.ID); err != nil {
				m.Log.Error("touch session failed", "err", err)
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, ctxKey{}, s)))
	})
}

// FullyAuthenticated reports whether s may access protected routes: a
// password session suffices unless the user has MFA configured.
func FullyAuthenticated(s *store.Session) bool {
	if s == nil {
		return false
	}
	if s.MFARequired {
		return s.AuthLevel >= LevelMFA
	}
	return s.AuthLevel >= LevelPassword
}

// CheckCSRF validates the per-session token on state-changing requests. It
// accepts the X-CSRF-Token header (htmx) or the csrf_token form field.
func CheckCSRF(r *http.Request, s *store.Session) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		got = r.PostFormValue("csrf_token")
	}
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.CSRFToken)) == 1
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
