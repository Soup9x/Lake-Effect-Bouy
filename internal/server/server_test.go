package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"html"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/auth"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/config"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/store"
)

// Integration tests need TEST_DATABASE_URL pointing at a Postgres role that
// may CREATE DATABASE. Each run uses a fresh throwaway database.
func testDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "cav_test_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	u, _ := url.Parse(base)
	u.Path = "/" + name
	if err := Migrate(ctx, u.String()); err != nil {
		t.Fatal(err)
	}
	pool, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

type env struct {
	t         *testing.T
	pool      *pgxpool.Pool
	srv       *httptest.Server
	client    *http.Client
	csrf      string
	downloads string
}

func setup(t *testing.T, allowed string) *env {
	pool := testDB(t)
	pu, _ := url.Parse("https://console.example.test")
	cfg := &config.Config{
		PublicURL: pu, TokenHashKey: bytes.Repeat([]byte("k"), 32), AgentOfflineAfter: 3 * time.Minute,
		DownloadsDir: t.TempDir(), AdminAllowedCIDRs: []netip.Prefix{netip.MustParsePrefix(allowed)},
		SessionIdleTimeout: 30 * time.Minute, SessionAbsoluteTimeout: 12 * time.Hour,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(Handler(cfg, pool, log))
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &env{t: t, pool: pool, srv: srv, client: &http.Client{Jar: jar}, downloads: cfg.DownloadsDir}
}

func (e *env) do(method, path string, body io.Reader, hdr map[string]string) (int, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, body)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *env) form(path string, v url.Values) (int, string) {
	if v.Get("csrf_token") == "" && e.csrf != "" {
		v.Set("csrf_token", e.csrf)
	}
	return e.do("POST", path, strings.NewReader(v.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
}

func (e *env) login() {
	e.t.Helper()
	hash, _ := auth.HashPassword("correct horse battery staple")
	if _, err := store.CreateUser(context.Background(), e.pool, "admin@example.test", "Admin", hash); err != nil {
		e.t.Fatal(err)
	}
	code, body := e.form("/login", url.Values{"email": {"admin@example.test"}, "password": {"correct horse battery staple"}})
	if code != 200 || !strings.Contains(body, "Tenants") {
		e.t.Fatalf("login failed: %d", code)
	}
	e.csrf = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(body)[1]
}

func (e *env) agentCall(path string, body any, cred string) (int, map[string]any) {
	e.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func errCode(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

// enrollAgent creates a tenant and token via the UI and enrolls one agent.
func (e *env) enrollAgent() (tenantID, credential string) {
	e.t.Helper()
	_, body := e.form("/tenants", url.Values{"name": {"Acme"}})
	tenantID = regexp.MustCompile(`/tenants/([0-9a-f-]{36})/tokens`).FindStringSubmatch(body)[1]
	_, body = e.form("/tenants/"+tenantID+"/tokens", url.Values{"label": {"t"}, "expires_days": {"1"}})
	tok := regexp.MustCompile(`cav_enr_[a-z0-9]+`).FindString(body)
	code, resp := e.agentCall(protocol.PathEnroll, protocol.EnrollRequest{EnrollmentToken: tok, MachineID: "m1", Hostname: "host1",
		OSFamily: "linux", OSName: "Debian 12", OSVersion: "6.1", Arch: "amd64", AgentVersion: "0.1.0"}, "")
	if code != 201 {
		e.t.Fatalf("enroll: %d %v", code, resp)
	}
	return tenantID, resp["credential"].(string)
}

var hb = protocol.HeartbeatRequest{Hostname: "host1", OSName: "Debian 12", OSVersion: "6.1", AgentVersion: "0.1.0",
	ClamAV: protocol.ClamAVStatus{Status: protocol.ClamdRunning, EngineVersion: "1.4.1", SignatureVersion: 27410}}

func TestAgentRevokedOnlyForValidCredential(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	_, cred := e.enrollAgent()
	if code, _ := e.agentCall(protocol.PathHeartbeat, hb, cred); code != 200 {
		t.Fatalf("heartbeat: %d", code)
	}
	if code, m := e.agentCall(protocol.PathHeartbeat, hb, cred+"x"); code != 401 || errCode(m) != protocol.ErrUnauthorized {
		t.Fatalf("tampered credential: %d %v", code, m)
	}
	if code, m := e.agentCall(protocol.PathHeartbeat, hb, ""); code != 401 || errCode(m) != protocol.ErrUnauthorized {
		t.Fatalf("missing credential: %d %v", code, m)
	}
	id := strings.SplitN(strings.TrimPrefix(cred, protocol.CredentialPrefix), ".", 2)[0]
	if code, _ := e.form("/agents/"+id+"/revoke", url.Values{}); code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	if code, m := e.agentCall(protocol.PathHeartbeat, hb, cred); code != 401 || errCode(m) != protocol.ErrAgentRevoked {
		t.Fatalf("revoked: %d %v", code, m)
	}
	// A wrong secret for a revoked agent must not reveal revocation.
	if code, m := e.agentCall(protocol.PathHeartbeat, hb, cred+"x"); code != 401 || errCode(m) != protocol.ErrUnauthorized {
		t.Fatalf("tampered credential for revoked agent: %d %v", code, m)
	}
}

func TestArchivedTenantRevokesAgents(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	tenantID, cred := e.enrollAgent()
	if code, _ := e.form("/tenants/"+tenantID+"/archive", url.Values{}); code != 200 {
		t.Fatalf("archive: %d", code)
	}
	if code, m := e.agentCall(protocol.PathHeartbeat, hb, cred); code != 401 || errCode(m) != protocol.ErrAgentRevoked {
		t.Fatalf("archived tenant: %d %v", code, m)
	}
}

func TestAdminRoutesRestrictedByCIDR(t *testing.T) {
	e := setup(t, "10.0.0.0/8") // test client is 127.0.0.1, outside the allowlist
	for _, p := range []string{"/login", "/tenants", "/readyz", "/static/app.css"} {
		if code, _ := e.do("GET", p, nil, nil); code != 404 {
			t.Errorf("%s from disallowed IP: got %d, want 404", p, code)
		}
	}
	if code, _ := e.do("GET", "/healthz", nil, nil); code != 200 {
		t.Errorf("/healthz should be public, got %d", code)
	}
	if code, m := e.agentCall(protocol.PathEnroll, map[string]string{}, ""); code != 400 {
		t.Errorf("enroll should be public, got %d %v", code, m)
	}
	if code, _ := e.do("GET", "/downloads/missing", nil, nil); code != 404 {
		t.Errorf("downloads: got %d", code)
	}
}

func TestBackgroundRefreshDoesNotExtendSession(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	tenantID, _ := e.enrollAgent()
	ctx := context.Background()
	old := time.Now().Add(-20 * time.Minute).UTC().Truncate(time.Second)
	if _, err := e.pool.Exec(ctx, `UPDATE sessions SET last_seen_at=$1`, old); err != nil {
		t.Fatal(err)
	}
	lastSeen := func() time.Time {
		var ts time.Time
		if err := e.pool.QueryRow(ctx, `SELECT last_seen_at FROM sessions WHERE revoked_at IS NULL`).Scan(&ts); err != nil {
			t.Fatal(err)
		}
		return ts.UTC()
	}
	bg := map[string]string{auth.BackgroundHeader: "1", "HX-Request": "true"}
	if code, body := e.do("GET", "/tenants/"+tenantID+"/agents", nil, bg); code != 200 || !strings.Contains(body, "host1") {
		t.Fatalf("background refresh: %d", code)
	}
	if got := lastSeen(); !got.Equal(old) {
		t.Fatalf("background refresh moved last_seen_at from %v to %v", old, got)
	}
	e.do("GET", "/tenants/"+tenantID, nil, nil)
	if got := lastSeen(); !got.After(old) {
		t.Fatalf("foreground request did not extend session")
	}

	// Past the idle timeout, a background refresh is sent to the login page.
	if _, err := e.pool.Exec(ctx, `UPDATE sessions SET last_seen_at=now() - interval '31 minutes'`); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", e.srv.URL+"/tenants/"+tenantID+"/agents", nil)
	for k, v := range bg {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("HX-Redirect") != "/login" {
		t.Fatalf("expired session: want HX-Redirect /login, got %q (%d)", resp.Header.Get("HX-Redirect"), resp.StatusCode)
	}
}

func TestCSRFAndAuditAppendOnly(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	code, _ := e.form("/tenants", url.Values{"name": {"X"}, "csrf_token": {"wrong"}})
	if code != 403 {
		t.Fatalf("bad CSRF: got %d", code)
	}
	ctx := context.Background()
	var denied int
	_ = e.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='access.denied'`).Scan(&denied)
	if denied != 1 {
		t.Fatalf("access.denied entries: %d", denied)
	}
	if _, err := e.pool.Exec(ctx, `UPDATE audit_log SET action='x'`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("update audit_log: %v", err)
	}
	if _, err := e.pool.Exec(ctx, `DELETE FROM audit_log`); err == nil {
		t.Fatal("delete audit_log succeeded")
	}
	if _, err := e.pool.Exec(ctx, `TRUNCATE audit_log`); err == nil {
		t.Fatal("truncate audit_log succeeded")
	}
}

func TestLockout(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	jar, _ := cookiejar.New(nil)
	e.client = &http.Client{Jar: jar}
	// Nine earlier failures; the tenth locks the account.
	if _, err := e.pool.Exec(context.Background(), `UPDATE users SET failed_login_count=9`); err != nil {
		t.Fatal(err)
	}
	e.form("/login", url.Values{"email": {"admin@example.test"}, "password": {"wrong-password-123"}})
	code, body := e.form("/login", url.Values{"email": {"admin@example.test"}, "password": {"correct horse battery staple"}})
	if code != 401 || !strings.Contains(body, "locked") {
		t.Fatalf("expected lockout, got %d", code)
	}

	// After the lock expires, one wrong password must not lock the account
	// again: the count starts over.
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, `UPDATE users SET locked_until=now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	e.form("/login", url.Values{"email": {"admin@example.test"}, "password": {"wrong-password-123"}})
	var count int
	var lockedUntil *time.Time
	if err := e.pool.QueryRow(ctx, `SELECT failed_login_count, locked_until FROM users`).Scan(&count, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	if count != 1 || lockedUntil != nil {
		t.Fatalf("after expired lock: failed_login_count=%d locked_until=%v, want 1 and NULL", count, lockedUntil)
	}
	code, body = e.form("/login", url.Values{"email": {"admin@example.test"}, "password": {"correct horse battery staple"}})
	if code != 200 || !strings.Contains(body, "Tenants") {
		t.Fatalf("login after expired lock: got %d", code)
	}
}

func TestRotationSurvivesLostResponse(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	_, old := e.enrollAgent()
	id := strings.SplitN(strings.TrimPrefix(old, protocol.CredentialPrefix), ".", 2)[0]
	heartbeat := func(cred string) (int, bool) {
		t.Helper()
		code, m := e.agentCall(protocol.PathHeartbeat, hb, cred)
		rotate, _ := m["rotate_credential"].(bool)
		return code, rotate
	}
	rotate := func(cred string) string {
		t.Helper()
		code, m := e.agentCall(protocol.PathRotate, struct{}{}, cred)
		if code != 200 {
			t.Fatalf("rotate: %d %v", code, m)
		}
		return m["credential"].(string)
	}

	if code, _ := e.form("/agents/"+id+"/rotate", url.Values{}); code != 200 {
		t.Fatalf("request rotation: %d", code)
	}
	if code, r := heartbeat(old); code != 200 || !r {
		t.Fatalf("heartbeat after request: %d rotate=%v", code, r)
	}

	// The agent never receives (or fails to save) the first new credential.
	lost := rotate(old)
	if code, r := heartbeat(old); code != 200 || !r {
		t.Fatalf("heartbeat on old credential after lost rotation: %d rotate=%v, want 200 and rotate", code, r)
	}
	// It retries with the credential it still holds; the lost one is dropped.
	got := rotate(old)
	if code, _ := heartbeat(lost); code != 401 {
		t.Fatalf("discarded credential: got %d, want 401", code)
	}
	if code, r := heartbeat(old); code != 200 || !r {
		t.Fatalf("old credential during grace after retry: %d rotate=%v", code, r)
	}

	// First use of the new credential completes the rotation.
	if code, r := heartbeat(got); code != 200 || r {
		t.Fatalf("heartbeat on new credential: %d rotate=%v, want 200 and no rotate", code, r)
	}
	if code, _ := heartbeat(old); code != 401 {
		t.Fatalf("old credential after confirmation: got %d, want 401", code)
	}

	// A rotation requested while another is unconfirmed is not lost.
	next := rotate(got)
	if code, _ := e.form("/agents/"+id+"/rotate", url.Values{}); code != 200 {
		t.Fatalf("request rotation: %d", code)
	}
	if code, r := heartbeat(next); code != 200 || !r {
		t.Fatalf("heartbeat after mid-rotation request: %d rotate=%v, want rotate", code, r)
	}
}

// TestInstallCommandsPinPrivateCA: once a private CA is published in the
// downloads directory, new tokens come with commands that pin it.
func TestInstallCommandsPinPrivateCA(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	_, body := e.form("/tenants", url.Values{"name": {"Acme"}})
	tenantID := regexp.MustCompile(`/tenants/([0-9a-f-]{36})/tokens`).FindStringSubmatch(body)[1]
	newToken := func() string {
		t.Helper()
		_, body := e.form("/tenants/"+tenantID+"/tokens", url.Values{"label": {"t"}, "expires_days": {"1"}})
		return html.UnescapeString(body)
	}

	body = newToken()
	if !strings.Contains(body, "--token-stdin") || strings.Contains(body, "--ca-sha256") || !strings.Contains(body, "Invoke-WebRequest") {
		t.Fatal("public-CA commands missing or pinned")
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Caddy Local Authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err := os.WriteFile(filepath.Join(e.downloads, "console-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.downloads, "install.ps1"), []byte("# install.ps1"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	fp := hex.EncodeToString(sum[:])
	body = newToken()
	for _, want := range []string{"--ca-sha256 " + fp, "-CaSha256 " + fp, `--cacert "$d/ca.pem"`, strings.ToUpper(fp[:2]) + ":"} {
		if !strings.Contains(body, want) {
			t.Errorf("private-CA token page lacks %q", want)
		}
	}

	// A broken CA file yields an explanation, not unpinned commands.
	if err := os.WriteFile(filepath.Join(e.downloads, "console-ca.pem"), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	body = newToken()
	if !strings.Contains(body, "console CA published in the downloads directory is invalid") || (strings.Contains(body, "install.sh") && strings.Contains(body, "sudo sh")) {
		t.Fatal("invalid CA file: expected an error and no install commands")
	}
}
