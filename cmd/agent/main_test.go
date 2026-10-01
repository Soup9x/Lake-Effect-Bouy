package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
)

// TestEnrollThenRunUntilRevoked drives the real subcommands against an
// httptest server speaking the protocol types.
func TestEnrollThenRunUntilRevoked(t *testing.T) {
	var beats atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.PathEnroll, func(w http.ResponseWriter, r *http.Request) {
		var req protocol.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.EnrollmentToken != "cav_enr_TESTTOKEN" {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(protocol.ErrorResponse{Error: protocol.ErrorBody{Code: protocol.ErrInvalidToken}})
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{AgentID: "a1", Credential: "cav_agt_a1.secret", TenantName: "Acme"})
	})
	mux.HandleFunc("POST "+protocol.PathHeartbeat, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cav_agt_a1.secret" {
			t.Errorf("auth %q", r.Header.Get("Authorization"))
		}
		var hb protocol.HeartbeatRequest
		_ = json.NewDecoder(r.Body).Decode(&hb)
		if hb.ClamAV.Status == "" || hb.Hostname == "" {
			t.Errorf("heartbeat %+v", hb)
		}
		beats.Add(1)
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(protocol.ErrorResponse{Error: protocol.ErrorBody{Code: protocol.ErrAgentRevoked}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	cred := filepath.Join(dir, "credential")
	t.Setenv("CAV_ENROLL_TOKEN", "cav_enr_TESTTOKEN")
	code := realMain([]string{"enroll", "--server", srv.URL, "--config", cfg, "--credential", cred,
		"--clamd", "tcp://127.0.0.1:1", "--insecure-http-for-testing"})
	if code != exitOK {
		t.Fatalf("enroll exit %d", code)
	}
	if os.Getenv("CAV_ENROLL_TOKEN") != "" {
		t.Fatal("token left in environment")
	}
	b, _ := os.ReadFile(cfg)
	if strings.Contains(string(b), "cav_") {
		t.Fatal("secret in config file")
	}
	// Second enroll without --replace must refuse before reading a token.
	if code := realMain([]string{"enroll", "--server", srv.URL, "--config", cfg, "--credential", cred, "--insecure-http-for-testing"}); code == exitOK {
		t.Fatal("re-enroll without --replace succeeded")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if code := runAgent(ctx, cfg, cred); code != exitConfig {
		t.Fatalf("run exit %d, want %d", code, exitConfig)
	}
	if beats.Load() != 1 {
		t.Fatalf("beats %d", beats.Load())
	}
}

func TestRunWithoutCredentialExits78(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	_ = os.WriteFile(cfg, []byte("server_url: https://console.example\nclamd:\n  address: tcp://127.0.0.1:3310\n"), 0o644)
	if code := runAgent(context.Background(), cfg, filepath.Join(dir, "missing")); code != exitConfig {
		t.Fatalf("exit %d", code)
	}
	if code := runAgent(context.Background(), filepath.Join(dir, "nope.yaml"), filepath.Join(dir, "missing")); code != exitConfig {
		t.Fatalf("exit %d", code)
	}
}

func TestUsage(t *testing.T) {
	if realMain(nil) != exitUsage || realMain([]string{"bogus"}) != exitUsage || realMain([]string{"verify", "x"}) != exitUsage {
		t.Fatal("usage exits")
	}
	if realMain([]string{"enroll"}) != exitUsage {
		t.Fatal("enroll without --server")
	}
}
