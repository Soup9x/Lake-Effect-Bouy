package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/config"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/credstore"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/sysinfo"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
)

func setup(t *testing.T, handler http.HandlerFunc) (Options, *httptest.Server) {
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	return Options{
		Config:         config.Config{ServerURL: srv.URL, Clamd: config.ClamdConfig{Address: "tcp://127.0.0.1:3310"}},
		ConfigPath:     filepath.Join(dir, "etc", "agent.yaml"),
		CredentialPath: filepath.Join(dir, "lib", "credential"),
		Token:          "cav_enr_ABCDEF",
		Version:        "0.1.0",
		HTTP:           srv.Client(),
		Info:           sysinfo.Info{Hostname: "h", OSFamily: "linux", MachineID: "m", Arch: "amd64"},
	}, srv
}

func TestEnrollSuccessAndReplace(t *testing.T) {
	var got protocol.EnrollRequest
	o, _ := setup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != protocol.PathEnroll || r.Header.Get("Authorization") != "" {
			t.Errorf("path %s auth %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&got); err != nil {
			t.Error(err)
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{AgentID: "a1", Credential: "cav_agt_a1.s", TenantName: "Acme\nDental", HeartbeatIntervalSeconds: 60})
	})
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.TenantName != "AcmeDental" || got.EnrollmentToken != "cav_enr_ABCDEF" || got.Hostname != "h" || got.Replace {
		t.Fatalf("res %+v req %+v", res, got)
	}
	if c, _ := (credstore.Store{Path: o.CredentialPath}).Load(); c != "cav_agt_a1.s" {
		t.Fatal(c)
	}
	if c, err := config.Load(o.ConfigPath); err != nil || c.ServerURL != o.Config.ServerURL {
		t.Fatal(c, err)
	}
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("second enroll: %v", err)
	}
	o.Replace = true
	if _, err := Run(context.Background(), o); err != nil || !got.Replace {
		t.Fatalf("replace: %v %v", err, got.Replace)
	}
}

func TestEnrollErrors(t *testing.T) {
	cases := []struct {
		code int
		body string
		want string
	}{
		{401, `{"error":{"code":"invalid_token"}}`, "token rejected"},
		{409, `{"error":{"code":"already_enrolled"}}`, "--replace"},
		{500, `oops`, "HTTP 500"},
		{201, `{"agent_id":"a","credential":"bad"}`, "invalid credential"},
	}
	for _, c := range cases {
		o, _ := setup(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.code)
			_, _ = w.Write([]byte(c.body))
		})
		_, err := Run(context.Background(), o)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%d: %v", c.code, err)
		}
		if (credstore.Store{Path: o.CredentialPath}).Exists() {
			t.Errorf("%d: credential written on failure", c.code)
		}
	}
}

func TestEnrollRejectsBadInput(t *testing.T) {
	o, _ := setup(t, func(w http.ResponseWriter, _ *http.Request) { t.Error("request sent") })
	for _, tok := range []string{"", "abc", "cav_enr_", "cav_enr_a b", "cav_agt_x", "cav_enr_" + strings.Repeat("a", 300)} {
		o.Token = tok
		if _, err := Run(context.Background(), o); err == nil {
			t.Errorf("token %q accepted", tok)
		}
	}
	o.Token = "cav_enr_ok"
	o.Config.ServerURL = "http://plain.example"
	if _, err := Run(context.Background(), o); err == nil {
		t.Error("http accepted")
	}
	o.Config.ServerURL = "https://x.example"
	o.Config.Clamd.Address = "tcp://8.8.8.8:3310"
	if _, err := Run(context.Background(), o); err == nil {
		t.Error("remote clamd accepted")
	}
}
