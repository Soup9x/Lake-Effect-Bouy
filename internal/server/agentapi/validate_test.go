package agentapi

import (
	"strings"
	"testing"
	"time"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
)

func TestValidateHeartbeat(t *testing.T) {
	now := time.Now()
	ok := protocol.HeartbeatRequest{Hostname: "FS01", OSName: "Windows Server 2022", AgentVersion: "0.1.0",
		ClamAV: protocol.ClamAVStatus{Status: protocol.ClamdRunning, EngineVersion: "1.4.1", SignatureVersion: 27410}}
	if err := validateHeartbeat(&ok, now); err != nil {
		t.Fatalf("valid heartbeat rejected: %v", err)
	}
	future := now.Add(72 * time.Hour)
	cases := map[string]func(r *protocol.HeartbeatRequest){
		"empty hostname":     func(r *protocol.HeartbeatRequest) { r.Hostname = "" },
		"shell metachar":     func(r *protocol.HeartbeatRequest) { r.Hostname = "a;b" },
		"control char":       func(r *protocol.HeartbeatRequest) { r.OSName = "x\x00y" },
		"long os":            func(r *protocol.HeartbeatRequest) { r.OSName = strings.Repeat("a", 201) },
		"bad status":         func(r *protocol.HeartbeatRequest) { r.ClamAV.Status = "exploded" },
		"bad engine version": func(r *protocol.HeartbeatRequest) { r.ClamAV.EngineVersion = "1.0 <b>" },
		"negative sigs":      func(r *protocol.HeartbeatRequest) { r.ClamAV.SignatureVersion = -1 },
		"future sig date":    func(r *protocol.HeartbeatRequest) { r.ClamAV.SignatureDate = &future },
		"bad agent version":  func(r *protocol.HeartbeatRequest) { r.AgentVersion = "" },
	}
	for name, mut := range cases {
		r := ok
		mut(&r)
		if err := validateHeartbeat(&r, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzValidateEnroll(f *testing.F) {
	f.Add("cav_enr_abc", "m1", "host", "linux", "amd64", "0.1.0")
	f.Fuzz(func(t *testing.T, tok, mid, host, fam, arch, ver string) {
		r := protocol.EnrollRequest{EnrollmentToken: tok, MachineID: mid, Hostname: host, OSFamily: fam, Arch: arch, AgentVersion: ver}
		if validateEnroll(&r) == nil {
			if strings.ContainsAny(host, ";|&$`<>") || (fam != "linux" && fam != "windows") {
				t.Fatalf("accepted invalid input %+v", r)
			}
		}
	})
}
