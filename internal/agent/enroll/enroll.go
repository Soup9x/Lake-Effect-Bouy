// Package enroll registers this machine with the console using a one-time
// enrollment token and writes the agent config and credential.
package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/config"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/credstore"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/sysinfo"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
)

const maxTokenLen = 256

// ErrAlreadyEnrolled means a credential already exists locally.
var ErrAlreadyEnrolled = errors.New("this machine already has an agent credential; rerun with --replace to re-enroll")

// Options for Run.
type Options struct {
	Config         config.Config // ServerURL, Clamd, CACertPin, InsecureHTTPForTesting are used
	ConfigPath     string
	CredentialPath string
	Token          string
	Version        string
	Replace        bool
	HTTP           *http.Client
	Info           sysinfo.Info
}

// ValidateToken checks the enrollment token's shape without echoing it.
func ValidateToken(tok string) error {
	if !strings.HasPrefix(tok, protocol.EnrollTokenPrefix) || len(tok) <= len(protocol.EnrollTokenPrefix) {
		return fmt.Errorf("enrollment token must start with %q", protocol.EnrollTokenPrefix)
	}
	if len(tok) > maxTokenLen {
		return errors.New("enrollment token is too long")
	}
	for i := 0; i < len(tok); i++ {
		if c := tok[i]; c <= 0x20 || c >= 0x7f {
			return errors.New("enrollment token contains invalid characters")
		}
	}
	return nil
}

// Run enrolls and, on success, writes the config then the credential.
func Run(ctx context.Context, o Options) (*protocol.EnrollResponse, error) {
	if err := ValidateToken(o.Token); err != nil {
		return nil, err
	}
	cfg := o.Config
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	store := credstore.Store{Path: o.CredentialPath}
	if store.Exists() && !o.Replace {
		return nil, ErrAlreadyEnrolled
	}

	reqBody := protocol.EnrollRequest{
		EnrollmentToken: o.Token,
		MachineID:       o.Info.MachineID,
		Hostname:        o.Info.Hostname,
		OSFamily:        o.Info.OSFamily,
		OSName:          o.Info.OSName,
		OSVersion:       o.Info.OSVersion,
		Arch:            o.Info.Arch,
		AgentVersion:    o.Version,
		Replace:         o.Replace,
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.ServerURL+protocol.PathEnroll, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "clamav-agent/"+o.Version)
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read enroll response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, statusError(resp.StatusCode, data)
	}
	var er protocol.EnrollResponse
	if err := json.Unmarshal(data, &er); err != nil {
		return nil, fmt.Errorf("decode enroll response: %w", err)
	}
	if err := credstore.Validate(er.Credential); err != nil {
		return nil, fmt.Errorf("server returned an invalid credential: %w", err)
	}
	er.AgentID = sysinfo.Clean(er.AgentID)
	er.TenantName = sysinfo.Clean(er.TenantName)
	if er.AgentID == "" {
		return nil, errors.New("server returned no agent_id")
	}

	if err := config.Save(o.ConfigPath, &cfg); err != nil {
		return nil, err
	}
	if err := store.Save(er.Credential); err != nil {
		return nil, err
	}
	return &er, nil
}

func statusError(code int, body []byte) error {
	var e protocol.ErrorResponse
	_ = json.Unmarshal(body, &e)
	switch {
	case code == http.StatusUnauthorized && e.Error.Code == protocol.ErrInvalidToken:
		return errors.New("enrollment token rejected: it is unknown, expired, revoked or used up")
	case code == http.StatusConflict && e.Error.Code == protocol.ErrAlreadyEnrolled:
		return errors.New("the console already has an active agent for this machine in this tenant; rerun with --replace to replace it")
	case code == http.StatusTooManyRequests:
		return errors.New("rate limited by the console; wait a minute and retry")
	}
	return fmt.Errorf("enrollment failed: HTTP %d code=%q message=%q", code, sysinfo.Clean(e.Error.Code), sysinfo.Clean(e.Error.Message))
}
