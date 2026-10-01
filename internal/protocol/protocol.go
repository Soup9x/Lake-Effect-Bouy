// Package protocol defines the wire format between the agent and the server.
// Both binaries import it, so a change here is a protocol change: keep it
// backwards compatible or bump APIVersion.
package protocol

import "time"

const (
	APIVersion = "v1"
	// BasePath is the prefix of every agent-facing endpoint.
	BasePath = "/agent/" + APIVersion

	PathEnroll    = BasePath + "/enroll"
	PathHeartbeat = BasePath + "/heartbeat"
	PathRotate    = BasePath + "/credential/rotate"

	DefaultHeartbeatInterval = 60 * time.Second

	// MaxRequestBytes caps every agent request body.
	MaxRequestBytes = 64 << 10

	EnrollTokenPrefix = "cav_enr_" //nolint:gosec // a prefix, not a secret
	CredentialPrefix  = "cav_agt_"
)

// Error codes returned in ErrorResponse.Error.Code.
const (
	ErrInvalidToken    = "invalid_token"
	ErrAlreadyEnrolled = "already_enrolled"
	// ErrAgentRevoked is the ONLY code that makes an agent stop permanently.
	// Any other 401 is treated as transient by the agent.
	ErrAgentRevoked   = "agent_revoked"
	ErrUnauthorized   = "unauthorized"
	ErrInvalidRequest = "invalid_request"
	ErrRateLimited    = "rate_limited"
	ErrInternal       = "internal"
)

type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type EnrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	MachineID       string `json:"machine_id"`
	Hostname        string `json:"hostname"`
	OSFamily        string `json:"os_family"`
	OSName          string `json:"os_name"`
	OSVersion       string `json:"os_version"`
	Arch            string `json:"arch"`
	AgentVersion    string `json:"agent_version"`
	// Replace re-enrolls a machine whose machine_id already has an active
	// agent in the tenant; the old agent is revoked.
	Replace bool `json:"replace,omitempty"`
}

type EnrollResponse struct {
	AgentID                  string `json:"agent_id"`
	Credential               string `json:"credential"`
	TenantName               string `json:"tenant_name"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
}

// Clamd status values.
const (
	ClamdRunning       = "running"
	ClamdNotResponding = "not_responding"
	ClamdNotInstalled  = "not_installed"
	ClamdUnknown       = "unknown"
)

type ClamAVStatus struct {
	Status           string     `json:"status"`
	EngineVersion    string     `json:"engine_version,omitempty"`
	SignatureVersion int        `json:"signature_version,omitempty"`
	SignatureDate    *time.Time `json:"signature_date,omitempty"`
	Error            string     `json:"error,omitempty"`
}

type HeartbeatRequest struct {
	Hostname     string       `json:"hostname"`
	OSName       string       `json:"os_name"`
	OSVersion    string       `json:"os_version"`
	AgentVersion string       `json:"agent_version"`
	ClamAV       ClamAVStatus `json:"clamav"`
	SentAt       time.Time    `json:"sent_at"`
}

type HeartbeatResponse struct {
	HeartbeatIntervalSeconds int       `json:"heartbeat_interval_seconds"`
	ServerTime               time.Time `json:"server_time"`
	// RotateCredential asks the agent to call /credential/rotate.
	RotateCredential bool `json:"rotate_credential,omitempty"`
	// Actions is always empty in Phase 1. See actions.go.
	Actions []Action `json:"actions"`
}

// RotateResponse carries a newly issued credential. The previous credential
// stays valid for a short grace period, until the agent first authenticates
// with the new one.
type RotateResponse struct {
	Credential string `json:"credential"`
}
