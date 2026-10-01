//go:build !windows

package config

// Default locations on Linux.
const (
	DefaultConfigPath     = "/etc/clamav-agent/agent.yaml"
	DefaultCredentialPath = "/var/lib/clamav-agent/credential" //nolint:gosec // a path, not a secret
	DefaultClamdAddress   = "unix:///run/clamav/clamd.ctl"
)

// ConfigPath returns the default config file path.
func ConfigPath() string { return DefaultConfigPath }

// CredentialPath returns the default credential file path.
func CredentialPath() string { return DefaultCredentialPath }

// LogDir returns the directory for agent log files, or "" when logs go to
// stderr only (systemd's journal captures them on Linux).
func LogDir() string { return "" }
