//go:build windows

package config

import (
	"os"
	"path/filepath"
)

// DefaultClamdAddress is the clamd TCP listener ClamAV for Windows uses.
const DefaultClamdAddress = "tcp://127.0.0.1:3310"

// DataDir is %ProgramData%\ClamAVAgent. The install script restricts its ACL.
func DataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "ClamAVAgent")
}

// ConfigPath returns the default config file path.
func ConfigPath() string { return filepath.Join(DataDir(), "agent.yaml") }

// CredentialPath returns the default credential file path.
func CredentialPath() string { return filepath.Join(DataDir(), "credential") }

// LogDir returns the directory for agent.log.
func LogDir() string { return filepath.Join(DataDir(), "logs") }
