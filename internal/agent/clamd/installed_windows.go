//go:build windows

package clamd

import (
	"os"
	"path/filepath"
)

// Installed reports whether clamd.exe exists under %ProgramFiles%\ClamAV.
func Installed() bool {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	fi, err := os.Stat(filepath.Join(pf, "ClamAV", "clamd.exe")) //nolint:gosec // %ProgramFiles% from the service environment
	return err == nil && fi.Mode().IsRegular()
}
