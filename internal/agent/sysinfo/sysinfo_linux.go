//go:build linux

package sysinfo

import (
	"bufio"
	"os"
	"strings"
)

func machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil { //nolint:gosec // fixed system paths
			if id := strings.TrimSpace(string(b)); id != "" {
				return id
			}
		}
	}
	return ""
}

// osNameVersion reads PRETTY_NAME and VERSION_ID from os-release.
func osNameVersion() (name, version string) {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		f, err := os.Open(p) //nolint:gosec // fixed system paths
		if err != nil {
			continue
		}
		name, version = parseOSRelease(bufio.NewScanner(f))
		_ = f.Close()
		if name != "" {
			return name, version
		}
	}
	return "Linux", ""
}

func parseOSRelease(sc *bufio.Scanner) (name, version string) {
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.TrimSpace(k) {
		case "PRETTY_NAME":
			name = v
		case "VERSION_ID":
			version = v
		}
	}
	return name, version
}
