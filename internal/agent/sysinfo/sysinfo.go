// Package sysinfo collects the host facts reported at enrollment and in
// heartbeats.
package sysinfo

import (
	"os"
	"runtime"
	"strings"
	"unicode"
)

// Info describes the host.
type Info struct {
	Hostname  string
	OSFamily  string // "linux" or "windows"
	OSName    string
	OSVersion string
	Arch      string
	MachineID string
}

// maxField caps every reported string.
const maxField = 255

// Collect gathers host facts. Fields that cannot be determined are left
// empty rather than failing, so a heartbeat is always sent.
func Collect() Info {
	h, _ := os.Hostname()
	name, version := osNameVersion()
	return Info{
		Hostname:  Clean(h),
		OSFamily:  runtime.GOOS,
		OSName:    Clean(name),
		OSVersion: Clean(version),
		Arch:      runtime.GOARCH,
		MachineID: Clean(machineID()),
	}
}

// Clean trims, strips non-printable characters and caps the length so the
// server's printable-charset validators accept the value.
func Clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > maxField {
		// Cut on a rune boundary.
		cut := 0
		for i := range s {
			if i > maxField {
				break
			}
			cut = i
		}
		s = s[:cut]
	}
	return s
}
