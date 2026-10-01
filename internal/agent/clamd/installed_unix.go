//go:build !windows

package clamd

import "os"

// clamdBinaries are the usual install locations of clamd on Linux.
var clamdBinaries = []string{"/usr/sbin/clamd", "/usr/bin/clamd", "/usr/local/sbin/clamd"}

// Installed reports whether a clamd binary exists in a standard location.
func Installed() bool {
	for _, p := range clamdBinaries {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}
