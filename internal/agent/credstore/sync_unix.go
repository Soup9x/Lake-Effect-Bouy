//go:build !windows

package credstore

import "os"

// syncDir makes the rename durable. Errors are ignored: the data is already
// written and renamed; this only narrows the power-loss window.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil { //nolint:gosec // our own state directory
		_ = d.Sync()
		_ = d.Close()
	}
}
