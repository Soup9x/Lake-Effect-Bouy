//go:build windows

package credstore

// syncDir is a no-op on Windows, where directories cannot be fsynced.
func syncDir(string) {}
