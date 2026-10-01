//go:build !linux && !windows

package sysinfo

import "runtime"

// Other platforms are only supported for development builds.
func machineID() string                     { return "" }
func osNameVersion() (name, version string) { return runtime.GOOS, "" }
