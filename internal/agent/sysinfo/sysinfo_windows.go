//go:build windows

package sysinfo

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func machineID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return v
}

// osNameVersion returns e.g. "Windows Server 2022 Standard", "10.0.20348".
func osNameVersion() (name, version string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "Windows", ""
	}
	defer func() { _ = k.Close() }()
	name, _, _ = k.GetStringValue("ProductName")
	build, _, _ := k.GetStringValue("CurrentBuild")
	major, _, errMaj := k.GetIntegerValue("CurrentMajorVersionNumber")
	minor, _, errMin := k.GetIntegerValue("CurrentMinorVersionNumber")
	if errMaj == nil && errMin == nil && build != "" {
		version = fmt.Sprintf("%d.%d.%s", major, minor, build)
	} else {
		cv, _, _ := k.GetStringValue("CurrentVersion")
		version = strings.Trim(cv+"."+build, ".")
	}
	return fixWindows11(name, build), version
}

// fixWindows11 corrects ProductName, which still says "Windows 10" on
// Windows 11 (build 22000 and later) client editions.
func fixWindows11(name, build string) string {
	var b int
	if _, err := fmt.Sscanf(build, "%d", &b); err == nil && b >= 22000 && strings.HasPrefix(name, "Windows 10") {
		return "Windows 11" + strings.TrimPrefix(name, "Windows 10")
	}
	if name == "" {
		return "Windows"
	}
	return name
}
