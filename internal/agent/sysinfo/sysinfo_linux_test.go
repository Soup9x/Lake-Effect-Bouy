//go:build linux

package sysinfo

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	in := "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n# comment\nID=ubuntu\n"
	name, ver := parseOSRelease(bufio.NewScanner(strings.NewReader(in)))
	if name != "Ubuntu 24.04.1 LTS" || ver != "24.04" {
		t.Fatalf("%q %q", name, ver)
	}
}
