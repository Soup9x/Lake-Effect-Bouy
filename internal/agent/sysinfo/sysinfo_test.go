package sysinfo

import (
	"runtime"
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	if got := Clean("  host\x00name\n "); got != "hostname" {
		t.Fatalf("%q", got)
	}
	long := strings.Repeat("é", 300)
	if got := Clean(long); len(got) > maxField || !strings.HasPrefix(long, got) {
		t.Fatalf("len %d", len(got))
	}
}

func TestCollect(t *testing.T) {
	i := Collect()
	if i.OSFamily != runtime.GOOS || i.Arch != runtime.GOARCH || i.Hostname == "" || i.OSName == "" {
		t.Fatalf("%+v", i)
	}
}
