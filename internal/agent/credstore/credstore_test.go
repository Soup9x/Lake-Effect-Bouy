package credstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	s := Store{Path: filepath.Join(dir, "state", "credential")}
	if _, err := s.Load(); !errors.Is(err, ErrNotFound) || s.Exists() {
		t.Fatalf("empty store: %v", err)
	}
	if err := s.Save("cav_agt_abc.def"); err != nil {
		t.Fatal(err)
	}
	if err := s.Save("cav_agt_new.secret"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil || got != "cav_agt_new.secret" {
		t.Fatalf("%q %v", got, err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(s.Path)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", fi.Mode())
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(s.Path))
	if len(entries) != 1 {
		t.Fatalf("temp files left: %v", entries)
	}
}

func TestValidate(t *testing.T) {
	for _, bad := range []string{"", "cav_agt_", "token", "cav_enr_x", "cav_agt_a b", "cav_agt_\x00", "cav_agt_é"} {
		if Validate(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	s := Store{Path: filepath.Join(t.TempDir(), "c")}
	if err := s.Save("bogus"); err == nil {
		t.Fatal("saved invalid credential")
	}
	_ = os.WriteFile(s.Path, []byte("garbage\n"), 0o600)
	if _, err := s.Load(); err == nil {
		t.Fatal("loaded garbage")
	}
}
