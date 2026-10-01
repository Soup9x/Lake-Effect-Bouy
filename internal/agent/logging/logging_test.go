package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRotatingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "logs", "agent.log")
	r, err := NewRotatingFile(p, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	line := bytes.Repeat([]byte("x"), 39)
	line = append(line, '\n')
	for i := 0; i < 20; i++ {
		if _, err := r.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	_ = r.Close()
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 4 { // agent.log + .1 .2 .3
		t.Fatalf("files: %v", entries)
	}
	for _, e := range entries {
		fi, _ := e.Info()
		if fi.Size() > 100 {
			t.Fatalf("%s is %d bytes", e.Name(), fi.Size())
		}
	}
}
