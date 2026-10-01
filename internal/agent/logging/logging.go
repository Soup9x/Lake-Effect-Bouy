// Package logging sets up the agent's slog logger: text to stderr (captured
// by the systemd journal), plus a size-rotated file on Windows.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ParseLevel maps a config log_level to a slog level.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// New returns a logger writing to stderr and, when logDir is non-empty, to
// logDir/agent.log as well. The returned closer flushes and closes the file.
// A log file that cannot be opened is reported on stderr and skipped.
func New(level slog.Leveler, logDir string) (*slog.Logger, io.Closer) {
	var w io.Writer = os.Stderr
	var closer io.Closer = nopCloser{}
	if logDir != "" {
		rf, err := NewRotatingFile(filepath.Join(logDir, "agent.log"), 5<<20, 3)
		if err != nil {
			fmt.Fprintf(os.Stderr, "clamav-agent: cannot open log file: %v\n", err)
		} else {
			w = io.MultiWriter(os.Stderr, rf)
			closer = rf
		}
	}
	h := slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(h), closer
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// RotatingFile is an io.Writer that rotates path -> path.1 -> ... -> path.N
// when the file would exceed maxBytes.
type RotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	f        *os.File
	size     int64
}

// NewRotatingFile opens (appending to) path, creating its directory.
func NewRotatingFile(path string, maxBytes int64, keep int) (*RotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	r := &RotatingFile{path: path, maxBytes: maxBytes, keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640) //nolint:gosec // logs readable by admins' group
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r.f, r.size = f, fi.Size()
	return nil
}

func (r *RotatingFile) rotate() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	for i := r.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	if r.keep >= 1 {
		_ = os.Rename(r.path, r.path+".1")
	} else {
		_ = os.Remove(r.path)
	}
	return r.open()
}

// Write implements io.Writer.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, os.ErrClosed
	}
	if r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// Close closes the current file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
