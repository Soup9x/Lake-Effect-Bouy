package clamd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Soup9x/Lake-Effect-Bouy/internal/protocol"
)

// DefaultTimeout bounds every clamd exchange (dial + command + reply).
const DefaultTimeout = 5 * time.Second

// maxReply caps how much of a clamd reply is read.
const maxReply = 1024

// MaxErrorLen caps ClamAVStatus.Error.
const MaxErrorLen = 200

// Client talks to one clamd endpoint.
type Client struct {
	Addr    Address
	Timeout time.Duration
	// Installed reports whether ClamAV appears to be installed; used to tell
	// not_installed from not_responding. Defaults to an OS-specific check.
	Installed func() bool
}

// New returns a client for a validated address.
func New(addr Address) *Client {
	return &Client{Addr: addr, Timeout: DefaultTimeout, Installed: Installed}
}

func (c *Client) timeout() time.Duration {
	if c.Timeout <= 0 {
		return DefaultTimeout
	}
	return c.Timeout
}

// command sends one fixed z-command and returns the NUL-terminated reply.
// cmd is always a constant from this package.
func (c *Client) command(ctx context.Context, cmd string) (string, error) {
	// Re-validate at dial time; Address may have been built by hand.
	if c.Addr.Network == "tcp" {
		if _, err := ParseAddress(c.Addr.String()); err != nil {
			return "", err
		}
	} else if c.Addr.Network != "unix" {
		return "", fmt.Errorf("clamd: unsupported network %q", c.Addr.Network)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	d := net.Dialer{
		// Check the actual resolved address, so "localhost" cannot be
		// redirected off-host via a tampered hosts file.
		Control: func(network, address string, _ syscall.RawConn) error {
			return checkLoopbackDial(network, address)
		},
	}
	conn, err := d.DialContext(ctx, c.Addr.Network, c.Addr.Addr)
	if err != nil {
		return "", &DialError{Err: err}
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write([]byte("z" + cmd + "\x00")); err != nil {
		return "", fmt.Errorf("clamd: write %s: %w", cmd, err)
	}
	r := bufio.NewReader(io.LimitReader(conn, maxReply))
	reply, err := r.ReadBytes(0)
	if err != nil && (!errors.Is(err, io.EOF) || len(reply) == 0) {
		return "", fmt.Errorf("clamd: read %s reply: %w", cmd, err)
	}
	return string(bytes.TrimRight(reply, "\x00\r\n ")), nil
}

// DialError wraps a failure to connect to clamd.
type DialError struct{ Err error }

func (e *DialError) Error() string { return "clamd: connect: " + e.Err.Error() }
func (e *DialError) Unwrap() error { return e.Err }

// Ping sends PING and expects PONG.
func (c *Client) Ping(ctx context.Context) error {
	reply, err := c.command(ctx, "PING")
	if err != nil {
		return err
	}
	if reply != "PONG" {
		return fmt.Errorf("clamd: unexpected PING reply %q", truncate(reply, 40))
	}
	return nil
}

// Version sends VERSION and parses the reply.
func (c *Client) Version(ctx context.Context) (VersionInfo, error) {
	reply, err := c.command(ctx, "VERSION")
	if err != nil {
		return VersionInfo{}, err
	}
	return ParseVersion(reply)
}

// Status queries clamd once and maps the outcome onto the protocol status.
func (c *Client) Status(ctx context.Context) protocol.ClamAVStatus {
	if err := c.Ping(ctx); err != nil {
		var de *DialError
		if errors.As(err, &de) && c.Installed != nil && !c.Installed() {
			return protocol.ClamAVStatus{Status: protocol.ClamdNotInstalled, Error: capError(err)}
		}
		if errors.Is(err, os.ErrPermission) {
			err = fmt.Errorf("%w (is the agent user in the clamd socket's group?)", err)
		}
		return protocol.ClamAVStatus{Status: protocol.ClamdNotResponding, Error: capError(err)}
	}
	st := protocol.ClamAVStatus{Status: protocol.ClamdRunning}
	v, err := c.Version(ctx)
	if v.Engine != "" {
		st.EngineVersion = v.Engine
		st.SignatureVersion = v.SignatureVersion
		st.SignatureDate = v.SignatureDate
	}
	if err != nil {
		st.Error = capError(err)
	}
	return st
}

func capError(err error) string { return truncate(err.Error(), MaxErrorLen) }

func truncate(s string, n int) string {
	// Keep it valid UTF-8, printable, and at most n bytes (so also at most
	// n characters) for the server's validators.
	var b []byte
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			r = '?'
		}
		if len(b)+utf8.RuneLen(r) > n {
			break
		}
		b = utf8.AppendRune(b, r)
	}
	return string(b)
}
