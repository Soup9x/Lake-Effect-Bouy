package agentapi

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
)

var (
	reVersion   = regexp.MustCompile(`^[0-9A-Za-z.+_~-]{1,64}$`)
	reMachineID = regexp.MustCompile(`^[0-9A-Za-z{}_-]{1,128}$`)
	reArch      = regexp.MustCompile(`^[a-z0-9_]{1,16}$`)
)

// printable rejects control characters and caps length.
func printable(field, s string, min, max int) error {
	if n := len(s); n < min || n > max {
		return fmt.Errorf("%s must be %d..%d bytes", field, min, max)
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("%s contains non-printable characters", field)
		}
	}
	return nil
}

func validHostname(s string) error {
	if err := printable("hostname", s, 1, 253); err != nil {
		return err
	}
	if strings.ContainsAny(s, " <>\"'`&;|$\\/") {
		return errors.New("hostname contains invalid characters")
	}
	return nil
}

func validateEnroll(r *protocol.EnrollRequest) error {
	var errs []error
	if !strings.HasPrefix(r.EnrollmentToken, protocol.EnrollTokenPrefix) || len(r.EnrollmentToken) > 128 {
		errs = append(errs, errors.New("enrollment_token is malformed"))
	}
	if !reMachineID.MatchString(r.MachineID) {
		errs = append(errs, errors.New("machine_id is invalid"))
	}
	errs = append(errs, validHostname(r.Hostname))
	if r.OSFamily != "linux" && r.OSFamily != "windows" {
		errs = append(errs, errors.New("os_family must be linux or windows"))
	}
	errs = append(errs, printable("os_name", r.OSName, 0, 200), printable("os_version", r.OSVersion, 0, 100))
	if !reArch.MatchString(r.Arch) {
		errs = append(errs, errors.New("arch is invalid"))
	}
	if !reVersion.MatchString(r.AgentVersion) {
		errs = append(errs, errors.New("agent_version is invalid"))
	}
	return errors.Join(errs...)
}

func validateHeartbeat(r *protocol.HeartbeatRequest, now time.Time) error {
	var errs []error
	errs = append(errs, validHostname(r.Hostname),
		printable("os_name", r.OSName, 0, 200), printable("os_version", r.OSVersion, 0, 100))
	if !reVersion.MatchString(r.AgentVersion) {
		errs = append(errs, errors.New("agent_version is invalid"))
	}
	c := r.ClamAV
	switch c.Status {
	case protocol.ClamdRunning, protocol.ClamdNotResponding, protocol.ClamdNotInstalled, protocol.ClamdUnknown:
	default:
		errs = append(errs, errors.New("clamav.status is invalid"))
	}
	if c.EngineVersion != "" && !reVersion.MatchString(c.EngineVersion) {
		errs = append(errs, errors.New("clamav.engine_version is invalid"))
	}
	if c.SignatureVersion < 0 || c.SignatureVersion > 100_000_000 {
		errs = append(errs, errors.New("clamav.signature_version is out of range"))
	}
	if c.SignatureDate != nil {
		if c.SignatureDate.Year() < 2000 || c.SignatureDate.After(now.Add(48*time.Hour)) {
			errs = append(errs, errors.New("clamav.signature_date is out of range"))
		}
	}
	errs = append(errs, printable("clamav.error", c.Error, 0, 500))
	return errors.Join(errs...)
}
