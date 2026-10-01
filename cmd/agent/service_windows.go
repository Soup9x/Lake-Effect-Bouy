//go:build windows

package main

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"
)

// serviceName must match the name used by packaging/windows/install.ps1.
const serviceName = "ClamAVAgent"

func isWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// runService runs the agent under the service control manager.
func runService(run func(ctx context.Context) int) int {
	h := &serviceHandler{run: run}
	if err := svc.Run(serviceName, h); err != nil {
		fmt.Fprintln(os.Stderr, "service:", err)
		return exitError
	}
	return h.code
}

type serviceHandler struct {
	run  func(ctx context.Context) int
	code int
}

// Execute implements svc.Handler. When the agent exits on its own (revoked
// or misconfigured) the service stops with a service-specific exit code
// (78). The installer's recovery actions only apply to crashes, so the SCM
// does not restart a revoked agent.
func (h *serviceHandler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				h.code = <-done
				return false, 0
			}
		case code := <-done:
			h.code = code
			status <- svc.Status{State: svc.StopPending}
			if code != exitOK {
				return true, uint32(code) //nolint:gosec // exit codes are small positive constants
			}
			return false, 0
		}
	}
}
