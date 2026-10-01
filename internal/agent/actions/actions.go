// Package actions dispatches server-requested actions through a static
// allowlist.
//
// SECURITY (CLAUDE.md rule 1): handlers are looked up in a map that is fixed
// at compile time and keyed by protocol.ActionType. Parameters are strictly
// decoded and validated by protocol.DecodeParams before any handler runs.
// There is no generic command execution here, and process execution is banned in
// internal/agent (enforced by a test). Phase 1 ships with zero handlers, so
// every action is rejected.
package actions

import (
	"context"
	"log/slog"

	"github.com/Soup9x/Lake-Effect-Bouy/internal/agent/sysinfo"
	"github.com/Soup9x/Lake-Effect-Bouy/internal/protocol"
)

// Handler runs one validated action.
type Handler func(ctx context.Context, params protocol.ActionParams) error

// handlers is the agent-side allowlist. It must only contain types that
// protocol.IsAllowed accepts. Empty in Phase 1.
var handlers = map[protocol.ActionType]Handler{}

// Outcome values.
const (
	OutcomeDone     = "done"
	OutcomeFailed   = "failed"
	OutcomeRejected = "rejected_unknown_action"
	OutcomeInvalid  = "rejected_invalid_params"
)

// Result is what happened to one action. Phase 1 only logs it; the protocol
// has no field to report results yet.
type Result struct {
	ID      string
	Type    string
	Outcome string
	Error   string
}

// Dispatcher runs actions.
type Dispatcher struct {
	Logger *slog.Logger
}

// Dispatch validates and runs a single action. It never panics on malformed
// input and never interprets an unknown type.
func (d *Dispatcher) Dispatch(ctx context.Context, a protocol.Action) Result {
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	// Server-supplied strings are sanitized before logging.
	res := Result{ID: sysinfo.Clean(a.ID), Type: sysinfo.Clean(string(a.Type))}
	params, err := protocol.DecodeParams(a)
	if err != nil {
		res.Outcome = OutcomeInvalid
		if !protocol.IsAllowed(a.Type) {
			res.Outcome = OutcomeRejected
		}
		res.Error = sysinfo.Clean(err.Error())
		logger.Warn("action rejected", "action_id", res.ID, "action_type", res.Type, "outcome", res.Outcome, "error", res.Error)
		return res
	}
	h, ok := handlers[a.Type]
	if !ok {
		// Allowed by the protocol but this agent build has no handler.
		res.Outcome = OutcomeRejected
		res.Error = "no handler for action type in this agent version"
		logger.Warn("action rejected", "action_id", res.ID, "action_type", res.Type, "outcome", res.Outcome)
		return res
	}
	if err := h(ctx, params); err != nil {
		res.Outcome = OutcomeFailed
		res.Error = sysinfo.Clean(err.Error())
		logger.Error("action failed", "action_id", res.ID, "action_type", res.Type, "error", res.Error)
		return res
	}
	res.Outcome = OutcomeDone
	logger.Info("action done", "action_id", res.ID, "action_type", res.Type)
	return res
}
