package protocol

import (
	"encoding/json"
	"fmt"
)

// ActionType is the closed set of things the server may ask an agent to do.
//
// SECURITY: this is the allowlist required by CLAUDE.md rule 1. Adding a type
// is a security change: it needs a typed params struct with Validate(), a
// handler in internal/agent/actions, and malicious-input tests, all in the
// same change. There is no generic "run command" type and there never will be.
type ActionType string

// Phase 1 ships with no action types enabled. Candidates for Phase 2 are
// listed in docs/design/phase1.md.
var allowedActions = map[ActionType]func() ActionParams{}

// ActionParams is implemented by every typed parameter struct.
type ActionParams interface {
	Validate() error
}

// Action is a unit of work sent in a heartbeat response.
type Action struct {
	ID     string          `json:"id"`
	Type   ActionType      `json:"type"`
	Params json.RawMessage `json:"params"`
}

// ErrUnknownAction is reported back when an agent receives a type it does not
// know. The agent never attempts to interpret it.
type ErrUnknownAction struct{ Type ActionType }

func (e ErrUnknownAction) Error() string {
	return fmt.Sprintf("action type %q is not in the allowlist", e.Type)
}

// IsAllowed reports whether t is a known action type.
func IsAllowed(t ActionType) bool {
	_, ok := allowedActions[t]
	return ok
}

// DecodeParams strictly decodes and validates an action's parameters. Unknown
// types, unknown fields and invalid values are all rejected.
func DecodeParams(a Action) (ActionParams, error) {
	newParams, ok := allowedActions[a.Type]
	if !ok {
		return nil, ErrUnknownAction{Type: a.Type}
	}
	p := newParams()
	dec := json.NewDecoder(bytesReader(a.Params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("decode params for %q: %w", a.Type, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid params for %q: %w", a.Type, err)
	}
	return p, nil
}
