package runtime

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/logfiles"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"testing"
)

func TestAgentFileLogsReadClearIsolationAndValidation(t *testing.T) {
	r := newTestRuntime(t)
	r.logs["agent"].Write([]byte("task began\ntask finished\n"))
	r.logs["xray-access"].Write([]byte("connection accepted\n"))
	read := command(t, r, "logs.read", map[string]any{"stream": "agent", "limit": 200})
	if len(read.Data["lines"].([]logfiles.Line)) != 2 {
		t.Fatal(read)
	}
	bad := r.Handle(context.Background(), wire.Command{ID: "bad", Action: "logs.remove", Params: map[string]any{"stream": "agent", "name": "../xray/config.json", "confirm": true}})
	if bad.Status != "failed" {
		t.Fatal("path traversal accepted")
	}
	command(t, r, "logs.remove", map[string]any{"stream": "agent", "all": true, "confirm": true})
	read = command(t, r, "logs.read", map[string]any{"stream": "agent"})
	if len(read.Data["lines"].([]logfiles.Line)) != 0 {
		t.Fatal("clear retained old lines")
	}
	read = command(t, r, "logs.read", map[string]any{"stream": "xray-access"})
	if len(read.Data["lines"].([]logfiles.Line)) != 1 {
		t.Fatal("clear changed other stream")
	}
	r.logs["agent"].Write([]byte("new task\n"))
	read = command(t, r, "logs.read", map[string]any{"stream": "agent"})
	if len(read.Data["lines"].([]logfiles.Line)) != 1 {
		t.Fatal("writing after clear failed")
	}
}
