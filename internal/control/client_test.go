package control

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"testing"
)

type runner struct{ calls int }

func (r *runner) Handle(_ context.Context, c wire.Command) wire.Result {
	r.calls++
	return wire.Result{ID: c.ID, Status: "success", Data: map[string]any{"executed": true}}
}
func (r *runner) Snapshot() map[string]any {
	return map[string]any{"core": map[string]any{"running": true}}
}
func (r *runner) Capabilities() map[string]bool { return map[string]bool{"core_config": true} }
func TestDuplicateCommandExecutesOnce(t *testing.T) {
	r := &runner{}
	client := New(config.Config{ConnectionMode: "websocket"}, r, "test")
	for i := 0; i < 2; i++ {
		reply := wire.Reply{Commands: []wire.Command{{ID: "same", Action: "core.status"}}}
		if err := client.accept(context.Background(), reply); err != nil {
			t.Fatal(err)
		}
	}
	if r.calls != 1 {
		t.Fatal("duplicate command executed twice")
	}
}
func TestConnectionModesValidation(t *testing.T) {
	for _, mode := range []string{"websocket", "pull", "http", "auto"} {
		cfg := config.Config{ConnectionMode: mode, ListenAddress: "127.0.0.1:23889", XrayMode: "embedded", DataDir: t.TempDir(), ObservationInterval: 5}
		if err := cfg.Validate(true); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	cfg := config.Config{ConnectionMode: "invalid", XrayMode: "embedded", DataDir: t.TempDir(), ObservationInterval: 5}
	if cfg.Validate(true) == nil {
		t.Fatal("invalid mode accepted")
	}
	if New(cfg, &runner{}, "test").Run(context.Background()) == nil {
		t.Fatal("invalid runtime mode accepted")
	}
}
