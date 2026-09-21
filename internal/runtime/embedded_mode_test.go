package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
)

func TestRemovedModeCannotBeActivated(t *testing.T) {
	r := newTestRuntime(t)
	calls := 0
	r.hostExec = func(context.Context, string, ...string) (string, error) { calls++; return "", nil }
	for _, mode := range []string{"embedded", "external"} {
		result := r.Handle(context.Background(), wire.Command{Action: "core.mode.migrate", Params: map[string]any{"mode": mode}})
		if result.Status == "success" || calls != 0 || r.cfg.XrayMode != "embedded" {
			t.Fatalf("removed migration executed: %+v", result)
		}
	}
	c := r.cfg
	c.XrayMode = "external"
	if _, err := New(c); err == nil {
		t.Fatal("external configuration accepted")
	}
	if err := c.Validate(true); err == nil {
		t.Fatal("external configuration passed validation")
	}
	if err := os.WriteFile(filepath.Join(r.cfg.DataDir, "runtime-mode.json"), []byte(`{"mode":"external"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(r.cfg); err == nil {
		t.Fatal("legacy external state silently activated")
	}
}
