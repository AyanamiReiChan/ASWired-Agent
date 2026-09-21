package control

import (
	"context"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/updater"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"os"
	"path/filepath"
	"testing"
)

func TestConnectionSwitchPersistsAndPreservesPendingResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte(`{"connection_mode":"websocket","custom":"keep","token":"keep-token"}`), 0600); err != nil {
		t.Fatal(err)
	}
	c := New(config.Config{ConfigPath: path, ConnectionMode: "websocket", AgentToken: "agent-token"}, &runner{}, "test")
	c.results = []wire.Result{{ID: "first", Status: "success"}, {ID: "second", Status: "success"}}
	c.sentCount = 1
	reply := wire.Reply{ConnectionMode: "http", ListenAddress: "0.0.0.0:24567"}
	if err := c.accept(context.Background(), reply); err != nil {
		t.Fatal(err)
	}
	if mode, _ := c.connectionSettings(); mode != "websocket" {
		t.Fatal("switched before pending results acknowledged")
	}
	c.report()
	if err := c.accept(context.Background(), reply); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err = json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored["connection_mode"] != "http" || stored["listen_address"] != "0.0.0.0:24567" || stored["custom"] != "keep" || stored["token"] != "keep-token" {
		t.Fatalf("bad persistence: %s", raw)
	}
	c.cfg.ConfigPath = filepath.Join(t.TempDir(), "absent", "agent.json")
	if c.accept(context.Background(), wire.Reply{ConnectionMode: "pull"}) == nil {
		t.Fatal("failed persistence accepted")
	}
	if mode, _ := c.connectionSettings(); mode != "http" {
		t.Fatal("failed persistence changed live mode")
	}
}

func TestDirectReportAcknowledgesConfirmedUpdate(t *testing.T) {
	dir := t.TempDir()
	updateDir := filepath.Join(dir, "agent-update")
	if err := os.MkdirAll(updateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(updateDir, "state.json"), []byte(`{"taskId":"upgrade","status":"staged","version":"next"}`), 0600); err != nil {
		t.Fatal(err)
	}
	c := New(config.Config{DataDir: dir}, &runner{}, "old")
	c.execute(context.Background(), wire.Command{ID: "report1", Action: "agent.report"})
	if updater.Snapshot(dir)["status"] != "staged" {
		t.Fatal("unconfirmed update promoted")
	}
	result := c.execute(context.Background(), wire.Command{ID: "report2", Action: "agent.report", Params: map[string]any{"acknowledged_update": "upgrade"}})
	observation := result.Data["observation"].(map[string]any)
	if observation["agent_update"].(map[string]any)["status"] != "ready" {
		t.Fatal("confirmed HTTP update not ready")
	}
}
