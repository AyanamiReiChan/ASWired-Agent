package control

import (
	"context"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIdentityRotationPersistsBeforeSameWebSocketUsesNewToken(t *testing.T) {
	private, public, e := wire.GenerateKey()
	if e != nil {
		t.Fatal(e)
	}
	oldToken, newToken := strings.Repeat("o", 40), strings.Repeat("n", 40)
	oldAgent, newAgent := strings.Repeat("a", 40), strings.Repeat("b", 40)
	received := make(chan wire.Report, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, e := websocket.Accept(w, r, nil)
		if e != nil {
			t.Error(e)
			return
		}
		defer conn.CloseNow()
		var hello wire.Hello
		if e = wsjson.Read(r.Context(), conn, &hello); e != nil {
			t.Error(e)
			return
		}
		ch, e := wire.NewServer(private, hello.PublicKey)
		if e != nil {
			t.Error(e)
			return
		}
		var report wire.Report
		if e = ch.Open(hello.Packet, &report); e != nil || report.Token != oldToken {
			t.Error("initial identity incorrect")
			return
		}
		packet, _ := ch.Seal(wire.Reply{Interval: 1, Commands: []wire.Command{{ID: "rotate", Action: "identity.rotate", Params: map[string]any{"token": newToken, "agent_token": newAgent}}}})
		if e = wsjson.Write(r.Context(), conn, packet); e != nil {
			t.Error(e)
			return
		}
		if e = wsjson.Read(r.Context(), conn, &packet); e != nil {
			t.Error(e)
			return
		}
		if e = ch.Open(packet, &report); e != nil {
			t.Error(e)
			return
		}
		received <- report
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "agent.json")
	raw, _ := json.Marshal(map[string]any{"server_id": "home", "role": "speedtest", "master_url": server.URL, "master_public_key": public, "token": oldToken, "agent_token": oldAgent, "mihomo_binary": "preserve-local", "custom_local": true})
	os.WriteFile(path, raw, 0600)
	cfg, e := config.Load(path)
	if e != nil {
		t.Fatal(e)
	}
	run := &runner{}
	client := New(cfg, run, "test")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = client.webSocket(ctx)
	select {
	case report := <-received:
		if report.Token != newToken || report.Mode != "speedtest" || len(report.Results) != 1 || report.Results[0].Status != "success" {
			t.Fatalf("rotation report incorrect: %+v", report)
		}
	case <-ctx.Done():
		t.Fatal("new identity not used on existing WebSocket")
	}
	updated, e := config.Load(path)
	if e != nil || updated.Token != newToken || updated.AgentToken != newAgent || updated.PreviousAgentToken != oldAgent {
		t.Fatal("rotation did not persist identity")
	}
	var saved map[string]any
	raw, _ = os.ReadFile(path)
	json.Unmarshal(raw, &saved)
	if saved["custom_local"] != true || saved["mihomo_binary"] != "preserve-local" {
		t.Fatal("rotation discarded Home/local fields")
	}
	if run.calls != 0 {
		t.Fatal("identity rotation reached the restricted task runner")
	}
	client.cfg.ConfigPath = t.TempDir()
	result := client.execute(context.Background(), wire.Command{ID: "failed-save", Action: "identity.rotate", Params: map[string]any{"token": strings.Repeat("x", 40), "agent_token": strings.Repeat("y", 40)}})
	if result.Status != "failed" || client.cfg.Token != newToken {
		t.Fatal("failed persistence changed running identity")
	}
}
