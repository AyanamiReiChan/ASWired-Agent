package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type blockedStreamRunner struct {
	release   chan struct{}
	snapshots atomic.Int32
	started   chan struct{}
}

func (r *blockedStreamRunner) Handle(ctx context.Context, c wire.Command) wire.Result {
	close(r.started)
	select {
	case <-r.release:
	case <-ctx.Done():
	}
	return wire.Result{ID: c.ID, Status: "success"}
}
func (r *blockedStreamRunner) Snapshot() map[string]any {
	if r.snapshots.Add(1) > 1 {
		<-r.release
	}
	return map[string]any{"core": map[string]any{"running": true}, "padding": strings.Repeat("counter>>>uplink;", 1000)}
}
func (r *blockedStreamRunner) Capabilities() map[string]bool {
	return map[string]bool{"embedded_core": true}
}

func TestStreamHeartbeatDuringBlockedSamplingAndImmediateResults(t *testing.T) {
	private, public, _ := wire.GenerateKey()
	runner := &blockedStreamRunner{release: make(chan struct{}), started: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(runner.release) }) }
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	finished := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.CloseNow()
		var hello wire.Hello
		if err := wsjson.Read(ctx, conn, &hello); err != nil {
			t.Error(err)
			return
		}
		ch, _ := wire.NewServer(private, hello.PublicKey)
		var report wire.Report
		if err := ch.Open(hello.Packet, &report); err != nil {
			t.Error(err)
			return
		}
		options := wire.NegotiateStream(report.Stream)
		options.TelemetryDelta = false // This fixture exercises the prior binary protocol.
		if !options.Valid() {
			t.Error("no negotiated stream")
			return
		}
		packet, _ := ch.Seal(wire.Reply{Stream: options, Commands: []wire.Command{{ID: "slow", Action: "core.slow"}}})
		if err := wsjson.Write(ctx, conn, packet); err != nil {
			t.Error(err)
			return
		}
		start := time.Now()
		var heartbeatAt time.Time
		gotResult, gotTelemetry := false, false
		for ctx.Err() == nil {
			kind, raw, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var update wire.Update
			if kind != websocket.MessageBinary || ch.OpenBinary(raw, &update, true) != nil || !update.Valid() {
				t.Error("invalid stream frame")
				return
			}
			if update.Token != "" || update.Capabilities != nil {
				t.Error("unchanged session metadata repeated")
				return
			}
			reply := wire.Reply{}
			switch update.Kind {
			case "heartbeat":
				if time.Since(start) < 14*time.Second || time.Since(start) > 20*time.Second {
					t.Error("heartbeat is not on the 15s interval")
				}
				if runner.snapshots.Load() < 2 || !update.Busy || raw[4] != 0 {
					t.Error("heartbeat did not bypass slow sampling/command")
				}
				heartbeatAt = time.Now()
				release()
			case "telemetry":
				if heartbeatAt.IsZero() || raw[4] != 1 {
					t.Error("sampling unexpectedly unblocked or not compressed")
				}
				gotTelemetry = true
			case "results":
				if heartbeatAt.IsZero() || time.Since(heartbeatAt) > 3*time.Second || raw[4] != 0 {
					t.Error("results waited for a periodic report or were compressed")
				}
				if len(update.Results) != 1 || update.Results[0].ID != "slow" {
					t.Error("wrong result")
				}
				gotResult = true
				reply.AckResults = []string{"slow"}
			}
			raw, _ = ch.SealBinary(reply, false)
			if err := conn.Write(ctx, websocket.MessageBinary, raw); err != nil {
				return
			}
			if gotResult && gotTelemetry {
				select {
				case finished <- struct{}{}:
				default:
				}
			}
		}
	}))
	defer server.Close()
	client := New(config.Config{MasterURL: server.URL, MasterPublicKey: public, ServerID: "node", Token: "fixture-token", XrayMode: "embedded", DataDir: t.TempDir()}, runner, "test")
	done := make(chan error, 1)
	go func() { done <- client.webSocket(ctx) }()
	defer func() { cancel(); release(); <-done }()
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("stream did not complete", ctx.Err())
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		client.mu.Lock()
		pending := len(client.results)
		client.mu.Unlock()
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("result ACK not applied")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStreamResultAcknowledgementPreservesUnconfirmedResults(t *testing.T) {
	c := New(config.Config{DataDir: t.TempDir()}, &runner{}, "test")
	c.results = []wire.Result{{ID: "confirmed", Status: "success"}, {ID: "unconfirmed", Status: "success"}}
	c.acknowledgeResults([]string{"confirmed"})
	report := c.report()
	if len(report.Results) != 1 || report.Results[0].ID != "unconfirmed" {
		t.Fatal("reconnect would lose unconfirmed results", report.Results)
	}
}

func TestStreamIdentityRotationIsUncompressedAndLostAckSurvives(t *testing.T) {
	private, public, _ := wire.GenerateKey()
	oldToken, nextToken := strings.Repeat("o", 40), strings.Repeat("n", 40)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	received := make(chan wire.Update, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.CloseNow()
		var hello wire.Hello
		if err := wsjson.Read(ctx, conn, &hello); err != nil {
			t.Error(err)
			return
		}
		ch, _ := wire.NewServer(private, hello.PublicKey)
		var report wire.Report
		if err := ch.Open(hello.Packet, &report); err != nil || report.Token != oldToken {
			t.Error("invalid initial identity", err)
			return
		}
		packet, _ := ch.Seal(wire.Reply{Stream: wire.NegotiateStream(report.Stream), Commands: []wire.Command{{ID: "rotate", Action: "identity.rotate", Params: map[string]any{"token": nextToken, "agent_token": strings.Repeat("b", 40)}}}})
		if err := wsjson.Write(ctx, conn, packet); err != nil {
			t.Error(err)
			return
		}
		kind, raw, err := conn.Read(ctx)
		var update wire.Update
		if err != nil || kind != websocket.MessageBinary || ch.OpenBinary(raw, &update, false) != nil {
			t.Error("rotation was not an uncompressed binary update", err)
			return
		}
		received <- update // Close before ACK to exercise reconnect retention.
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "agent.json")
	raw, _ := json.Marshal(map[string]any{"token": oldToken, "agent_token": strings.Repeat("a", 40)})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	c := New(config.Config{ConfigPath: path, DataDir: t.TempDir(), MasterURL: server.URL, MasterPublicKey: public, ServerID: "node", Token: oldToken, AgentToken: strings.Repeat("a", 40), XrayMode: "embedded"}, &runner{}, "test")
	_ = c.webSocket(ctx)
	select {
	case update := <-received:
		if update.Kind != "results" || update.Token != nextToken || len(update.Results) != 1 || update.Results[0].Status != "success" {
			t.Fatal("rotation update incomplete", update.Kind)
		}
	case <-ctx.Done():
		t.Fatal("rotation result waited for telemetry")
	}
	report := c.report()
	if report.Token != nextToken || len(report.Results) != 1 || report.Results[0].ID != "rotate" {
		t.Fatal("unacknowledged rotation result lost")
	}
}
