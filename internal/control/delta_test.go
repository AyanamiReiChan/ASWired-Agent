package control

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type idleDeltaRunner struct{}

func (*idleDeltaRunner) Handle(_ context.Context, c wire.Command) wire.Result {
	return wire.Result{ID: c.ID, Status: "success"}
}
func (*idleDeltaRunner) Capabilities() map[string]bool { return map[string]bool{"embedded_core": true} }
func (*idleDeltaRunner) Snapshot() map[string]any {
	return map[string]any{"core": map[string]any{"running": true, "static": strings.Repeat("unchanged", 500)}, "xray_stats": map[string]any{"generation": 1, "timestamp": time.Now().UnixMilli(), "counters": map[string]int64{"idle": 123456}}}
}

func TestDeltaWaitsForAckAndReconnectStartsFull(t *testing.T) {
	private, public, _ := wire.GenerateKey()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	var sessions atomic.Int32
	completed := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection := sessions.Add(1)
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
		packet, _ := ch.Seal(wire.Reply{Stream: wire.NegotiateStream(report.Stream)})
		if err := wsjson.Write(ctx, conn, packet); err != nil {
			t.Error(err)
			return
		}
		var baseline map[string]any
		var seq uint64
		held := false
		acked := false
		for {
			_, raw, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var update wire.Update
			if err := ch.OpenBinary(raw, &update, true); err != nil {
				t.Error(err)
				return
			}
			reply := wire.Reply{}
			if update.Kind == "telemetry" {
				if held && !acked {
					t.Error("Agent sent another telemetry against an unacknowledged baseline")
					return
				}
				if update.Delta == nil || update.TelemetrySeq != seq+1 {
					t.Error("missing delta sequence")
					return
				}
				if seq == 0 && !update.Delta.Full {
					t.Error("connection did not start with full baseline")
					return
				}
				baseline, err = wire.ApplyObservationDelta(seq, baseline, *update.Delta)
				if err != nil {
					t.Error(err)
					return
				}
				seq++
				if connection == 2 {
					completed <- struct{}{}
					return
				}
				if seq == 1 {
					held = true
					continue
				}
				if update.Delta.Full || strings.Contains(string(raw), "unchanged") || update.Delta.Set["core"] != nil {
					t.Error("static state repeated")
				}
				if baseline["xray_stats"].(map[string]any)["counters"] == nil {
					t.Error("idle counters lost")
				}
				return // Force reconnect after receiving the second sample, before ACK.
			}
			if update.Kind == "heartbeat" && held && !acked {
				reply.TelemetryAck = 1
				acked = true
			}
			raw, _ = ch.SealBinary(wire.CompactReply(reply, "", ""), false)
			if err := conn.Write(ctx, websocket.MessageBinary, raw); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	client := New(config.Config{MasterURL: server.URL, MasterPublicKey: public, ServerID: "node", Token: "fixture-token", XrayMode: "embedded", DataDir: t.TempDir()}, &idleDeltaRunner{}, "test")
	_ = client.webSocket(ctx)
	_ = client.webSocket(ctx)
	select {
	case <-completed:
	case <-ctx.Done():
		t.Fatal("delta/reconnect did not finish", ctx.Err())
	default:
		t.Fatal("missing second baseline")
	}
}
