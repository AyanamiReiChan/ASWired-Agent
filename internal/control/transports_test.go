package control

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebSocketEncryptedCommandsAndResults(t *testing.T) {
	private, public, e := wire.GenerateKey()
	if e != nil {
		t.Fatal(e)
	}
	received := make(chan wire.Report, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		if e = ch.Open(hello.Packet, &report); e != nil {
			t.Error(e)
			return
		}
		packet, e := ch.Seal(wire.Reply{Interval: 1, Commands: []wire.Command{{ID: "ws-task", Action: "core.status"}}})
		if e != nil {
			t.Error(e)
			return
		}
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
	defer srv.Close()
	run := &runner{}
	client := New(config.Config{ServerID: "s", Token: "token", MasterURL: srv.URL, MasterPublicKey: public, XrayMode: "embedded"}, run, "test")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = client.webSocket(ctx)
	select {
	case report := <-received:
		if len(report.Results) != 1 || report.Results[0].Status != "success" {
			t.Fatalf("result not delivered: %+v", report)
		}
	case <-ctx.Done():
		t.Fatal("missing encrypted WS result")
	}
}

func TestWebSocketRejectsWrongPinnedMasterKey(t *testing.T) {
	private, _, err := wire.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, wrong, err := wire.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	rejected := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		var hello wire.Hello
		if wsjson.Read(r.Context(), conn, &hello) != nil {
			return
		}
		channel, err := wire.NewServer(private, hello.PublicKey)
		if err != nil {
			t.Error(err)
			return
		}
		var report wire.Report
		rejected <- channel.Open(hello.Packet, &report) != nil
	}))
	defer server.Close()
	run := &runner{}
	client := New(config.Config{MasterURL: server.URL, MasterPublicKey: wrong, ConnectionMode: "websocket"}, run, "test")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if client.webSocket(ctx) == nil {
		t.Fatal("wrong pinned key accepted")
	}
	select {
	case bad := <-rejected:
		if !bad {
			t.Fatal("wrong key decrypted")
		}
	case <-ctx.Done():
		t.Fatal("handshake not observed")
	}
	if run.calls != 0 {
		t.Fatal("unauthenticated command executed")
	}
}
