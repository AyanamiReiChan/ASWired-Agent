package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestDirectHTTPEncryptedRPCRejectsReplayAndToken(t *testing.T) {
	private, public, e := wire.GenerateKey()
	if e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := ln.Addr().String()
	ln.Close()
	run := &runner{}
	client := New(config.Config{ServerID: "s", MasterPublicKey: public, AgentToken: "agent-secret", ListenAddress: address, ConnectionMode: "http"}, run, "test")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.direct(ctx) }()
	defer func() { cancel(); <-done }()
	httpClient := &http.Client{Timeout: 3 * time.Second}
	base := "http://" + address
	nonceBytes := make([]byte, 32)
	if _, e = rand.Read(nonceBytes); e != nil {
		t.Fatal(e)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	var res *http.Response
	for i := 0; i < 100; i++ {
		res, e = httpClient.Get(base + "/v1/hello?nonce=" + nonce)
		if e == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	var hello wire.DirectHello
	if e = json.NewDecoder(res.Body).Decode(&hello); e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if hello.Nonce != nonce || hello.ServerID != "s" || hello.MasterPublicKey != public || hello.Timestamp < time.Now().Unix()-90 || hello.Timestamp > time.Now().Unix()+90 {
		t.Fatalf("hello request/identity binding failed: %+v", hello)
	}
	if e = wire.VerifyDirectHello("agent-secret", hello); e != nil {
		t.Fatal(e)
	}
	tampered := hello
	tampered.PublicKey = public
	if wire.VerifyDirectHello("agent-secret", tampered) == nil || wire.VerifyDirectHello("wrong-token", hello) == nil {
		t.Fatal("forged direct identity accepted before sending credentials")
	}
	ch, e := wire.NewServer(private, hello.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	packet, e := ch.Seal(wire.DirectRequest{Token: "agent-secret", Command: wire.Command{ID: "direct", Action: "core.status"}, Timestamp: time.Now().Unix()})
	if e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(wire.Hello{PublicKey: hello.PublicKey, Packet: packet})
	res, e = httpClient.Post(base+"/v1/rpc", "application/json", bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		t.Fatalf("RPC failed: %s", b)
	}
	var response wire.Packet
	json.NewDecoder(res.Body).Decode(&response)
	res.Body.Close()
	var result wire.Result
	if e = ch.Open(response, &result); e != nil {
		t.Fatal(e)
	}
	if result.Status != "success" {
		t.Fatal(result)
	}
	res, e = httpClient.Post(base+"/v1/rpc", "application/json", bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("replayed direct RPC accepted")
	}
	res, e = httpClient.Get(base + "/v1/hello")
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatal("hello without a nonce accepted")
	}
	res, e = httpClient.Get(base + "/v1/hello?nonce=" + nonce)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.NewDecoder(res.Body).Decode(&hello); e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if e = wire.VerifyDirectHello("agent-secret", hello); e != nil {
		t.Fatal(e)
	}
	ch, e = wire.NewServer(private, hello.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	packet, e = ch.Seal(wire.DirectRequest{Token: "wrong-token", Command: wire.Command{ID: "wrong", Action: "core.status"}, Timestamp: time.Now().Unix()})
	if e != nil {
		t.Fatal(e)
	}
	body, _ = json.Marshal(wire.Hello{PublicKey: hello.PublicKey, Packet: packet})
	res, e = httpClient.Post(base+"/v1/rpc", "application/json", bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("wrong direct token accepted")
	}
	if run.calls != 1 {
		t.Fatal("unauthorized command executed")
	}
}
