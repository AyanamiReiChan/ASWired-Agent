package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"testing"
	"time"
)

func TestOpaqueFederationScopesConsumerProofAndRevocation(t *testing.T) {
	r := newTestRuntime(t)
	r.cfg.ServerID = "node"
	cfg := map[string]any{"log": map[string]any{"loglevel": "none"}, "stats": map[string]any{}, "inbounds": []any{map[string]any{"tag": "shared-tag", "listen": "127.0.0.1", "port": freePort(t), "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"email": "owner-user", "id": "11111111-1111-4111-8111-111111111111"}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
	command(t, r, "core.config.apply", map[string]any{"config": cfg})
	_, agentPublic, e := r.federationIdentity()
	if e != nil {
		t.Fatal(e)
	}
	consumerPrivate, consumerPublic, e := wire.GenerateKey()
	if e != nil {
		t.Fatal(e)
	}
	_, ownerKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	grant := wire.FederationGrant{Protocol: wire.FederationProtocol, ID: "share", Revision: 1, ServerID: "node", AgentPublicKey: agentPublic, ConsumerPublicKey: consumerPublic, Namespace: "consumer", Inbounds: map[string]string{"main": "shared-tag"}, Actions: []string{"inbound.users.sync", "inbound.users.get", "stats.get", "status.get"}}
	signed, e := wire.SignFederationGrant(grant, ownerKey)
	if e != nil {
		t.Fatal(e)
	}
	command(t, r, "federation.grant", map[string]any{"signed_grant": signed})
	makeRequest := func(id, action string, params map[string]any, proofPrivate string) (wire.FederationEnvelope, *wire.Channel) {
		ch, e := wire.NewClient(agentPublic)
		if e != nil {
			t.Fatal(e)
		}
		request := wire.FederationRequest{Protocol: wire.FederationProtocol, ShareID: "share", GrantRevision: 1, Namespace: "consumer", AgentPublicKey: agentPublic, ConsumerPublicKey: consumerPublic, EphemeralPublicKey: ch.PublicKey(), IssuedAt: time.Now().Unix(), Command: wire.Command{ID: id, Action: action, Params: params}}
		request.Proof, e = wire.FederationProof(proofPrivate, agentPublic, request)
		if e != nil {
			t.Fatal(e)
		}
		packet, e := ch.Seal(request)
		if e != nil {
			t.Fatal(e)
		}
		return wire.FederationEnvelope{RequestID: id, ShareID: "share", ConsumerPublicKey: consumerPublic, Hello: wire.Hello{PublicKey: ch.PublicKey(), Packet: packet}}, ch
	}
	decode := func(outer wire.Result, ch *wire.Channel) wire.Result {
		if outer.Status != "success" {
			t.Fatal(outer.Error)
		}
		b, _ := json.Marshal(outer.Data["packet"])
		var packet wire.Packet
		json.Unmarshal(b, &packet)
		var result wire.Result
		if e := ch.Open(packet, &result); e != nil {
			t.Fatal(e)
		}
		return result
	}
	envelope, consumerChannel := makeRequest("mutation", "inbound.users.sync", map[string]any{"inbound": "main", "users": []any{map[string]any{"email": "secret-member", "id": "22222222-2222-4222-8222-222222222222"}}}, consumerPrivate)
	saved, e := consumerChannel.ClientState()
	if e != nil {
		t.Fatal(e)
	}
	outer := r.Handle(context.Background(), wire.Command{ID: "forward", Action: "federation.execute", Params: map[string]any{"envelope": envelope}})
	if result := decode(outer, consumerChannel); result.Status != "success" {
		t.Fatal(result.Error)
	}
	configResult := command(t, r, "core.config.get", nil)
	raw, _ := json.Marshal(configResult.Data)
	if !bytesContain(raw, `"owner-user"`) || !bytesContain(raw, `"consumer.secret-member"`) {
		t.Fatal("federation replaced another namespace or did not create own user")
	}

	command(t, r, "core.config.apply", map[string]any{"config": cfg})
	configResult = command(t, r, "core.config.get", nil)
	raw, _ = json.Marshal(configResult.Data)
	if !bytesContain(raw, `"consumer.secret-member"`) {
		t.Fatal("owner configuration apply erased the consumer namespace")
	}
	ownerPrivate, _, _ := wire.GenerateKey()
	ownerChannel, _ := wire.NewServer(ownerPrivate, envelope.Hello.PublicKey)
	var stolen wire.FederationRequest
	if ownerChannel.Open(envelope.Hello.Packet, &stolen) == nil {
		t.Fatal("owner could decrypt consumer command")
	}
	replayed := r.Handle(context.Background(), wire.Command{ID: "forward-again", Action: "federation.execute", Params: map[string]any{"envelope": envelope}})
	restored, e := wire.RestoreClient(agentPublic, saved)
	if e != nil {
		t.Fatal(e)
	}
	if result := decode(replayed, restored); result.Status != "success" || replayed.Data["cached"] != true {
		t.Fatal("idempotent encrypted result was not retained")
	}
	wrongScope, ch := makeRequest("wrong-scope", "inbound.users.sync", map[string]any{"inbound": "private", "users": []any{}}, consumerPrivate)
	result := decode(r.Handle(context.Background(), wire.Command{Action: "federation.execute", Params: map[string]any{"envelope": wrongScope}}), ch)
	if result.Status != "failed" {
		t.Fatal("consumer escaped inbound whitelist")
	}
	global, _ := makeRequest("global", "core.config.apply", map[string]any{"config": map[string]any{}}, consumerPrivate)
	if r.Handle(context.Background(), wire.Command{Action: "federation.execute", Params: map[string]any{"envelope": global}}).Status != "failed" {
		t.Fatal("consumer invoked global action")
	}
	fakePrivate, _, _ := wire.GenerateKey()
	forged, _ := makeRequest("forged", "status.get", nil, fakePrivate)
	if r.Handle(context.Background(), wire.Command{Action: "federation.execute", Params: map[string]any{"envelope": forged}}).Status != "failed" {
		t.Fatal("consumer public key alone authenticated forged request")
	}
	grant.Revision = 2
	grant.Revoked = true
	signed, e = wire.SignFederationGrant(grant, ownerKey)
	if e != nil {
		t.Fatal(e)
	}
	command(t, r, "federation.grant", map[string]any{"signed_grant": signed})
	if r.Handle(context.Background(), wire.Command{Action: "federation.execute", Params: map[string]any{"envelope": envelope}}).Status != "failed" {
		t.Fatal("revoked grant accepted replay")
	}
	configResult = command(t, r, "core.config.get", nil)
	raw, _ = json.Marshal(configResult.Data)
	if !bytesContain(raw, `"consumer.secret-member"`) {
		t.Fatal("management revocation deleted existing user")
	}
}
func bytesContain(b []byte, s string) bool {
	for i := 0; i+len(s) <= len(b); i++ {
		if string(b[i:i+len(s)]) == s {
			return true
		}
	}
	return false
}
