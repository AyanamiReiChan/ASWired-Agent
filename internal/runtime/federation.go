package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
)

func (r *Runtime) federationIdentity() (private, public string, err error) {
	path := filepath.Join(r.cfg.DataDir, "federation", "identity.key")
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		private, public, e = wire.GenerateKey()
		if e != nil {
			return "", "", e
		}
		if e = atomicWrite(path, []byte(private), 0600); e != nil {
			return "", "", e
		}
		return private, public, nil
	}
	if e != nil {
		return "", "", e
	}
	private = strings.TrimSpace(string(b))
	public, e = wire.PublicKey(private)
	return private, public, e
}
func federationActionAllowed(action string) bool {
	switch action {
	case "status.get", "inbound.users.get", "inbound.users.sync", "stats.get":
		return true
	}
	return false
}

func (r *Runtime) installFederationGrant(raw any) (map[string]any, error) {
	b, e := json.Marshal(raw)
	if e != nil {
		return nil, e
	}
	var signed wire.SignedFederationGrant
	if e = json.Unmarshal(b, &signed); e != nil {
		return nil, e
	}
	if e = wire.VerifyFederationGrant(signed); e != nil {
		return nil, e
	}
	grant := signed.Grant
	_, public, e := r.federationIdentity()
	if e != nil {
		return nil, e
	}
	if grant.Protocol != wire.FederationProtocol || grant.ServerID != r.cfg.ServerID || grant.AgentPublicKey != public || !safeName(grant.ID) || !safeName(grant.Namespace) || grant.Revision == 0 || len(grant.Inbounds) == 0 {
		return nil, errors.New("federation grant identity or scope mismatch")
	}
	if _, e = wire.NewClient(grant.ConsumerPublicKey); e != nil {
		return nil, e
	}
	for alias, tag := range grant.Inbounds {
		if !safeName(alias) || tag == "" || len(tag) > 200 {
			return nil, errors.New("invalid federation inbound mapping")
		}
	}
	for _, action := range grant.Actions {
		if !federationActionAllowed(action) {
			return nil, errors.New("global or unsupported operation cannot be granted")
		}
	}
	pinPath := filepath.Join(r.cfg.DataDir, "federation", "owner-signing.pub")
	pin, e := os.ReadFile(pinPath)
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	if len(pin) > 0 && string(pin) != signed.OwnerPublicKey {
		return nil, errors.New("federation ACL signing key does not match pinned owner")
	}
	if len(pin) == 0 {
		if e = atomicWrite(pinPath, []byte(signed.OwnerPublicKey), 0600); e != nil {
			return nil, e
		}
	}
	path := filepath.Join(r.cfg.DataDir, "federation", "grants", grant.ID+".json")
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == grant.ID+".json" {
			continue
		}
		data, e := os.ReadFile(filepath.Join(filepath.Dir(path), entry.Name()))
		if e != nil {
			return nil, e
		}
		var other wire.SignedFederationGrant
		if e = json.Unmarshal(data, &other); e != nil {
			return nil, e
		}
		if other.Grant.Namespace == grant.Namespace || strings.HasPrefix(other.Grant.Namespace, grant.Namespace+".") || strings.HasPrefix(grant.Namespace, other.Grant.Namespace+".") {
			return nil, errors.New("federation namespace overlaps an existing grant")
		}
	}
	if old, e := os.ReadFile(path); e == nil {
		var prior wire.SignedFederationGrant
		if e = json.Unmarshal(old, &prior); e != nil {
			return nil, e
		}
		if grant.Revision < prior.Grant.Revision {
			return nil, errors.New("stale federation grant revision")
		}
		if grant.Namespace != prior.Grant.Namespace {
			return nil, errors.New("federation namespace is immutable for a grant")
		}
		if grant.Revision == prior.Grant.Revision {
			if signed.Signature != prior.Signature {
				return nil, errors.New("federation grant revision conflict")
			}
			return map[string]any{"installed": true, "revoked": grant.Revoked, "revision": grant.Revision}, nil
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if e = atomicWrite(path, b, 0600); e != nil {
		return nil, e
	}
	return map[string]any{"installed": true, "revoked": grant.Revoked, "revision": grant.Revision, "namespace": grant.Namespace}, nil
}

func (r *Runtime) executeFederation(ctx context.Context, raw any) (map[string]any, error) {
	b, e := json.Marshal(raw)
	if e != nil {
		return nil, e
	}
	var envelope wire.FederationEnvelope
	if e = json.Unmarshal(b, &envelope); e != nil {
		return nil, e
	}
	b, e = json.Marshal(envelope)
	if e != nil {
		return nil, e
	}
	if !safeName(envelope.ShareID) {
		return nil, errors.New("invalid federation share")
	}
	signedBytes, e := os.ReadFile(filepath.Join(r.cfg.DataDir, "federation", "grants", envelope.ShareID+".json"))
	if e != nil {
		return nil, errors.New("federation grant unavailable")
	}
	var signed wire.SignedFederationGrant
	if e = json.Unmarshal(signedBytes, &signed); e != nil {
		return nil, e
	}
	if e = wire.VerifyFederationGrant(signed); e != nil {
		return nil, e
	}
	pin, e := os.ReadFile(filepath.Join(r.cfg.DataDir, "federation", "owner-signing.pub"))
	if e != nil || string(pin) != signed.OwnerPublicKey {
		return nil, errors.New("federation owner identity no longer matches")
	}
	grant := signed.Grant
	if grant.Revoked || (grant.ExpiresAt > 0 && grant.ExpiresAt <= time.Now().Unix()) || grant.ConsumerPublicKey != envelope.ConsumerPublicKey {
		return nil, errors.New("federation permission denied")
	}
	private, public, e := r.federationIdentity()
	if e != nil {
		return nil, e
	}
	if grant.AgentPublicKey != public || grant.ServerID != r.cfg.ServerID {
		return nil, errors.New("federation Agent identity changed")
	}
	channel, e := wire.NewServer(private, envelope.Hello.PublicKey)
	if e != nil {
		return nil, e
	}
	var request wire.FederationRequest
	if e = channel.Open(envelope.Hello.Packet, &request); e != nil {
		return nil, errors.New("federation ciphertext authentication failed")
	}
	if request.Protocol != wire.FederationProtocol || request.ShareID != grant.ID || request.Namespace != grant.Namespace || request.ConsumerPublicKey != grant.ConsumerPublicKey || request.AgentPublicKey != public || request.EphemeralPublicKey != envelope.Hello.PublicKey || request.GrantRevision != grant.Revision {
		return nil, errors.New("federation request binding failed")
	}
	if e = wire.VerifyFederationProof(private, request); e != nil {
		return nil, e
	}
	allowed := false
	for _, action := range grant.Actions {
		if action == request.Command.Action {
			allowed = true
		}
	}
	if !allowed || !federationActionAllowed(request.Command.Action) {
		return nil, errors.New("federation action outside grant")
	}
	if request.Command.ID == "" || len(request.Command.ID) > 200 || request.Command.ID != envelope.RequestID {
		return nil, errors.New("invalid federation command ID")
	}
	cachePath := filepath.Join(r.cfg.DataDir, "federation", "results", digest([]byte(grant.ID+"/"+request.Command.ID))+".json")
	envelopeHash := digest(b)
	if cached, e := os.ReadFile(cachePath); e == nil {
		var old struct {
			Hash   string      `json:"hash"`
			Packet wire.Packet `json:"packet"`
		}
		if e = json.Unmarshal(cached, &old); e != nil {
			return nil, e
		}
		if old.Hash != envelopeHash {
			return nil, errors.New("federation command ID reused with another ciphertext")
		}
		return map[string]any{"packet": old.Packet, "cached": true}, nil
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if request.IssuedAt < time.Now().Add(-5*time.Minute).Unix() || request.IssuedAt > time.Now().Add(90*time.Second).Unix() {
		return nil, errors.New("federation request expired")
	}
	result := wire.Result{ID: request.Command.ID, Status: "success"}
	result.Data, e = r.handleFederationOperation(ctx, grant, request.Command)
	if e != nil {
		result.Status = "failed"
		result.Error = e.Error()
	}
	packet, e := channel.Seal(result)
	if e != nil {
		return nil, e
	}
	record, e := json.Marshal(map[string]any{"hash": envelopeHash, "packet": packet})
	if e != nil {
		return nil, e
	}
	if e = atomicWrite(cachePath, record, 0600); e != nil {
		return nil, errors.New("federation operation completed but result could not be persisted")
	}
	return map[string]any{"packet": packet, "cached": false}, nil
}

func (r *Runtime) federationInbound(grant wire.FederationGrant, alias string) (map[string]any, error) {
	tag := grant.Inbounds[alias]
	if tag == "" {
		return nil, errors.New("inbound is outside the shared scope")
	}
	b, e := os.ReadFile(r.cfg.XrayConfig)
	if e != nil {
		return nil, e
	}
	var cfg map[string]any
	if e = json.Unmarshal(b, &cfg); e != nil {
		return nil, e
	}
	inbounds, _ := cfg["inbounds"].([]any)
	for _, value := range inbounds {
		item, _ := value.(map[string]any)
		if item["tag"] == tag {
			return item, nil
		}
	}
	return nil, errors.New("shared inbound is not configured on this Agent")
}

func (r *Runtime) handleFederationOperation(ctx context.Context, grant wire.FederationGrant, cmd wire.Command) (map[string]any, error) {
	prefix := grant.Namespace + "."
	switch cmd.Action {
	case "status.get":
		return map[string]any{"namespace": grant.Namespace, "inbounds": grant.Inbounds, "running": r.status(ctx)["running"], "mode": r.cfg.XrayMode, "generation": r.generation}, nil
	case "stats.get":
		data, e := r.readStats(ctx)
		if e != nil {
			return nil, e
		}
		counters := map[string]int64{}
		if raw, ok := data["counters"].(map[string]int64); ok {
			for name, value := range raw {
				if strings.HasPrefix(name, "user>>>"+prefix) {
					counters[name] = value
				}
			}
		}
		data["counters"] = counters
		return data, nil
	case "inbound.users.get", "inbound.users.sync":
		alias, _ := cmd.Params["inbound"].(string)
		inbound, e := r.federationInbound(grant, alias)
		if e != nil {
			return nil, e
		}
		settings, _ := inbound["settings"].(map[string]any)
		existing, _ := settings["clients"].([]any)
		mine := []any{}
		others := []any{}
		for _, value := range existing {
			user, _ := value.(map[string]any)
			email, _ := user["email"].(string)
			if strings.HasPrefix(email, prefix) {
				mine = append(mine, user)
			} else {
				others = append(others, user)
			}
		}
		if cmd.Action == "inbound.users.get" {
			return map[string]any{"inbound": alias, "protocol": inbound["protocol"], "users": mine}, nil
		}
		desired, ok := cmd.Params["users"].([]any)
		if !ok {
			return nil, errors.New("users array is required")
		}
		for _, value := range desired {
			user, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("invalid user")
			}
			copyUser := map[string]any{}
			for key, value := range user {
				copyUser[key] = value
			}
			email, _ := copyUser["email"].(string)
			if email == "" || len(email) > 150 {
				return nil, errors.New("invalid consumer user email")
			}
			if !strings.HasPrefix(email, prefix) {
				email = prefix + email
			}
			copyUser["email"] = email
			others = append(others, copyUser)
		}
		data, e := r.syncUsers(ctx, grant.Inbounds[alias], others)
		if e != nil {
			return data, e
		}
		return map[string]any{"applied": true, "persisted": true, "namespace": grant.Namespace, "inbound": alias, "users": len(desired)}, nil
	}
	return nil, errors.New("unsupported scoped federation operation")
}

func (r *Runtime) federationPrefixes(tag string) ([]string, error) {
	dir := filepath.Join(r.cfg.DataDir, "federation", "grants")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var prefixes []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var signed wire.SignedFederationGrant
		if err = json.Unmarshal(b, &signed); err != nil {
			return nil, err
		}
		if err = wire.VerifyFederationGrant(signed); err != nil {
			return nil, err
		}
		for _, mapped := range signed.Grant.Inbounds {
			if mapped == tag {
				prefixes = append(prefixes, signed.Grant.Namespace+".")
				break
			}
		}
	}
	return prefixes, nil
}
func (r *Runtime) preserveFederationUsers(tag string, desired, existing []any) ([]any, error) {
	prefixes, err := r.federationPrefixes(tag)
	if err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return desired, nil
	}
	reserved := func(value any) bool {
		user, _ := value.(map[string]any)
		email, _ := user["email"].(string)
		for _, prefix := range prefixes {
			if strings.HasPrefix(email, prefix) {
				return true
			}
		}
		return false
	}
	out := make([]any, 0, len(desired)+len(existing))
	for _, user := range desired {
		if !reserved(user) {
			out = append(out, user)
		}
	}
	for _, user := range existing {
		if reserved(user) {
			out = append(out, user)
		}
	}
	return out, nil
}
func (r *Runtime) preserveFederationConfig(desired, existing []byte) ([]byte, error) {
	if len(existing) == 0 {
		return desired, nil
	}
	var next, old map[string]any
	if err := json.Unmarshal(desired, &next); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(existing, &old); err != nil {
		return nil, err
	}
	nextInbounds, _ := next["inbounds"].([]any)
	oldInbounds, _ := old["inbounds"].([]any)
	for _, item := range nextInbounds {
		in, _ := item.(map[string]any)
		tag, _ := in["tag"].(string)
		for _, prior := range oldInbounds {
			previous, _ := prior.(map[string]any)
			if previous["tag"] != tag {
				continue
			}
			settings, _ := in["settings"].(map[string]any)
			previousSettings, _ := previous["settings"].(map[string]any)
			desiredUsers, _ := settings["clients"].([]any)
			oldUsers, _ := previousSettings["clients"].([]any)
			merged, err := r.preserveFederationUsers(tag, desiredUsers, oldUsers)
			if err != nil {
				return nil, err
			}
			if len(merged) > len(desiredUsers) && previous["protocol"] != in["protocol"] {
				return nil, errors.New("cannot change protocol while a shared namespace has configured users")
			}
			if len(merged) > 0 || settings["clients"] != nil {
				if settings == nil {
					settings = map[string]any{}
					in["settings"] = settings
				}
				settings["clients"] = merged
			}
			break
		}
	}
	return json.MarshalIndent(next, "", "  ")
}
func (r *Runtime) syncOwnerUsers(ctx context.Context, tag string, raw any) (map[string]any, error) {
	desired, ok := raw.([]any)
	if !ok {
		return nil, errors.New("users array is required")
	}
	b, err := os.ReadFile(r.cfg.XrayConfig)
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err = json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	inbounds, _ := cfg["inbounds"].([]any)
	for _, value := range inbounds {
		in, _ := value.(map[string]any)
		if in["tag"] != tag {
			continue
		}
		settings, _ := in["settings"].(map[string]any)
		existing, _ := settings["clients"].([]any)
		desired, err = r.preserveFederationUsers(tag, desired, existing)
		if err != nil {
			return nil, err
		}
		break
	}
	return r.syncUsers(ctx, tag, desired)
}
