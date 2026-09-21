package config

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHomePairingPreservesLocalSettingsAndPinsOrigin(t *testing.T) {
	_, public, e := wire.GenerateKey()
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "home.json")
	original := []byte(`{"mihomo_binary":"local-only-binary","mihomo_sha256":"local-hash","custom_local_setting":true}`)
	if e = os.WriteFile(path, original, 0600); e != nil {
		t.Fatal(e)
	}
	var origin string
	badOrigin := false
	used := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/home/pair" || r.Method != "POST" {
			t.Error("incorrect pairing endpoint")
			w.WriteHeader(404)
			return
		}
		var v map[string]string
		json.NewDecoder(r.Body).Decode(&v)
		if v["code"] != "once" || used {
			w.WriteHeader(403)
			return
		}
		target := origin
		if badOrigin {
			target = "https://other.invalid"
		} else {
			used = true
		}
		json.NewEncoder(w).Encode(map[string]any{"config": map[string]any{"server_id": "new-home", "token": strings.Repeat("t", 40), "agent_token": strings.Repeat("a", 40), "master_public_key": public, "master_url": target, "mihomo_binary": "remote-must-not-control-executable", "data_dir": "remote-must-not-control-files"}})
	}))
	defer server.Close()
	origin = server.URL
	badOrigin = true
	if PairHome(context.Background(), origin, "once", path) == nil {
		t.Fatal("controller origin substitution accepted")
	}
	current, _ := os.ReadFile(path)
	if !bytes.Equal(current, original) {
		t.Fatal("invalid enrollment overwrote local configuration")
	}
	badOrigin = false
	if e = PairHome(context.Background(), origin, "once", path); e != nil {
		t.Fatal(e)
	}
	var cfg map[string]any
	b, _ := os.ReadFile(path)
	json.Unmarshal(b, &cfg)
	if cfg["mihomo_binary"] != "local-only-binary" || cfg["custom_local_setting"] != true || cfg["server_id"] != "new-home" {
		t.Fatal("pairing replaced machine settings or lost identity")
	}
	if PairHome(context.Background(), origin, "once", path) == nil {
		t.Fatal("one-use pairing accepted twice")
	}
	loaded, e := Load(path)
	if e != nil || loaded.ConfigPath != path || loaded.Role != "speedtest" || loaded.Validate(false) != nil {
		t.Fatal("paired configuration cannot run")
	}
	if PairHome(context.Background(), "http://public.invalid", "once", path) == nil {
		t.Fatal("pairing sent identity over unprotected public HTTP")
	}
}
