package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
)

func TestFreshAgentInitializesAndStartsCore(t *testing.T) {
	r, err := New(config.Config{DataDir: filepath.Join(t.TempDir(), "new-agent"), XrayMode: "embedded"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := os.ReadFile(r.cfg.XrayConfig)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if inbounds, ok := cfg["inbounds"].([]any); !ok || len(inbounds) != 0 {
		t.Fatalf("initial configuration must not expose a proxy listener: %v", cfg)
	}
	if cfg["api"] != nil || cfg["reverse"] != nil {
		t.Fatal("initial configuration must not expose an API or reverse proxy")
	}
	if goruntime.GOOS != "windows" {
		info, err := os.Stat(r.cfg.XrayConfig)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("configuration is not private: %v %v", info, err)
		}
	}
	// Match the first management snapshot/config fetch, before any deploy task.
	core := r.Snapshot()["core"].(map[string]any)
	if core["config_exists"] != true || core["config_sha256"] != digest(b) {
		t.Fatalf("initial configuration cannot be discovered: %v", core)
	}
	got := command(t, r, "core.config.get", nil)
	if got.Data["sha256"] != core["config_sha256"] || got.Data["config"] == nil {
		t.Fatalf("initial configuration cannot synchronize: %+v", got)
	}
	if err = r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Snapshot()["core"].(map[string]any)["running"] != true {
		t.Fatal("new embedded core did not start")
	}
	command(t, r, "core.stats", nil)
	command(t, r, "core.restart", nil)
	if current, err := os.ReadFile(r.cfg.XrayConfig); err != nil || !bytes.Equal(current, b) {
		t.Fatalf("startup/restart changed initial configuration: %v", err)
	}
	command(t, r, "core.stop", nil)
	command(t, r, "core.start", nil)
}

func TestInitializationPreservesExistingCoreConfig(t *testing.T) {
	for _, contents := range []string{
		`{"log":{"loglevel":"none"},"inbounds":[],"outbounds":[{"tag":"custom","protocol":"blackhole"}]}`,
		`{invalid JSON`,
		"",
	} {
		t.Run(contents, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "custom.json")
			if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				r, err := New(config.Config{DataDir: dir, XrayConfig: path, XrayMode: "embedded"})
				if err != nil {
					t.Fatal(err)
				}
				startErr := r.Start(context.Background())
				if json.Valid([]byte(contents)) != (startErr == nil) {
					t.Fatalf("existing configuration was not respected: %v", startErr)
				}
				r.Close()
				if b, err := os.ReadFile(path); err != nil || string(b) != contents {
					t.Fatalf("existing config was overwritten: %q %v", b, err)
				}
			}
		})
	}
}

func TestInitializationRejectsConfigurationDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if r, err := New(config.Config{DataDir: dir, XrayConfig: path, XrayMode: "embedded"}); err == nil {
		r.Close()
		t.Fatal("configuration directory accepted")
	}
}

func TestAtomicCreateDoesNotReplaceExistingConfiguration(t *testing.T) {
	root, err := canonicalManagedRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "xray", "config.json")
	if err = atomicCreate(path, []byte("custom configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = atomicCreate(path, []byte(initialCoreConfig), 0600); !os.IsExist(err) {
		t.Fatalf("existing file was not protected: %v", err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "custom configuration" {
		t.Fatalf("existing file changed: %q %v", b, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v %v", entries, err)
	}
}
