package runtime

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
)

func directoryLink(t *testing.T, target, link string) {
	t.Helper()
	if runtime.GOOS == "windows" {

		cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path $env:ASWIRED_TEST_LINK -Target $env:ASWIRED_TEST_TARGET | Out-Null")
		cmd.Env = append(os.Environ(), "ASWIRED_TEST_LINK="+link, "ASWIRED_TEST_TARGET="+target)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("create directory junction: %v %s", err, out)
		}
		return
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredRootAliasSupportsManagedWrites(t *testing.T) {
	parent := t.TempDir()
	physical := filepath.Join(parent, "physical")
	if err := os.Mkdir(physical, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias")
	directoryLink(t, physical, alias)

	configured := filepath.Join(alias, "agent-data")
	r, err := New(config.Config{DataDir: configured, XrayConfig: filepath.Join(configured, "xray", "config.json"), NginxConfig: filepath.Join(configured, "site", "nginx.conf"), XrayMode: "embedded"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	want, err := filepath.EvalSymlinks(filepath.Join(physical, "agent-data"))
	if err != nil {
		t.Fatal(err)
	}
	if r.cfg.DataDir != want || r.cfg.XrayConfig != filepath.Join(want, "xray", "config.json") || r.cfg.NginxConfig != filepath.Join(want, "site", "nginx.conf") {
		t.Fatalf("managed paths were not rebased together: %+v", r.cfg)
	}
	core := map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
	command(t, r, "core.config.apply", map[string]any{"config": core})
	command(t, r, "core.config.apply", map[string]any{"config": core})
	command(t, r, "core.policy.apply", map[string]any{"policies": []any{}})
	if _, err := os.Stat(filepath.Join(want, "core-generation")); err != nil {
		t.Fatal(err)
	}
	if history, err := os.ReadDir(filepath.Join(want, "history")); err != nil || len(history) == 0 {
		t.Fatalf("history not written through canonical root: %v", err)
	}
}

func TestInternalDirectoryLinkIsNotCanonicalizedOrFollowed(t *testing.T) {
	parent := t.TempDir()
	physical, outside := filepath.Join(parent, "physical"), filepath.Join(parent, "outside")
	for _, dir := range []string{physical, outside} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(parent, "alias")
	directoryLink(t, physical, alias)
	directoryLink(t, outside, filepath.Join(physical, "escape"))

	r, err := New(config.Config{DataDir: alias, XrayConfig: filepath.Join(alias, "escape", "new-parent", "config.json"), XrayMode: "embedded"})
	if err == nil {
		r.Close()
		t.Fatal("initialization accepted an internal directory link")
	}
	if _, err := os.Stat(filepath.Join(outside, "new-parent")); !os.IsNotExist(err) {
		t.Fatalf("even parent directory creation escaped: %v", err)
	}
	if err := atomicWrite(filepath.Join(physical, "escape", "new-parent", "secret"), []byte("secret"), 0600); err == nil {
		t.Fatal("direct managed write followed a directory link")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("outside directory changed: %v %v", entries, err)
	}
}

func TestManagedPathRebaseUsesDirectoryBoundary(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, canonical := filepath.Join(parent, "data"), filepath.Join(parent, "canonical")
	outside := filepath.Join(parent, "data-other", "xray.json")
	if got, err := rebaseManagedPath(outside, root, canonical); err != nil || got != outside {
		t.Fatalf("sibling prefix wrongly rebased: %q %v", got, err)
	}
	if got, err := rebaseManagedPath(filepath.Join(root, "xray", "config.json"), root, canonical); err != nil || got != filepath.Join(canonical, "xray", "config.json") {
		t.Fatalf("child not rebased: %q %v", got, err)
	}
}

func TestEmptyAndInvalidManagedRootPaths(t *testing.T) {
	if _, err := canonicalManagedRoot(""); err == nil {
		t.Fatal("empty root accepted as the working directory")
	}
	path := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := canonicalManagedRoot(path); err == nil {
		t.Fatal("file accepted as data directory")
	}
	if got, err := rebaseManagedPath("", filepath.Dir(path), filepath.Dir(path)); err != nil || got != "" {
		t.Fatal("disabled optional path changed")
	}
}
