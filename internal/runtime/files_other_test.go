//go:build !windows

package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedWriteRejectsFinalFileSymlink(t *testing.T) {
	root, err := canonicalManagedRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "untouched")
	if err := os.WriteFile(outside, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "config.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(link, []byte("replacement"), 0600); err == nil {
		t.Fatal("symbolic-link destination accepted")
	}
	if got, err := os.ReadFile(outside); err != nil || string(got) != "original" {
		t.Fatalf("external file changed: %q %v", got, err)
	}
}
