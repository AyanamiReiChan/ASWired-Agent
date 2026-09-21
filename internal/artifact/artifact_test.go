package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "-version" && os.Getenv("ASWIRED_ARTIFACT_HELPER") == "1" {
		fmt.Println("1.2.3")
		os.Exit(0)
	}
	os.Exit(m.Run())
}
func TestPinnedArtifactVersionAndHashBeforeExecution(t *testing.T) {
	t.Setenv("ASWIRED_ARTIFACT_HELPER", "1")
	self, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(self)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "candidate.exe")
	if e = os.WriteFile(path, b, 0755); e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(b)
	checksum := hex.EncodeToString(hash[:])
	if e = Verify(context.Background(), path, checksum, "1.2.3"); e != nil {
		t.Fatal(e)
	}
	if e = Verify(context.Background(), path, checksum, "1.2.4"); e == nil {
		t.Fatal("wrong release version accepted")
	}
	if e = Verify(context.Background(), path, strings.Repeat("0", 64), "1.2.3"); e == nil {
		t.Fatal("wrong binary hash accepted")
	}
	if e = Verify(context.Background(), path, checksum, "latest"); e == nil {
		t.Fatal("moving release name accepted")
	}
}
func TestDownloadedArtifactIsVerifiedBeforePublishing(t *testing.T) {
	t.Setenv("ASWIRED_ARTIFACT_HELPER", "1")
	self, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(self)
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(b)
	checksum := hex.EncodeToString(hash[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(b) }))
	defer srv.Close()
	target := filepath.Join(t.TempDir(), "release.exe")
	if e = Fetch(context.Background(), srv.URL, target, strings.Repeat("0", 64), "1.2.3"); e == nil {
		t.Fatal("corrupted download published")
	}
	if _, e = os.Stat(target); !os.IsNotExist(e) {
		t.Fatal("failed checksum left a published artifact")
	}
	if e = Fetch(context.Background(), srv.URL, target, checksum, "1.2.3"); e != nil {
		t.Fatal(e)
	}
	if e = Verify(context.Background(), target, checksum, "1.2.3"); e != nil {
		t.Fatal(e)
	}
}
