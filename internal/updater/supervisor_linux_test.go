//go:build linux

package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStageRejectsUnfinishedOrUnreadableState(t *testing.T) {
	t.Setenv("ASWIRED_UPDATE_SUPERVISED", "1")
	for _, status := range []string{"staged", "ready", "restarting", "healthy", "corrupt"} {
		t.Run(status, func(t *testing.T) {
			data := t.TempDir()
			if err := write(data, State{Status: status}); err != nil {
				t.Fatal(err)
			}
			if status == "corrupt" {
				if err := os.WriteFile(filepath.Join(directory(data), "state.json"), []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := Stage(context.Background(), data, "next", "invalid", "", "2")
			if err == nil || (!strings.Contains(err.Error(), "已有升级") && !strings.Contains(err.Error(), "无法读取升级状态")) {
				t.Fatalf("unsafe state accepted: %v", err)
			}
		})
	}
}

func TestSupervisorRollsBackCrashingReplacement(t *testing.T) {
	data := t.TempDir()
	dir := directory(data)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	original := []byte("#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n")
	replacement := []byte("#!/bin/sh\nif [ \"$1\" = -version ]; then echo 1.2.3; exit 0; fi\nexit 13\n")
	if err := os.WriteFile(filepath.Join(dir, "current"), original, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "next"), replacement, 0700); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(replacement)
	if err := write(data, State{TaskID: "crash", Status: "ready", Version: "1.2.3", SHA256: hex.EncodeToString(hash[:])}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Supervise(ctx, "unused.json", data) }()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		state, _ := read(data)
		if state.Status == "rolled_back" {
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			raw, _ := os.ReadFile(filepath.Join(dir, "current"))
			if string(raw) != string(original) {
				t.Fatal("original binary not restored")
			}
			return
		}
		select {
		case err := <-done:
			t.Fatal("supervisor stopped", err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	cancel()
	<-done
	t.Fatal("replacement did not roll back")
}

func TestSupervisorRecoversInterruptedPromotionBeforeRename(t *testing.T) {
	data := t.TempDir()
	dir := directory(data)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	original := []byte("#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n")
	if err := os.WriteFile(filepath.Join(dir, "current"), original, 0700); err != nil {
		t.Fatal(err)
	}
	if err := write(data, State{TaskID: "interrupted", Status: "restarting", Version: "1.2.3"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Supervise(ctx, "unused.json", data) }()
	for attempts := 0; attempts < 50; attempts++ {
		state, _ := read(data)
		if state.Status == "rolled_back" {
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			raw, _ := os.ReadFile(filepath.Join(dir, "current"))
			if string(raw) != string(original) {
				t.Fatal("original replaced")
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("interrupted promotion remained stuck")
}
