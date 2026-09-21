//go:build linux

package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/artifact"
)

func copyBinary(source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func Supervise(ctx context.Context, config, data string) error {
	dir := directory(data)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// One supervisor owns replacement, rollback and child process lifetime.
	lock, err := os.OpenFile(filepath.Join(dir, "supervisor.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("已有 Agent 升级监督进程")
	}
	current := filepath.Join(dir, "current")
	previous := filepath.Join(dir, "previous")
	next := filepath.Join(dir, "next")
	if _, err = os.Lstat(current); os.IsNotExist(err) {
		self, e := os.Executable()
		if e != nil {
			return e
		}
		if e = copyBinary(self, current); e != nil {
			return e
		}
	} else if err != nil {
		return err
	}
	state, stateErr := read(data)
	if stateErr != nil && !os.IsNotExist(stateErr) {
		return stateErr
	}
	if state.Status == "restarting" { // Interrupted upgrade: restore before restarting.
		if _, e := os.Stat(previous); e == nil {
			if e = os.Rename(previous, current); e != nil {
				return e
			}
		} else if !os.IsNotExist(e) {
			return e
		}
		// No previous file means promotion had not renamed current yet.
		state.Status = "rolled_back"
		state.Error = "升级确认前监督进程重启，已恢复原版本"
		if err = write(data, state); err != nil {
			return err
		}
	} else if state.Status == "healthy" {
		state.Status = "completed"
		if err = write(data, state); err != nil {
			return err
		}
	}
	var child *exec.Cmd
	var done chan error
	start := func() error {
		info, err := os.Lstat(current)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("Agent 当前制品不是普通文件")
		}
		child = exec.Command(current, "-config", config)
		child.Env = append(os.Environ(), "ASWIRED_UPDATE_SUPERVISED=1")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err = child.Start(); err != nil {
			return err
		}
		done = make(chan error, 1)
		go func(command *exec.Cmd, result chan error) { result <- command.Wait() }(child, done)
		return nil
	}
	stop := func() {
		_ = child.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = child.Process.Kill()
			<-done
		}
	}
	rollback := func(reason string) error {
		if err = os.Rename(previous, current); err != nil {
			return err
		}
		state.Status = "rolled_back"
		state.Error = reason
		if err = write(data, state); err != nil {
			return err
		}
		return start()
	}
	if err = start(); err != nil {
		return err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var deadline time.Time
	for {
		select {
		case <-ctx.Done():
			stop()
			return nil
		case childErr := <-done:
			if !deadline.IsZero() {
				if err = rollback("新 Agent 启动失败，已恢复原版本"); err != nil {
					return err
				}
				deadline = time.Time{}
				continue
			}
			return fmt.Errorf("Agent worker exited: %v", childErr)
		case <-ticker.C:
			observed, e := read(data)
			if e != nil && !os.IsNotExist(e) {
				stop()
				return e
			}
			if e == nil {
				state = observed
			}
			if state.Status == "ready" {
				if err = artifact.Verify(ctx, next, state.SHA256, state.Version); err != nil {
					state.Status = "failed"
					state.Error = err.Error()
					_ = write(data, state)
					continue
				}
				stop()
				_ = os.Remove(previous)
				state.Status = "restarting"
				if err = write(data, state); err != nil {
					return err
				}
				if err = os.Rename(current, previous); err != nil {
					return err
				}
				if err = os.Rename(next, current); err != nil {
					_ = os.Rename(previous, current)
					return err
				}
				deadline = time.Now().Add(90 * time.Second)
				if err = start(); err != nil {
					if err = rollback("新制品无法启动，已恢复原版本"); err != nil {
						return err
					}
					deadline = time.Time{}
				}
			} else if !deadline.IsZero() {
				if state.Status == "healthy" {
					state.Status = "completed"
					state.Error = ""
					if err = write(data, state); err != nil {
						return err
					}
					deadline = time.Time{}
				} else if time.Now().After(deadline) {
					stop()
					if err = rollback("新 Agent 90 秒内未完成主控认证，已恢复原版本"); err != nil {
						return err
					}
					deadline = time.Time{}
				}
			}
		}
	}
}
