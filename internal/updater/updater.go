package updater

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/artifact"
)

type State struct {
	TaskID    string    `json:"taskId"`
	Status    string    `json:"status"`
	Version   string    `json:"version"`
	SHA256    string    `json:"sha256"`
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
}

var mu sync.Mutex

func directory(data string) string { return filepath.Join(data, "agent-update") }
func read(data string) (State, error) {
	var state State
	raw, err := os.ReadFile(filepath.Join(directory(data), "state.json"))
	if err == nil {
		err = json.Unmarshal(raw, &state)
	}
	return state, err
}
func write(data string, state State) error {
	state.UpdatedAt = time.Now().UTC()
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	dir := directory(data)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".state-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, filepath.Join(dir, "state.json"))
}
func Available() bool {
	return runtime.GOOS == "linux" && os.Getenv("ASWIRED_UPDATE_SUPERVISED") == "1"
}
func Snapshot(data string) map[string]any {
	mu.Lock()
	defer mu.Unlock()
	state, err := read(data)
	if err != nil {
		return map[string]any{"available": Available()}
	}
	raw, _ := json.Marshal(state)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	out["available"] = Available()
	return out
}
func Stage(ctx context.Context, data, task, url, checksum, version string) (map[string]any, error) {
	mu.Lock()
	defer mu.Unlock()
	if !Available() {
		return nil, errors.New("Agent 未通过升级监督进程启动，请先更新安装服务")
	}
	old, err := read(data)
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.New("无法读取升级状态，请先修复状态文件")
	}
	if old.Status == "staged" || old.Status == "ready" || old.Status == "restarting" || old.Status == "healthy" {
		return nil, errors.New("已有升级正在进行")
	}
	path := filepath.Join(directory(data), "next")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := artifact.Fetch(ctx, url, path, checksum, version); err != nil {
		return nil, err
	}
	if err := write(data, State{TaskID: task, Status: "staged", SHA256: checksum, Version: version}); err != nil {
		return nil, err
	}
	return map[string]any{"staged": true, "version": version, "sha256": checksum, "message": "制品已验证，主控确认收到任务结果后重启；最终结果以 Agent 重新上线报告为准"}, nil
}

// Only a successfully authenticated controller reply can acknowledge a staged
// command or confirm that the replacement has rejoined under the same identity.
func Acknowledge(data, task, version string) error {
	mu.Lock()
	defer mu.Unlock()
	state, err := read(data)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if state.Status == "staged" && state.TaskID == task {
		state.Status = "ready"
		return write(data, state)
	}
	if state.Status == "restarting" && state.Version == version {
		state.Status = "healthy"
		return write(data, state)
	}
	return nil
}
