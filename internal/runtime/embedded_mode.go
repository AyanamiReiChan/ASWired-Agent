package runtime

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Do not silently take over an external service recorded by an older Agent.
func (r *Runtime) validateLegacyMode() error {
	b, err := os.ReadFile(filepath.Join(r.cfg.DataDir, "runtime-mode.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var state struct {
		Mode string `json:"mode"`
	}
	if err = json.Unmarshal(b, &state); err != nil {
		return err
	}
	if state.Mode != "embedded" {
		return errors.New("legacy runtime mode is unsupported; reinstall with a fresh embedded configuration")
	}
	return nil
}
