package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
)

func (r *Runtime) applyManagedConfig(ctx context.Context, config []byte, params map[string]any) (map[string]any, error) {
	auxiliary, exists := params["auxiliary"]
	if !exists {
		return r.applyConfig(ctx, config)
	}
	aux, ok := auxiliary.(map[string]any)
	if !ok {
		return nil, errors.New("auxiliary must be an object")
	}
	listeners, ok := aux["listeners"].([]any)
	if !ok {
		return nil, errors.New("auxiliary listeners must be an array")
	}
	if len(listeners) > 0 && !r.mihomo.Available() {
		return nil, errors.New("verified Mihomo installation required")
	}
	old, readErr := os.ReadFile(r.cfg.XrayConfig)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, readErr
	}
	result, err := r.applyConfig(ctx, config)
	if err != nil {
		return result, err
	}
	var applied map[string]any
	applied, err = r.mihomo.Apply(ctx, listeners)
	if err == nil {
		result["auxiliary"] = applied
		return result, nil
	}
	var recovery error
	if len(old) > 0 {
		_, recovery = r.applyConfig(ctx, old)
	} else {
		recovery = r.stop(ctx)
		if recovery == nil {
			recovery = os.Remove(r.cfg.XrayConfig)
		}
	}
	return map[string]any{"applied": false, "auxiliary": applied, "core_rollback_succeeded": recovery == nil}, fmt.Errorf("auxiliary apply failed: %w; core rollback: %v", err, recovery)
}
