package policy

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features/policy"
)

type Instance struct {
	levels map[uint32]*Policy
	system *SystemPolicy
}

func New(ctx context.Context, config *Config) (*Instance, error) {
	m := &Instance{
		levels: make(map[uint32]*Policy),
		system: config.System,
	}
	if len(config.Level) > 0 {
		for lv, p := range config.Level {
			pp := defaultPolicy()
			pp.overrideWith(p)
			m.levels[lv] = pp
		}
	}

	return m, nil
}

func (*Instance) Type() interface{} {
	return policy.ManagerType()
}

func (m *Instance) ForLevel(level uint32) policy.Session {
	if p, ok := m.levels[level]; ok {
		return p.ToCorePolicy()
	}
	return policy.SessionDefault()
}

func (m *Instance) ForSystem() policy.System {
	if m.system == nil {
		return policy.System{}
	}
	return m.system.ToCorePolicy()
}

func (m *Instance) Start() error {
	return nil
}

func (m *Instance) Close() error {
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
