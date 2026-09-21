package dokodemo

import (
	"github.com/xtls/xray-core/common/net"
)

func (v *Config) GetPredefinedAddress() net.Address {
	addr := v.Address.AsAddress()
	if addr == nil {
		return nil
	}
	return addr
}
