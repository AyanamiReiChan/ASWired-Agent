package runtime

import (
	"errors"
	"os"
)

// A new Agent can report and manage its core before any inbounds are deployed.
// This configuration needs no external assets and opens no listening ports.
const initialCoreConfig = `{
  "log": {"loglevel": "warning"},
  "inbounds": [],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {"domainStrategy": "AsIs", "rules": []},
  "stats": {},
  "policy": {
    "levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true}},
    "system": {"statsInboundUplink": true, "statsInboundDownlink": true, "statsOutboundUplink": true, "statsOutboundDownlink": true}
  }
}
`

func (r *Runtime) initializeCoreConfig() error {
	if err := noSymlinks(r.cfg.XrayConfig); err != nil {
		return err
	}
	info, err := os.Stat(r.cfg.XrayConfig)
	if err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("Xray configuration must be a regular file")
		}
		// Even invalid existing JSON must remain available for diagnosis/repair.
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	if err = atomicCreate(r.cfg.XrayConfig, []byte(initialCoreConfig), 0600); os.IsExist(err) {
		// Recheck the winning path, without overwriting a concurrently saved config.
		return r.initializeCoreConfig()
	}
	return err
}
