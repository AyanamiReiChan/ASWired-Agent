package runtime

import (
	"encoding/json"
	"errors"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
)

// Persist explicit command policy so restart and rollback retain it. Existing
// configurations without metadata are not migrated merely by starting an Agent.
func proxyNetworkConfig(raw []byte, params map[string]any) ([]byte, error) {
	if len(raw) > 8<<20 {
		return nil, errors.New("config exceeds 8 MiB")
	}
	blocked := true
	if value, exists := params["blockProxyIPv6"]; exists {
		var ok bool
		blocked, ok = value.(bool)
		if !ok {
			return nil, errors.New("blockProxyIPv6 must be a boolean")
		}
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil || config == nil {
		return nil, errors.New("Xray configuration must be an object")
	}
	metadata, _ := config["aswired"].(map[string]any)
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["blockProxyIPv6"] = blocked
	config["aswired"] = metadata
	if !blocked {
		if route, ok := config["routing"].(map[string]any); ok {
			if rules, ok := route["rules"].([]any); ok {
				kept := make([]any, 0, len(rules))
				for _, item := range rules {
					rule, _ := item.(map[string]any)
					if rule["ruleTag"] != "aswired-block-ipv6" {
						kept = append(kept, item)
					}
				}
				route["rules"] = kept
			}
		}
		if outs, ok := config["outbounds"].([]any); ok {
			kept := make([]any, 0, len(outs))
			for _, item := range outs {
				out, _ := item.(map[string]any)
				if out["tag"] != "aswired-block-ipv6" || out["protocol"] != "blackhole" {
					kept = append(kept, item)
				}
			}
			config["outbounds"] = kept
		}
	}
	return json.Marshal(config)
}

func configureProxyNetwork(instance *core.Instance, raw []byte) error {
	var config struct {
		ASWired struct {
			BlockProxyIPv6 bool `json:"blockProxyIPv6"`
		} `json:"aswired"`
		API struct {
			Tag string `json:"tag"`
		} `json:"api"`
		Inbounds []struct {
			Tag string `json:"tag"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return err
	}
	if !config.ASWired.BlockProxyIPv6 {
		return nil
	}
	guard, ok := instance.GetFeature(routing.DispatcherType()).(interface{ ConfigureProxyIPv4([]string) })
	if !ok {
		return errors.New("embedded core lacks IPv6 proxy destination protection")
	}
	tags := []string{}
	for _, inbound := range config.Inbounds {
		if config.API.Tag == "" || inbound.Tag != config.API.Tag {
			tags = append(tags, inbound.Tag)
		}
	}
	guard.ConfigureProxyIPv4(tags)
	return nil
}
