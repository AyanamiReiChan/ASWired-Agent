package kcp

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

func (c *Config) GetMTUValue() uint32 {
	if c == nil || c.Mtu == nil {
		return 1350
	}
	return c.Mtu.Value
}

func (c *Config) GetTTIValue() uint32 {
	if c == nil || c.Tti == nil {
		return 50
	}
	return c.Tti.Value
}

func (c *Config) GetUplinkCapacityValue() uint32 {
	if c == nil || c.UplinkCapacity == nil {
		return 5
	}
	return c.UplinkCapacity.Value
}

func (c *Config) GetDownlinkCapacityValue() uint32 {
	if c == nil || c.DownlinkCapacity == nil {
		return 20
	}
	return c.DownlinkCapacity.Value
}

func (c *Config) GetWriteBufferSize() uint32 {
	if c == nil || c.WriteBuffer == nil {
		return 2 * 1024 * 1024
	}
	return c.WriteBuffer.Size
}

func (c *Config) GetSendingInFlightSize() uint32 {
	size := c.GetUplinkCapacityValue() * 1024 * 1024 / c.GetMTUValue() / (1000 / c.GetTTIValue())
	if size < 8 {
		size = 8
	}
	return size
}

func (c *Config) GetSendingBufferSize() uint32 {
	return c.GetWriteBufferSize() / c.GetMTUValue()
}

func (c *Config) GetReceivingInFlightSize() uint32 {
	size := c.GetDownlinkCapacityValue() * 1024 * 1024 / c.GetMTUValue() / (1000 / c.GetTTIValue())
	if size < 8 {
		size = 8
	}
	return size
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
