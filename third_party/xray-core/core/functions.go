package core

import (
	"bytes"
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/udp"
)

func CreateObject(v *Instance, config interface{}) (interface{}, error) {
	ctx := v.ctx
	if v != nil {
		ctx = toContext(v.ctx, v)
	}
	return common.CreateObject(ctx, config)
}

func StartInstance(configFormat string, configBytes []byte) (*Instance, error) {
	config, err := LoadConfig(configFormat, bytes.NewReader(configBytes))
	if err != nil {
		return nil, err
	}
	instance, err := New(config)
	if err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		return nil, err
	}
	return instance, nil
}

func Dial(ctx context.Context, v *Instance, dest net.Destination) (net.Conn, error) {
	ctx = toContext(ctx, v)

	dispatcher := v.GetFeature(routing.DispatcherType())
	if dispatcher == nil {
		return nil, errors.New("routing.Dispatcher is not registered in Xray core")
	}

	r, err := dispatcher.(routing.Dispatcher).Dispatch(ctx, dest)
	if err != nil {
		return nil, err
	}
	var readerOpt cnc.ConnectionOption
	if dest.Network == net.Network_TCP {
		readerOpt = cnc.ConnectionOutputMulti(r.Reader)
	} else {
		readerOpt = cnc.ConnectionOutputMultiUDP(r.Reader)
	}
	return cnc.NewConnection(cnc.ConnectionInputMulti(r.Writer), readerOpt), nil
}

func DialUDP(ctx context.Context, v *Instance) (net.PacketConn, error) {
	ctx = toContext(ctx, v)

	dispatcher := v.GetFeature(routing.DispatcherType())
	if dispatcher == nil {
		return nil, errors.New("routing.Dispatcher is not registered in Xray core")
	}
	return udp.DialDispatcher(ctx, dispatcher.(routing.Dispatcher))
}
