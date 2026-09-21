package inbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features"
)

type Handler interface {
	common.Runnable

	Tag() string

	ReceiverSettings() *serial.TypedMessage

	ProxySettings() *serial.TypedMessage
}

type Manager interface {
	features.Feature

	GetHandler(ctx context.Context, tag string) (Handler, error)

	AddHandler(ctx context.Context, handler Handler) error

	RemoveHandler(ctx context.Context, tag string) error

	ListHandlers(ctx context.Context) []Handler
}

func ManagerType() interface{} {
	return (*Manager)(nil)
}
