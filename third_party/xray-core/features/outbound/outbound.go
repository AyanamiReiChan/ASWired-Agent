package outbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/transport"
)

type Handler interface {
	common.Runnable
	Tag() string
	Dispatch(ctx context.Context, link *transport.Link)
	SenderSettings() *serial.TypedMessage
	ProxySettings() *serial.TypedMessage
}

type HandlerSelector interface {
	Select([]string) []string
}

type Manager interface {
	features.Feature

	GetHandler(tag string) Handler

	GetDefaultHandler() Handler

	AddHandler(ctx context.Context, handler Handler) error

	RemoveHandler(ctx context.Context, tag string) error

	ListHandlers(ctx context.Context) []Handler
}

func ManagerType() interface{} {
	return (*Manager)(nil)
}
