package routing

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features"
)

type Router interface {
	features.Feature

	PickRoute(ctx Context) (Route, error)
	AddRule(config *serial.TypedMessage, shouldAppend bool) error
	RemoveRule(tag string) error
	ListRule() []Route
}

type Route interface {
	Context

	GetOutboundGroupTags() []string

	GetOutboundTag() string

	GetRuleTag() string
}

func RouterType() interface{} {
	return (*Router)(nil)
}

type DefaultRouter struct{}

func (DefaultRouter) Type() interface{} {
	return RouterType()
}

func (DefaultRouter) PickRoute(ctx Context) (Route, error) {
	return nil, common.ErrNoClue
}

func (DefaultRouter) AddRule(config *serial.TypedMessage, shouldAppend bool) error {
	return common.ErrNoClue
}

func (DefaultRouter) RemoveRule(tag string) error {
	return common.ErrNoClue
}

func (DefaultRouter) ListRule() []Route {
	return nil
}

func (DefaultRouter) Start() error {
	return nil
}

func (DefaultRouter) Close() error {
	return nil
}
