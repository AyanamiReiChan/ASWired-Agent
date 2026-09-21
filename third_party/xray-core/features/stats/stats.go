package stats

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features"
)

type Counter interface {
	Value() int64

	Set(int64) int64

	Add(int64) int64
}

type OnlineMap interface {
	Count() int

	AddIP(string)

	RemoveIP(string)

	List() []string

	IPTimeMap() map[string]time.Time
}

type Channel interface {
	common.Runnable

	Publish(context.Context, interface{})

	Subscribers() []chan interface{}

	Subscribe() (chan interface{}, error)

	Unsubscribe(chan interface{}) error
}

func SubscribeRunnableChannel(c Channel) (chan interface{}, error) {
	if len(c.Subscribers()) == 0 {
		if err := c.Start(); err != nil {
			return nil, err
		}
	}
	return c.Subscribe()
}

func UnsubscribeClosableChannel(c Channel, sub chan interface{}) error {
	if err := c.Unsubscribe(sub); err != nil {
		return err
	}
	if len(c.Subscribers()) == 0 {
		return c.Close()
	}
	return nil
}

type Manager interface {
	features.Feature

	RegisterCounter(string) (Counter, error)

	UnregisterCounter(string) error

	GetCounter(string) Counter

	RegisterOnlineMap(string) (OnlineMap, error)

	UnregisterOnlineMap(string) error

	GetOnlineMap(string) OnlineMap

	RegisterChannel(string) (Channel, error)

	UnregisterChannel(string) error

	GetChannel(string) Channel

	GetAllOnlineUsers() []string
}

func GetOrRegisterCounter(m Manager, name string) (Counter, error) {
	counter := m.GetCounter(name)
	if counter != nil {
		return counter, nil
	}

	return m.RegisterCounter(name)
}

func GetOrRegisterOnlineMap(m Manager, name string) (OnlineMap, error) {
	onlineMap := m.GetOnlineMap(name)
	if onlineMap != nil {
		return onlineMap, nil
	}

	return m.RegisterOnlineMap(name)
}

func GetOrRegisterChannel(m Manager, name string) (Channel, error) {
	channel := m.GetChannel(name)
	if channel != nil {
		return channel, nil
	}

	return m.RegisterChannel(name)
}

func ManagerType() interface{} {
	return (*Manager)(nil)
}

type NoopManager struct{}

func (NoopManager) Type() interface{} {
	return ManagerType()
}

func (NoopManager) RegisterCounter(string) (Counter, error) {
	return nil, errors.New("not implemented")
}

func (NoopManager) UnregisterCounter(string) error {
	return nil
}

func (NoopManager) GetCounter(string) Counter {
	return nil
}

func (NoopManager) RegisterOnlineMap(string) (OnlineMap, error) {
	return nil, errors.New("not implemented")
}

func (NoopManager) UnregisterOnlineMap(string) error {
	return nil
}

func (NoopManager) GetOnlineMap(string) OnlineMap {
	return nil
}

func (NoopManager) RegisterChannel(string) (Channel, error) {
	return nil, errors.New("not implemented")
}

func (NoopManager) UnregisterChannel(string) error {
	return nil
}

func (NoopManager) GetChannel(string) Channel {
	return nil
}

func (NoopManager) GetAllOnlineUsers() []string {
	return nil
}

func (NoopManager) Start() error { return nil }

func (NoopManager) Close() error { return nil }
