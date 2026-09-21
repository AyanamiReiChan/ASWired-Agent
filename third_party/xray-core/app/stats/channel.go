package stats

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
)

type Channel struct {
	channel     chan channelMessage
	subscribers []chan interface{}

	access sync.RWMutex
	closed chan struct{}

	blocking   bool
	bufferSize int
	subsLimit  int
}

func NewChannel(config *ChannelConfig) *Channel {
	return &Channel{
		channel:    make(chan channelMessage, config.BufferSize),
		subsLimit:  int(config.SubscriberLimit),
		bufferSize: int(config.BufferSize),
		blocking:   config.Blocking,
	}
}

func (c *Channel) Subscribers() []chan interface{} {
	c.access.RLock()
	defer c.access.RUnlock()
	return c.subscribers
}

func (c *Channel) Subscribe() (chan interface{}, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.subsLimit > 0 && len(c.subscribers) >= c.subsLimit {
		return nil, errors.New("Number of subscribers has reached limit")
	}
	subscriber := make(chan interface{}, c.bufferSize)
	c.subscribers = append(c.subscribers, subscriber)
	return subscriber, nil
}

func (c *Channel) Unsubscribe(subscriber chan interface{}) error {
	c.access.Lock()
	defer c.access.Unlock()
	for i, s := range c.subscribers {
		if s == subscriber {

			subscribers := make([]chan interface{}, len(c.subscribers)-1)
			copy(subscribers[:i], c.subscribers[:i])
			copy(subscribers[i:], c.subscribers[i+1:])
			c.subscribers = subscribers
		}
	}
	return nil
}

func (c *Channel) Publish(ctx context.Context, msg interface{}) {
	select {
	case <-c.closed:
		return
	default:
		pub := channelMessage{context: ctx, message: msg}
		if c.blocking {
			pub.publish(c.channel)
		} else {
			pub.publishNonBlocking(c.channel)
		}
	}
}

func (c *Channel) Running() bool {
	select {
	case <-c.closed:
	default:
		if c.closed != nil {
			return true
		}
	}
	return false
}

func (c *Channel) Start() error {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.Running() {
		c.closed = make(chan struct{})
		go func() {
			for {
				select {
				case pub := <-c.channel:
					for _, sub := range c.Subscribers() {
						if c.blocking {
							pub.broadcast(sub)
						} else {
							pub.broadcastNonBlocking(sub)
						}
					}
				case <-c.closed:
					for _, sub := range c.Subscribers() {
						common.Must(c.Unsubscribe(sub))
						close(sub)
					}
					return
				}
			}
		}()
	}
	return nil
}

func (c *Channel) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.Running() {
		close(c.closed)
	}
	return nil
}

type channelMessage struct {
	context context.Context
	message interface{}
}

func (c channelMessage) publish(publisher chan channelMessage) {
	select {
	case publisher <- c:
	case <-c.context.Done():
	}
}

func (c channelMessage) publishNonBlocking(publisher chan channelMessage) {
	select {
	case publisher <- c:
	default:
		go c.publish(publisher)
	}
}

func (c channelMessage) broadcast(subscriber chan interface{}) {
	select {
	case subscriber <- c.message:
	case <-c.context.Done():
	}
}

func (c channelMessage) broadcastNonBlocking(subscriber chan interface{}) {
	select {
	case subscriber <- c.message:
	default:
		go c.broadcast(subscriber)
	}
}
