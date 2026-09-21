package stats

import "sync/atomic"

type Counter struct {
	value int64
}

func (c *Counter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

func (c *Counter) Set(newValue int64) int64 {
	return atomic.SwapInt64(&c.value, newValue)
}

func (c *Counter) Add(delta int64) int64 {
	return atomic.AddInt64(&c.value, delta)
}
