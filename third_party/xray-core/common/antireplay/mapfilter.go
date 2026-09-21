package antireplay

import (
	"sync"
	"time"
)

type ReplayFilter[T comparable] struct {
	lock      sync.Mutex
	poolA     map[T]struct{}
	poolB     map[T]struct{}
	interval  time.Duration
	lastClean time.Time
}

func NewMapFilter[T comparable](interval int64) *ReplayFilter[T] {
	filter := &ReplayFilter[T]{
		poolA:     make(map[T]struct{}),
		poolB:     make(map[T]struct{}),
		interval:  time.Duration(interval) * time.Second,
		lastClean: time.Now(),
	}
	return filter
}

func (filter *ReplayFilter[T]) Check(sum T) bool {
	filter.lock.Lock()
	defer filter.lock.Unlock()

	now := time.Now()
	if now.Sub(filter.lastClean) >= filter.interval {
		filter.poolB = filter.poolA
		filter.poolA = make(map[T]struct{})
		filter.lastClean = now
	}

	_, existsA := filter.poolA[sum]
	_, existsB := filter.poolB[sum]
	if !existsA && !existsB {
		filter.poolA[sum] = struct{}{}
	}
	return !(existsA || existsB)
}
