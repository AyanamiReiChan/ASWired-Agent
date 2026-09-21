package tun

import (
	"time"
)

type Stack interface {
	Start() error
	Close() error
}

type StackOptions struct {
	Tun         Tun
	IdleTimeout time.Duration
}
