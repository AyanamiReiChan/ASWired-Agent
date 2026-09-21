// SPDX-License-Identifier: MPL-2.0

package aswired

import (
	"context"
	"github.com/xtls/xray-core/common/session"
	"sync"
	"sync/atomic"
)

type Controller interface {
	AdmitSession(ctx context.Context, email, ip string, terminate func()) (release func(), err error)
	Transfer(ctx context.Context, email string, bytes int64) error
}
type DirectionalController interface {
	TransferDirection(context.Context, string, int64, string) error
}
type UnboundedController interface {
	BeginUnboundedSplice(context.Context, string, func()) (func(), bool)
}

type SpliceObserver interface{ ObserveSplice(string, bool, int64) }

// Record only bytes that actually traversed CopyRawConn's splice branch.
func ObserveSplice(ctx context.Context, direction string, limited bool, bytes int64) {
	h := active.Load()
	if h == nil || bytes <= 0 {
		return
	}
	email, _ := identity(ctx)
	if email == "" {
		return
	}
	if observer, ok := h.controller.(SpliceObserver); ok {
		observer.ObserveSplice(direction, limited, bytes)
	}
}

type holder struct{ controller Controller }

var active atomic.Pointer[holder]

func Install(c Controller) {
	if c == nil {
		active.Store(nil)
	} else {
		active.Store(&holder{c})
	}
}
func identity(ctx context.Context) (string, string) {
	in := session.InboundFromContext(ctx)
	if in == nil || in.User == nil {
		return "", ""
	}
	ip := ""
	if in.Source.Address != nil {
		ip = in.Source.Address.String()
	}
	return in.User.Email, ip
}

type admittedKey struct{}

func Admit(ctx context.Context) (context.Context, error) {
	h := active.Load()
	if h == nil || ctx.Value(admittedKey{}) != nil {
		return ctx, nil
	}
	email, ip := identity(ctx)
	if email == "" {
		return ctx, nil
	}
	managedCtx, cancel := context.WithCancel(ctx)
	var once sync.Once
	terminate := func() {
		once.Do(func() {
			cancel()
			if in := session.InboundFromContext(ctx); in != nil && in.Conn != nil {
				_ = in.Conn.Close()
			}
		})
	}
	release, err := h.controller.AdmitSession(managedCtx, email, ip, terminate)
	if err != nil {
		cancel()
		return ctx, err
	}
	context.AfterFunc(managedCtx, release)
	return context.WithValue(managedCtx, admittedKey{}, true), nil
}
func Managed(ctx context.Context) bool {
	email, _ := identity(ctx)
	return email != "" && active.Load() != nil
}

func TryUnboundedSplice(ctx context.Context) (func(), bool) {
	h := active.Load()
	email, _ := identity(ctx)
	if h == nil || email == "" {
		return func() {}, true
	}
	controller, ok := h.controller.(UnboundedController)
	if !ok {
		return nil, false
	}
	return controller.BeginUnboundedSplice(ctx, email, func() {
		if in := session.InboundFromContext(ctx); in != nil && in.Conn != nil {
			_ = in.Conn.Close()
		}
	})
}
func Transfer(ctx context.Context, n int64) error {
	return TransferDirection(ctx, n, "both")
}
func TransferDirection(ctx context.Context, n int64, direction string) error {
	h := active.Load()
	if h == nil || n <= 0 {
		return nil
	}
	email, _ := identity(ctx)
	if email == "" {
		return nil
	}
	if c, ok := h.controller.(DirectionalController); ok {
		return c.TransferDirection(ctx, email, n, direction)
	}
	return h.controller.Transfer(ctx, email, n)
}
