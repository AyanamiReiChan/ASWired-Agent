package core

import (
	"context"
)

type XrayKey int

const xrayKey XrayKey = 1

func FromContext(ctx context.Context) *Instance {
	if s, ok := ctx.Value(xrayKey).(*Instance); ok {
		return s
	}
	return nil
}

func MustFromContext(ctx context.Context) *Instance {
	x := FromContext(ctx)
	if x == nil {
		panic("X is not in context.")
	}
	return x
}

func toContext(ctx context.Context, v *Instance) context.Context {
	if FromContext(ctx) != v {
		ctx = context.WithValue(ctx, xrayKey, v)
	}
	return ctx
}

func ToBackgroundDetachedContext(ctx context.Context) context.Context {
	instance := MustFromContext(ctx)
	return toContext(context.Background(), instance)
}
