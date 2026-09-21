package ctx

import "context"

type SessionKey int

type ID uint32

const (
	idSessionKey SessionKey = 0
)

func ContextWithID(ctx context.Context, id ID) context.Context {
	return context.WithValue(ctx, idSessionKey, id)
}

func IDFromContext(ctx context.Context) ID {
	if id, ok := ctx.Value(idSessionKey).(ID); ok {
		return id
	}
	return 0
}
