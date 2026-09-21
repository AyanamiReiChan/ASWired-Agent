//go:build !linux

package updater

import (
	"context"
	"errors"
)

func Supervise(context.Context, string, string) error {
	return errors.New("Agent 自更新监督进程仅支持 Linux")
}
