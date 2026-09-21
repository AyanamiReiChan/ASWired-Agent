package task

import "github.com/xtls/xray-core/common"

func Close(v interface{}) func() error {
	return func() error {
		return common.Close(v)
	}
}
