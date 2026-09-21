package features

import (
	"github.com/xtls/xray-core/common"
)

type Feature interface {
	common.HasType
	common.Runnable
}
