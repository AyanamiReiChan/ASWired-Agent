package transport

import "github.com/xtls/xray-core/common/buf"

type Link struct {
	Reader buf.Reader
	Writer buf.Writer
}
