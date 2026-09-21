package blackhole

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

const (
	http403response = `HTTP/1.1 403 Forbidden
Connection: close
Cache-Control: max-age=3600, public
Content-Length: 0


`
)

type ResponseConfig interface {
	WriteTo(buf.Writer) int32
}

func (*NoneResponse) WriteTo(buf.Writer) int32 { return 0 }

func (*HTTPResponse) WriteTo(writer buf.Writer) int32 {
	b := buf.New()
	common.Must2(b.WriteString(http403response))
	n := b.Len()
	writer.WriteMultiBuffer(buf.MultiBuffer{b})
	return n
}

func (c *Config) GetInternalResponse() (ResponseConfig, error) {
	if c.GetResponse() == nil {
		return new(NoneResponse), nil
	}

	config, err := c.GetResponse().GetInstance()
	if err != nil {
		return nil, err
	}
	return config.(ResponseConfig), nil
}
