package grpc

import (
	"net/url"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}

func (c *Config) getServiceName() string {

	if !strings.HasPrefix(c.ServiceName, "/") {
		return url.PathEscape(c.ServiceName)
	}

	lastIndex := strings.LastIndex(c.ServiceName, "/")
	if lastIndex < 1 {
		lastIndex = 1
	}
	rawServiceName := c.ServiceName[1:lastIndex]
	serviceNameParts := strings.Split(rawServiceName, "/")
	for i := range serviceNameParts {
		serviceNameParts[i] = url.PathEscape(serviceNameParts[i])
	}
	return strings.Join(serviceNameParts, "/")
}

func (c *Config) getTunStreamName() string {

	if !strings.HasPrefix(c.ServiceName, "/") {
		return "Tun"
	}

	endingPath := c.ServiceName[strings.LastIndex(c.ServiceName, "/")+1:]
	return url.PathEscape(strings.Split(endingPath, "|")[0])
}

func (c *Config) getTunMultiStreamName() string {

	if !strings.HasPrefix(c.ServiceName, "/") {
		return "TunMulti"
	}

	endingPath := c.ServiceName[strings.LastIndex(c.ServiceName, "/")+1:]
	streamNames := strings.Split(endingPath, "|")
	if len(streamNames) == 1 {
		return url.PathEscape(streamNames[0])
	} else {
		return url.PathEscape(streamNames[1])
	}
}
