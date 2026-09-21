package confloader

import (
	"context"
	"io"
	"os"

	"github.com/xtls/xray-core/common/errors"
)

type (
	configFileLoader func(string) (io.Reader, error)
)

var (
	EffectiveConfigFileLoader configFileLoader
)

func LoadConfig(file string) (io.Reader, error) {
	if EffectiveConfigFileLoader == nil {
		errors.LogInfo(context.Background(), "external config module not loaded, reading from stdin")
		return os.Stdin, nil
	}
	return EffectiveConfigFileLoader(file)
}
