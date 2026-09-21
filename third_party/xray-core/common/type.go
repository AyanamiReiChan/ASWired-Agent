package common

import (
	"context"
	"reflect"

	"github.com/xtls/xray-core/common/errors"
)

type ConfigCreator func(ctx context.Context, config interface{}) (interface{}, error)

var typeCreatorRegistry = make(map[reflect.Type]ConfigCreator)

func RegisterConfig(config interface{}, configCreator ConfigCreator) error {
	configType := reflect.TypeOf(config)
	if _, found := typeCreatorRegistry[configType]; found {
		return errors.New(configType.Name() + " is already registered").AtError()
	}
	typeCreatorRegistry[configType] = configCreator
	return nil
}

func CreateObject(ctx context.Context, config interface{}) (interface{}, error) {
	configType := reflect.TypeOf(config)
	creator, found := typeCreatorRegistry[configType]
	if !found {
		return nil, errors.New(configType.String() + " is not registered").AtError()
	}
	return creator(ctx, config)
}
