package utils

import (
	"reflect"
	"unsafe"
)

func AccessField[valueType any](obj any, fieldName string) *valueType {
	field := reflect.ValueOf(obj).Elem().FieldByName(fieldName)
	if field.Type() != reflect.TypeOf(*new(valueType)) {
		panic("field type: " + field.Type().String() + ", valueType: " + reflect.TypeOf(*new(valueType)).String())
	}
	v := (*valueType)(unsafe.Pointer(field.UnsafeAddr()))
	return v
}
