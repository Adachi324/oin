package openapi

import (
	"fmt"
	"reflect"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gogf/gf/v2/util/gconv"
)

type EnumAble interface {
	Enums() map[string]any
}

func NewEnumSchema(name string, kind reflect.Kind) *openapi3.Schema {
	switch kind {
	case reflect.Bool:
		return openapi3.NewBoolSchema()
	case reflect.Int8, reflect.Int16, reflect.Int, reflect.Uint8, reflect.Uint16, reflect.Uint:
		return openapi3.NewIntegerSchema()
	case reflect.Int32, reflect.Uint32:
		return openapi3.NewInt32Schema()
	case reflect.Int64, reflect.Uint64:
		return openapi3.NewInt64Schema()
	case reflect.Float32:
		schema := openapi3.NewFloat64Schema()
		schema.Format = "float"
		return schema
	case reflect.Float64:
		schema := openapi3.NewFloat64Schema()
		schema.Format = "double"
		return schema
	case reflect.String:
		return openapi3.NewStringSchema()
	default:
		panic(fmt.Errorf("'%s' invalid Enum type: %d", name, kind))
	}
}

func GetEnumVal(name string, kind reflect.Kind, val any) any {
	switch kind {
	case reflect.Bool:
		return gconv.Bool(val)
	case reflect.Int8:
		return gconv.Int8(val)
	case reflect.Int16:
		return gconv.Int16(val)
	case reflect.Int:
		return gconv.Int(val)
	case reflect.Uint8:
		return gconv.Uint8(val)
	case reflect.Uint16:
		return gconv.Uint16(val)
	case reflect.Uint:
		return gconv.Uint(val)
	case reflect.Int32:
		return gconv.Int32(val)
	case reflect.Uint32:
		return gconv.Uint32(val)
	case reflect.Int64:
		return gconv.Int64(val)
	case reflect.Uint64:
		return gconv.Uint64(val)
	case reflect.Float32:
		return gconv.Float32(val)
	case reflect.Float64:
		return gconv.Float64(val)
	case reflect.String:
		return gconv.String(val)
	default:
		panic(fmt.Errorf("'%s' invalid Enum val: %v", name, val))
	}
}
