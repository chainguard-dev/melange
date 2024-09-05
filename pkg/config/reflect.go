package config

import (
	"reflect"
	"strings"
)

// replace takes the given T and recursively walks it, replacing any strings it encounters inside structs, maps, slices, etc with the given replacer.
func replace[T any](r *strings.Replacer, in T) T {
	return replaceValue(r, reflect.ValueOf(in)).Interface().(T)
}

func replaceValue(r *strings.Replacer, in reflect.Value) reflect.Value {
	switch in.Kind() {
	case reflect.String:
		return reflect.ValueOf(r.Replace(in.String()))
	case reflect.Struct:
		out := reflect.New(in.Type()).Elem()
		for i := 0; i < in.NumField(); i++ {
			if out.Field(i).CanSet() {
				out.Field(i).Set(replaceValue(r, in.Field(i)))
			}
		}
		return out
	case reflect.Map:
		if in.IsNil() {
			return in
		}
		out := reflect.MakeMap(in.Type())
		for _, key := range in.MapKeys() {
			out.SetMapIndex(key, replaceValue(r, in.MapIndex(key)))
		}
		return out
	case reflect.Slice:
		if in.IsNil() {
			return in
		}
		out := reflect.MakeSlice(in.Type(), in.Len(), in.Cap())
		for i := 0; i < in.Len(); i++ {
			out.Index(i).Set(replaceValue(r, in.Index(i)))
		}
		return out
	case reflect.Array:
		out := reflect.New(in.Type()).Elem()
		for i := 0; i < in.Len(); i++ {
			out.Index(i).Set(replaceValue(r, in.Index(i)))
		}
		return out
	case reflect.Ptr:
		if in.IsNil() {
			return in
		}
		return replaceValue(r, in.Elem()).Addr()
	default:
		return in
	}
}
