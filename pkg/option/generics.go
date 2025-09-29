// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package option

import (
	"time"
)

type CurrentTimeFunc func() time.Time

func WithCurrentTimeFunc(id any, f CurrentTimeFunc) Option {
	return &valueOption[CurrentTimeFunc]{OptionImpl{}, id, f}
}

func IsCurrentTimeFuncOption(opt any) (ValueOption[CurrentTimeFunc], bool) {
	if o, ok := opt.(*valueOption[CurrentTimeFunc]); ok {
		return o, ok
	}

	return nil, false
}

func WithBoolean(id any, v bool) Option {
	return &valueOption[bool]{OptionImpl{}, id, v}
}

func IsBooleanOption(opt any) (ValueOption[bool], bool) {
	if o, ok := opt.(*valueOption[bool]); ok {
		return o, ok
	}

	return nil, false
}

func WithDuration(id any, d time.Duration) Option {
	return &valueOption[time.Duration]{OptionImpl{}, id, d}
}

func IsDurationOption(opt any) (ValueOption[time.Duration], bool) {
	if o, ok := opt.(*valueOption[time.Duration]); ok {
		return o, ok
	}

	return nil, false
}

func WithString(id any, value string) Option {
	return &valueOption[string]{OptionImpl{}, id, value}
}

func IsStringOption(opt any) (ValueOption[string], bool) {
	if o, ok := opt.(*valueOption[string]); ok {
		return o, ok
	}

	return nil, false
}

func WithStringSlice(id any, value []string) Option {
	return &valueOption[[]string]{OptionImpl{}, id, value}
}

func IsStringSliceOption(opt any) (ValueOption[[]string], bool) {
	if o, ok := opt.(*valueOption[[]string]); ok {
		return o, ok
	}

	return nil, false
}

func WithStringMap(id any, value map[string]string) Option {
	return &valueOption[map[string]string]{OptionImpl{}, id, value}
}

func IsStringMapOption(opt any) (ValueOption[map[string]string], bool) {
	if o, ok := opt.(*valueOption[map[string]string]); ok {
		return o, ok
	}

	return nil, false
}

func WithAnyMap(id any, value map[string]any) Option {
	return &valueOption[map[string]any]{OptionImpl{}, id, value}
}

func IsAnyMapOption(opt any) (ValueOption[map[string]any], bool) {
	if o, ok := opt.(*valueOption[map[string]any]); ok {
		return o, ok
	}

	return nil, false
}
