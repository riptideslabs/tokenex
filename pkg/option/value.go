// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package option

type (
	ValueOption[T any] interface {
		ID() any
		Value() T
	}
	valueOption[T any] struct {
		Option
		id any
		v  T
	}
)

func (o *valueOption[T]) ID() any {
	return o.id
}

func (o *valueOption[T]) Value() T {
	return o.v
}
