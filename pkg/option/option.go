// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package option

type Option interface {
	IsOption()
}

type OptionImpl struct{}

func (o OptionImpl) IsOption() {}

type OptionID struct {
	id string
}

func NewOptionID(id string) OptionID {
	return OptionID{
		id: id,
	}
}
