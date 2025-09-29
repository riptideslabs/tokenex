// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package token

import (
	"context"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
)

// IdentityTokenProvider provides ID tokens for access token exchange.
type IdentityTokenProvider interface {
	// GetToken returns the current valid ID token.
	// It should handle refreshing internally if needed.
	GetToken(ctx context.Context, opts ...option.Option) (credential.Token, error)
}

// IdentityTokenProviderFunc is a function type that implements the IdentityTokenProvider interface.
// This allows using a function directly as an IdentityTokenProvider without creating a new struct type.
type IdentityTokenProviderFunc func(context.Context, ...option.Option) (credential.Token, error)

// GetToken implements the IdentityTokenProvider interface by calling the function itself.
func (f IdentityTokenProviderFunc) GetToken(ctx context.Context, opts ...option.Option) (credential.Token, error) {
	return f(ctx, opts...)
}
