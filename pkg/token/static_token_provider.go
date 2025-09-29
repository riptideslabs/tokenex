// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package token

import (
	"context"
	"sync"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
)

// StaticIdentityTokenProvider is a simple implementation of IdentityTokenProvider that holds a static token.
// The token can be updated using the SetToken method.
type StaticIdentityTokenProvider struct {
	mu    sync.RWMutex
	token string
}

type Token struct {
	Token string
}

// NewStaticIdentityTokenProvider creates a new StaticTokenProvider with the given initial token.
func NewStaticIdentityTokenProvider(token string) *StaticIdentityTokenProvider {
	return &StaticIdentityTokenProvider{
		token: token,
	}
}

// GetToken returns the current token.
func (s *StaticIdentityTokenProvider) GetToken(ctx context.Context, opts ...option.Option) (credential.Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return credential.Token{
		Token: s.token,
	}, nil
}

// SetToken updates the token in a thread-safe manner.
func (s *StaticIdentityTokenProvider) SetToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.token = token
}

// Ensure StaticTokenProvider implements IdentityTokenProvider.
var _ IdentityTokenProvider = (*StaticIdentityTokenProvider)(nil)
