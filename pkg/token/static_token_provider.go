// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package token

import (
	"context"
	"sync"

	"emperror.dev/errors"
	"github.com/golang-jwt/jwt/v5"

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

	jwtParser := jwt.NewParser()
	t, _, err := jwtParser.ParseUnverified(s.token, jwt.MapClaims{})
	if err != nil {
		return credential.Token{}, errors.WrapIf(err, "failed to parse token")
	}

	if t.Claims == nil {
		return credential.Token{}, errors.New("token has no claims")
	}

	exp, err := t.Claims.GetExpirationTime()
	if err != nil {
		return credential.Token{}, errors.WrapIf(err, "failed to get token expiration time")
	}

	return credential.Token{
		Token:     t.Raw,
		ExpiresAt: exp.Time,
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
