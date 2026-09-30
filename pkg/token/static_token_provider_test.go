// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package token_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.riptides.io/tokenex/pkg/token"
)

func newJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-key"))
	require.NoError(t, err)

	return s
}

func TestStaticIdentityTokenProvider_GetToken(t *testing.T) {
	t.Parallel()

	exp := time.Now().Add(time.Hour)

	tests := []struct {
		name          string
		token         string
		wantExpiresAt time.Time
		wantErr       bool
	}{
		{
			name:          "with exp",
			token:         newJWT(t, jwt.MapClaims{"sub": "workload", "exp": exp.Unix()}),
			wantExpiresAt: time.Unix(exp.Unix(), 0),
		},
		{
			name:  "without exp never expires",
			token: newJWT(t, jwt.MapClaims{"sub": "workload"}),
		},
		{
			name:    "not a JWT",
			token:   "not-a-jwt",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tok, err := token.NewStaticIdentityTokenProvider(tt.token).GetToken(t.Context())
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.token, tok.Token)
			assert.True(t, tt.wantExpiresAt.Equal(tok.ExpiresAt), "ExpiresAt = %v, want %v", tok.ExpiresAt, tt.wantExpiresAt)
		})
	}
}
