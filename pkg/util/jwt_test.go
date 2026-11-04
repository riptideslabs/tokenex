// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package util_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.riptides.io/tokenex/pkg/util"
)

func TestDecodeJWTClaims(t *testing.T) {
	t.Parallel()

	exp := time.Now().Add(time.Hour).Unix()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "workload",
		"aud": []string{"a", "b"},
		"iss": "https://issuer",
		"exp": exp,
	}).SignedString([]byte("test-key"))
	require.NoError(t, err)

	claims, err := util.DecodeJWTClaims(signed)
	require.NoError(t, err)

	sub, err := claims.GetSubject()
	require.NoError(t, err)
	assert.Equal(t, "workload", sub)

	aud, err := claims.GetAudience()
	require.NoError(t, err)
	assert.Equal(t, jwt.ClaimStrings{"a", "b"}, aud)

	iss, err := claims.GetIssuer()
	require.NoError(t, err)
	assert.Equal(t, "https://issuer", iss)

	gotExp, err := claims.GetExpirationTime()
	require.NoError(t, err)
	require.NotNil(t, gotExp)
	assert.Equal(t, exp, gotExp.Unix())
}

func TestDecodeJWTClaims_Invalid(t *testing.T) {
	t.Parallel()

	enc := base64.RawURLEncoding.EncodeToString

	tests := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "not a jwt", token: "opaque-token"},
		{name: "two segments", token: enc([]byte(`{}`)) + "." + enc([]byte(`{}`))},
		{name: "four segments", token: "a.b.c.d"},
		{name: "bad base64 payload", token: enc([]byte(`{}`)) + ".!!!.sig"},
		{name: "payload not json", token: enc([]byte(`{}`)) + "." + enc([]byte(`nope`)) + ".sig"},
		{name: "payload not object", token: enc([]byte(`{}`)) + "." + enc([]byte(`[1]`)) + ".sig"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := util.DecodeJWTClaims(tt.token)
			assert.Error(t, err)
		})
	}
}
