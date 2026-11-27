// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package generic_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/generic"
	"go.riptides.io/tokenex/pkg/option"
)

type expiredTokenProvider struct{}

func (expiredTokenProvider) GetToken(context.Context, ...option.Option) (credential.Token, error) {
	return credential.Token{Token: "token", ExpiresAt: time.Now().Add(-time.Minute)}, nil
}

func TestExpiredTokenIsNotPublished(t *testing.T) {
	t.Parallel()

	// A slow logger gives the reader time to see each result before the next one replaces it.
	logger := funcr.New(func(string, string) { time.Sleep(20 * time.Millisecond) }, funcr.Options{Verbosity: 2})

	cp, err := generic.NewCredentialsProvider(t.Context(), logger)
	require.NoError(t, err)

	ch, err := cp.GetCredentials(t.Context(), expiredTokenProvider{})
	require.NoError(t, err)

	got := make([]credential.Result, 0, 1)
	for res := range ch {
		got = append(got, res)
	}

	require.Len(t, got, 1)
	require.Error(t, got[0].Err)
	assert.Nil(t, got[0].Credential)
}
