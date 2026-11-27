// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package gcp //nolint:testpackage // Tests use the unexported refresh loop

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/oauth2"

	"go.riptides.io/tokenex/internal/httpx"
	"go.riptides.io/tokenex/pkg/credential"
)

func TestExpiredTokenIsNotPublished(t *testing.T) {
	t.Parallel()

	// A slow logger gives the reader time to see each result before the next one replaces it.
	logger := funcr.New(func(string, string) { time.Sleep(20 * time.Millisecond) }, funcr.Options{Verbosity: 2})
	cp := &credentialsProvider{logger: logger}

	expired := func(context.Context) (*oauth2.Token, error) {
		return &oauth2.Token{AccessToken: "at", Expiry: time.Now().Add(-time.Minute)}, nil
	}

	ch := make(chan credential.Result, 1)

	go func() {
		defer close(ch)

		cp.refreshCredentialsLoop(t.Context(), &credentialsConfig{}, expired, ch, noop.NewTracerProvider().Tracer(""))
	}()

	got := make([]credential.Result, 0, 1)
	for res := range ch {
		got = append(got, res)
	}

	require.Len(t, got, 1)
	require.Error(t, got[0].Err)
	assert.Nil(t, got[0].Credential)
}

// The Google API clients have no timeout, so the fetch context carries one.
func TestFetchHasDeadline(t *testing.T) {
	t.Parallel()

	var left time.Duration

	_, err := fetchAccessToken(t.Context(), noop.NewTracerProvider().Tracer("test"), nil,
		func(ctx context.Context) (*oauth2.Token, error) {
			deadline, ok := ctx.Deadline()
			if ok {
				left = time.Until(deadline)
			}

			return &oauth2.Token{AccessToken: "at"}, nil
		}, false)
	require.NoError(t, err)

	assert.Positive(t, left)
	assert.LessOrEqual(t, left, httpx.DefaultTimeout)
}
