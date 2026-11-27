// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package oauth2cc //nolint:testpackage // Tests use the unexported refresh loop

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// runRefresher runs the refresh loop for a while against a token endpoint with
// the given answer and returns what it published, and whether it was still
// running at the end.
func runRefresher(t *testing.T, tokenResponse string) ([]Credential, bool) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, tokenResponse) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	r := &tokenRetriever{
		cfg:          credentialsConfig{tokenEndpointURL: srv.URL, authStyle: oauth2.AuthStyleInParams},
		ch:           make(chan Credential, 1),
		refreshCh:    make(chan struct{}),
		clientID:     "client",
		clientSecret: "secret",
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	stopped := make(chan struct{})

	go func() {
		defer close(stopped)

		r.tokenRefresherLoop(ctx)
	}()

	var got []Credential

	deadline := time.After(300 * time.Millisecond)

	for {
		select {
		case res := <-r.ch:
			got = append(got, res)
		case <-stopped:
			return got, false
		case <-deadline:
			return got, true
		}
	}
}

// expires_in is optional: a token without one is published and kept, not
// followed by an error that ends the subscription.
func TestTokenWithoutExpiryIsKept(t *testing.T) {
	t.Parallel()

	got, running := runRefresher(t, `{"access_token":"at","token_type":"Bearer"}`)

	require.Len(t, got, 1)
	require.NoError(t, got[0].Err)
	assert.NotNil(t, got[0].Credential)
	assert.True(t, running, "the refresh loop ended")
}

func TestExpiredTokenIsNotPublished(t *testing.T) {
	t.Parallel()

	got, running := runRefresher(t, `{"access_token":"at","token_type":"Bearer","expires_in":-5}`)

	require.Len(t, got, 1)
	require.ErrorContains(t, got[0].Err, "already expired")
	assert.Nil(t, got[0].Credential)
	assert.False(t, running)
}
