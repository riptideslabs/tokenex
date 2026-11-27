// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package oauth2ac //nolint:testpackage // Tests use unexported functions

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type memStore struct {
	mu   sync.Mutex
	tok  *oauth2.Token
	gets int
}

func (s *memStore) Get(context.Context, string) (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.gets++
	tok := *s.tok

	return &tok, nil
}

func (s *memStore) Store(_ context.Context, _ string, tok *oauth2.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tok = tok

	return nil
}

func (s *memStore) Delete(context.Context, string) error {
	return nil
}

// runRefresher runs the refresh loop of an authorized provider for a while and
// returns how often it read the token store and called the token endpoint.
func runRefresher(t *testing.T, runFor time.Duration, stored *oauth2.Token, tokenResponse string) (int, int64) {
	t.Helper()

	var requests atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, tokenResponse) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	store := &memStore{tok: stored}

	cp, err := NewCredentialsProvider("id", nil, store, &CredentialsConfig{
		AuthorizationEndpointURL: srv.URL + "/authorize",
		TokenEndpointURL:         srv.URL + "/token",
		SecretRef:                SecretRef{Name: "name", Namespace: "namespace", Key: "key"},
		RedirectURL:              "https://app.example.com/callback",
	}, logr.Discard())
	require.NoError(t, err)

	cp.clientID = "client"
	cp.clientSecret = "secret"
	cp.syncGate.Open()

	ctx, cancel := context.WithTimeout(t.Context(), runFor)
	defer cancel()

	cp.tokenRefresherLoop(ctx)

	store.mu.Lock()
	defer store.mu.Unlock()

	return store.gets, requests.Load()
}

func TestRefresherDoesNotSpin(t *testing.T) {
	t.Parallel()

	t.Run("token without an expiry", func(t *testing.T) {
		t.Parallel()

		gets, requests := runRefresher(t, 300*time.Millisecond, &oauth2.Token{AccessToken: "at", RefreshToken: "rt"}, "")
		assert.Equal(t, 1, gets)
		assert.Zero(t, requests)
	})

	t.Run("refresh answered with an expiry in the past", func(t *testing.T) {
		t.Parallel()

		expired := &oauth2.Token{AccessToken: "at", RefreshToken: "rt", Expiry: time.Now().Add(-time.Minute)}

		_, requests := runRefresher(t, 300*time.Millisecond, expired, `{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":-5}`)
		assert.EqualValues(t, 1, requests)
	})
}

// A token that lives for less than the wait above is still refreshed when it expires.
func TestRefresherRefreshesShortLivedToken(t *testing.T) {
	t.Parallel()

	expired := &oauth2.Token{AccessToken: "at", RefreshToken: "rt", Expiry: time.Now().Add(-time.Minute)}

	_, requests := runRefresher(t, 1800*time.Millisecond, expired, `{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":1}`)
	assert.GreaterOrEqual(t, requests, int64(2))
}
