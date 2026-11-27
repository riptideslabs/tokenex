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

	"emperror.dev/errors"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
)

const validTokenResponse = `{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":3600}`

type memStore struct {
	mu   sync.Mutex
	tok  *oauth2.Token
	gets int
}

func (s *memStore) Get(context.Context, string) (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.gets++

	if s.tok == nil {
		return nil, errors.New("no token")
	}

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

func newTestProvider(t *testing.T, store TokenStorage, baseURL string, opts ...option.Option) *credentialsProvider {
	t.Helper()

	cp, err := NewCredentialsProvider("id", nil, store, &CredentialsConfig{
		AuthorizationEndpointURL: baseURL + "/authorize",
		TokenEndpointURL:         baseURL + "/token",
		SecretRef:                SecretRef{Name: "name", Namespace: "namespace", Key: "key"},
		RedirectURL:              "https://app.example.com/callback",
	}, logr.Discard(), opts...)
	require.NoError(t, err)

	cp.clientID = "client"
	cp.clientSecret = "secret"

	return cp
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

	cp := newTestProvider(t, store, srv.URL)
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

// A refresh answered with an expiry in the past gives subscribers an error,
// not the expired token.
func TestRefresherDoesNotPublishExpiredToken(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":-5}`) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	store := &memStore{tok: &oauth2.Token{AccessToken: "at", RefreshToken: "rt", Expiry: time.Now().Add(-time.Minute)}}

	cp := newTestProvider(t, store, srv.URL)
	cp.syncGate.Open()

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()

	ch, err := cp.GetCredentials(ctx)
	require.NoError(t, err)

	cp.tokenRefresherLoop(ctx)

	select {
	case res := <-ch:
		require.ErrorContains(t, res.Err, "already expired")
		assert.Nil(t, res.Credential)
	default:
		t.Fatal("nothing was published")
	}
}

// A token that lives for less than the wait above is still refreshed when it expires.
func TestRefresherRefreshesShortLivedToken(t *testing.T) {
	t.Parallel()

	expired := &oauth2.Token{AccessToken: "at", RefreshToken: "rt", Expiry: time.Now().Add(-time.Minute)}

	_, requests := runRefresher(t, 1800*time.Millisecond, expired, `{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":1}`)
	assert.GreaterOrEqual(t, requests, int64(2))
}

// The sweeper is not the only thing that keeps an old state from being used.
func TestAuthStateExpires(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, validTokenResponse) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	cp := newTestProvider(t, &memStore{}, srv.URL, WithAuthStateTTL(50*time.Millisecond))

	state, _ := cp.AuthCodeURL(t.Context())

	_, err := cp.Authorize(t.Context(), state, "code")
	require.NoError(t, err)

	_, err = cp.Authorize(t.Context(), state, "code")
	require.ErrorIs(t, err, ErrUnknownAuthState, "a state was used twice")

	state, _ = cp.AuthCodeURL(t.Context())

	time.Sleep(100 * time.Millisecond)

	_, err = cp.Authorize(t.Context(), state, "code")
	require.ErrorIs(t, err, ErrUnknownAuthState, "an expired state was used")
	assert.EqualValues(t, 1, requests.Load())
}

func TestNewSubscriberGetsOnlyAValidToken(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		expiry time.Time
		want   bool
	}{
		"valid":   {time.Now().Add(time.Hour), true},
		"expired": {time.Now().Add(-time.Minute), false},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := &memStore{tok: &oauth2.Token{AccessToken: "at", RefreshToken: "rt", Expiry: tc.expiry}}

			ch, err := newTestProvider(t, store, "https://idp.example.com").GetCredentials(t.Context())
			require.NoError(t, err)

			select {
			case cred := <-ch:
				require.True(t, tc.want, "received an expired token")
				require.NotNil(t, cred.Credential)
			default:
				require.False(t, tc.want, "received no token")
			}
		})
	}
}

func TestCancelledSubscriberIsDropped(t *testing.T) {
	t.Parallel()

	cp := newTestProvider(t, &memStore{}, "https://idp.example.com")

	ctx, cancel := context.WithCancel(t.Context())

	ch, err := cp.GetCredentials(ctx)
	require.NoError(t, err)

	cancel()

	assert.Eventually(t, func() bool {
		cp.publishCredential(Credential{Event: credential.UpdateEventType})

		select {
		case <-ch:
			return false
		case <-time.After(20 * time.Millisecond):
			return true
		}
	}, 2*time.Second, time.Millisecond, "a cancelled subscriber still receives credentials")
}

// A consumer may take the buffered event just as the sender finds the channel
// full. The sender must not then wait for an event only it can send.
func TestSendStatusEventNeverWaitsForItself(t *testing.T) {
	t.Parallel()

	const (
		rounds = 100
		sends  = 2000
	)

	for range rounds {
		cp := newTestProvider(t, &memStore{}, "https://idp.example.com")
		done := make(chan struct{})

		go func() {
			defer close(done)

			for range sends {
				cp.sendStatusEvent(StatusEvent{Event: AuthorizedStatusEvent})
			}
		}()

		stuck := time.After(10 * time.Second)

		for running := true; running; {
			select {
			case <-done:
				running = false
			case <-cp.statusCh:
			case <-stuck:
				t.Fatal("sender is blocked with nothing to receive")
			}
		}
	}
}
