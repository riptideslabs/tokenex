// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package githubactions_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/rfc7523"
	"go.riptides.io/tokenex/pkg/token/githubactions"
)

const requestToken = "request-token"

func newJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-key"))
	require.NoError(t, err)

	return s
}

func newIDToken(t *testing.T, exp time.Time) string {
	t.Helper()

	return newJWT(t, jwt.MapClaims{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:riptideslabs/tokenex:ref:refs/heads/main",
		"exp": exp.Unix(),
	})
}

func tokenHandler(value string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"count": len(value), "value": value}) //nolint:errcheck
	}
}

func newServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return srv
}

func newProvider(t *testing.T, srv *httptest.Server, opts ...option.Option) *githubactions.IdentityTokenProvider {
	t.Helper()

	all := append([]option.Option{
		githubactions.WithRequestURL(srv.URL + "/token?api-version=2.0"),
		githubactions.WithRequestToken(requestToken),
		githubactions.WithHTTPClient(srv.Client()),
	}, opts...)

	p, err := githubactions.NewIdentityTokenProvider(all...)
	require.NoError(t, err)

	return p
}

func TestGetToken_RequestShape(t *testing.T) {
	t.Parallel()

	exp := time.Now().Add(10 * time.Minute)
	idToken := newIDToken(t, exp)

	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/token", r.URL.Path)
		assert.Equal(t, "Bearer "+requestToken, r.Header.Get("Authorization"))
		assert.Equal(t, "2.0", r.URL.Query().Get("api-version"))
		assert.Equal(t, "api.anthropic.com", r.URL.Query().Get("audience"))

		tokenHandler(idToken)(w, r)
	})

	p := newProvider(t, srv, githubactions.WithAudience("api.anthropic.com"))

	tok, err := p.GetToken(t.Context())
	require.NoError(t, err)
	assert.Equal(t, idToken, tok.Token)
	assert.Equal(t, exp.Unix(), tok.ExpiresAt.Unix())
}

func TestGetToken_NoAudience(t *testing.T) {
	t.Parallel()

	idToken := newIDToken(t, time.Now().Add(10*time.Minute))

	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.False(t, r.URL.Query().Has("audience"))

		tokenHandler(idToken)(w, r)
	})

	_, err := newProvider(t, srv).GetToken(t.Context())
	require.NoError(t, err)
}

func TestGetToken_Caching(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		ttl          time.Duration
		wantRequests int32
	}{
		{name: "reuses valid token", ttl: 10 * time.Minute, wantRequests: 1},
		{name: "refetches token about to expire", ttl: 30 * time.Second, wantRequests: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			idToken := newIDToken(t, time.Now().Add(tt.ttl))

			var requests atomic.Int32

			srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				tokenHandler(idToken)(w, r)
			})

			p := newProvider(t, srv)

			for range 2 {
				_, err := p.GetToken(t.Context())
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantRequests, requests.Load())
		})
	}
}

func TestGetToken_Errors(t *testing.T) {
	t.Parallel()

	noExp := newJWT(t, jwt.MapClaims{"sub": "repo:riptideslabs/tokenex:ref:refs/heads/main"})

	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "non-200 status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			},
		},
		{
			name: "invalid JSON",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte("not json")) //nolint:errcheck
			},
		},
		{name: "empty value", handler: tokenHandler("")},
		{name: "value is not a JWT", handler: tokenHandler("not-a-jwt")},
		{name: "JWT without exp", handler: tokenHandler(noExp)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := newProvider(t, newServer(t, tt.handler)).GetToken(t.Context())
			require.Error(t, err)
		})
	}
}

func TestNewIdentityTokenProvider_FromEnv(t *testing.T) {
	idToken := newIDToken(t, time.Now().Add(10*time.Minute))

	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer "+requestToken, r.Header.Get("Authorization"))

		tokenHandler(idToken)(w, r)
	})

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"/token?api-version=2.0")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", requestToken)

	p, err := githubactions.NewIdentityTokenProvider(githubactions.WithHTTPClient(srv.Client()))
	require.NoError(t, err)

	tok, err := p.GetToken(t.Context())
	require.NoError(t, err)
	assert.Equal(t, idToken, tok.Token)
}

func TestNewIdentityTokenProvider_MissingEnv(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	_, err := githubactions.NewIdentityTokenProvider()
	require.Error(t, err)
}

func TestWithRFC7523Exchange(t *testing.T) {
	t.Parallel()

	idToken := newIDToken(t, time.Now().Add(10*time.Minute))

	actions := newServer(t, tokenHandler(idToken))

	exchange := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string

		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, rfc7523.GrantType, body["grant_type"])
		assert.Equal(t, idToken, body["assertion"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"access_token": "access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)

	cp, err := rfc7523.NewCredentialsProvider(ctx, logr.Discard())
	require.NoError(t, err)

	ch, err := cp.GetCredentials(ctx, exchange.URL, newProvider(t, actions),
		rfc7523.WithBodyFormat(rfc7523.BodyFormatJSON),
		rfc7523.WithHTTPClient(exchange.Client()),
	)
	require.NoError(t, err)

	cred, ok := <-ch
	require.True(t, ok, "channel closed without sending a credential")
	require.NoError(t, cred.Err)

	creds, ok := cred.Credential.(*credential.Oauth2Creds)
	require.True(t, ok)
	assert.Equal(t, "access-token", creds.AccessToken)
}
