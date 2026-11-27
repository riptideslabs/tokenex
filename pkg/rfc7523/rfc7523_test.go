// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package rfc7523 //nolint:testpackage // Tests use unexported functions

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"

	"go.riptides.io/tokenex/internal/httpx"
	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
)

type staticProvider struct{}

func (staticProvider) GetToken(context.Context, ...option.Option) (credential.Token, error) {
	return credential.Token{Token: "assertion"}, nil
}

func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return srv
}

// Following a redirect would repeat the assertion to the host it names.
func TestGetCredentials_DoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	var followed atomic.Bool

	target := newTestServer(t, func(http.ResponseWriter, *http.Request) { followed.Store(true) })
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})

	cp, err := NewCredentialsProvider(t.Context(), logr.Discard())
	require.NoError(t, err)

	ch, err := cp.GetCredentials(t.Context(), srv.URL, staticProvider{})
	require.NoError(t, err)

	cred := <-ch
	require.ErrorContains(t, cred.Err, "status 307")
	require.False(t, followed.Load(), "the redirect was followed")
}

func TestExchangeToken_LimitsResponseBody(t *testing.T) {
	t.Parallel()

	huge := strings.Repeat("x", httpx.MaxTokenBody+1)

	for name, status := range map[string]int{"success": http.StatusOK, "error": http.StatusInternalServerError} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				io.WriteString(w, huge) //nolint:errcheck
			})

			_, err := exchangeToken(t.Context(), srv.Client(), &credentialsConfig{tokenEndpointURL: srv.URL}, "assertion")
			require.ErrorIs(t, err, httpx.ErrBodyTooLarge)
		})
	}

	t.Run("error message", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, huge[:64<<10]) //nolint:errcheck
		})

		_, err := exchangeToken(t.Context(), srv.Client(), &credentialsConfig{tokenEndpointURL: srv.URL}, "assertion")
		require.Error(t, err)
		require.Less(t, len(err.Error()), 1024)
	})
}

// A missing, negative or huge expires_in must not leave a token unrefreshed or wrap around.
func TestExchangeToken_Expiry(t *testing.T) {
	t.Parallel()

	enc := base64.RawURLEncoding.EncodeToString
	exp := time.Now().Add(10 * time.Minute).Truncate(time.Second)
	jwtToken := enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(`{"exp":`+strconv.FormatInt(exp.Unix(), 10)+`}`)) + ".sig"

	testCases := map[string]struct {
		response string
		check    func(expiry time.Time) bool
	}{
		"none, opaque token": {`{"access_token":"opaque"}`, time.Time.IsZero},
		"none, JWT":          {`{"access_token":"` + jwtToken + `"}`, exp.Equal},
		"negative":           {`{"access_token":"opaque","expires_in":-5}`, func(expiry time.Time) bool { return !expiry.IsZero() && time.Until(expiry) < 0 }},
		"overflowing":        {`{"access_token":"opaque","expires_in":9223372037}`, func(expiry time.Time) bool { return time.Until(expiry) > time.Hour }},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				io.WriteString(w, tc.response) //nolint:errcheck
			})

			tok, err := exchangeToken(t.Context(), srv.Client(), &credentialsConfig{tokenEndpointURL: srv.URL}, "assertion")
			require.NoError(t, err)
			require.True(t, tc.check(tok.Expiry), "expiry %s", tok.Expiry)
		})
	}
}

func TestFetchSpanConfigAttrs_NoUserInfo(t *testing.T) {
	t.Parallel()

	for _, attr := range fetchSpanConfigAttrs(&credentialsConfig{tokenEndpointURL: "https://user:secret@idp.example.com/token"}, "id") {
		require.NotContains(t, attr.Value.String(), "secret")
	}
}

func TestGetCredentials_ExpiredTokenIsNotPublished(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"access_token":"opaque","expires_in":-5}`) //nolint:errcheck
	})

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	t.Cleanup(cancel)

	// A slow logger gives the reader time to see each result before the next one replaces it.
	logger := funcr.New(func(string, string) { time.Sleep(20 * time.Millisecond) }, funcr.Options{Verbosity: 2})

	cp, err := NewCredentialsProvider(ctx, logger)
	require.NoError(t, err)

	ch, err := cp.GetCredentials(ctx, srv.URL, staticProvider{})
	require.NoError(t, err)

	got := make([]credential.Result, 0, 1)
	for res := range ch {
		got = append(got, res)
	}

	require.Len(t, got, 1)
	require.Error(t, got[0].Err)
	require.Nil(t, got[0].Credential)
}
