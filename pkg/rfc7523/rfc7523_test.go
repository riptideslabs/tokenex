// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package rfc7523 //nolint:testpackage // Tests use unexported functions

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-logr/logr"
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
