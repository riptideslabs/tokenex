// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package httpx_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.riptides.io/tokenex/internal/httpx"
)

func TestExchangeClient(t *testing.T) {
	t.Parallel()

	client := httpx.ExchangeClient(nil)
	assert.Equal(t, httpx.DefaultTimeout, client.Timeout)
	require.ErrorIs(t, client.CheckRedirect(nil, nil), http.ErrUseLastResponse)

	errOwn := assert.AnError
	base := &http.Client{
		Timeout:       time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errOwn },
	}

	client = httpx.ExchangeClient(base)
	assert.NotSame(t, base, client)
	assert.Equal(t, time.Second, client.Timeout)
	assert.ErrorIs(t, client.CheckRedirect(nil, nil), errOwn)
}

func TestWithTimeoutKeepsRedirects(t *testing.T) {
	t.Parallel()

	client := httpx.WithTimeout(&http.Client{})
	assert.Equal(t, httpx.DefaultTimeout, client.Timeout)
	assert.Nil(t, client.CheckRedirect)
}

func TestReadBody(t *testing.T) {
	t.Parallel()

	data, err := httpx.ReadBody(strings.NewReader("12345"), 5)
	require.NoError(t, err)
	assert.Equal(t, "12345", string(data))

	_, err = httpx.ReadBody(strings.NewReader("123456"), 5)
	require.ErrorIs(t, err, httpx.ErrBodyTooLarge)
}

func TestSnippet(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "short", httpx.Snippet("short"))

	got := httpx.Snippet([]byte(strings.Repeat("x", 4096)))
	assert.Less(t, len(got), 600)
	assert.True(t, strings.HasSuffix(got, "(truncated)"))
}

func TestRedactURL(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "https://idp.example.com/token?a=b", httpx.RedactURL("https://idp.example.com/token?a=b"))
	assert.Equal(t, "https://idp.example.com/token", httpx.RedactURL("https://user:secret@idp.example.com/token"))
	assert.NotContains(t, httpx.RedactURL("https://user:secret@idp.example.com:port/token"), "secret")
}

func TestLimitResponses(t *testing.T) {
	t.Parallel()

	const (
		limit    = 100
		errLimit = 10
	)

	testCases := map[string]struct {
		status  int
		size    int
		wantErr bool
	}{
		"at the limit":         {http.StatusOK, limit, false},
		"over the limit":       {http.StatusOK, limit + 1, true},
		"error at the limit":   {http.StatusForbidden, errLimit, false},
		"error over the limit": {http.StatusForbidden, errLimit + 1, true},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, strings.Repeat("x", tc.size)) //nolint:errcheck
			}))
			t.Cleanup(srv.Close)

			client := &http.Client{Transport: httpx.LimitResponses(http.DefaultTransport, limit, errLimit)}

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, http.NoBody)
			require.NoError(t, err)

			resp, err := client.Do(req)
			require.NoError(t, err)

			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if tc.wantErr {
				require.ErrorIs(t, err, httpx.ErrBodyTooLarge)

				return
			}

			require.NoError(t, err)
			assert.Len(t, body, tc.size)
		})
	}
}
