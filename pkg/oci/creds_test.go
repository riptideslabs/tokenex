// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package oci //nolint:testpackage // Tests use unexported functions

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"go.riptides.io/tokenex/pkg/token"
)

// The ID token and the client secret are posted to the identity domain URL.
func TestValidateConfig_IdentityDomainURL(t *testing.T) {
	t.Parallel()

	testCases := map[string]bool{
		"https://idcs-abc.identity.oraclecloud.com":      true,
		"https://idcs-abc.identity.oraclecloud.com:443/": true,
		"http://idcs-abc.identity.oraclecloud.com":       false,
		"https://user:pass@idcs-abc.example.com":         false,
		"https://idcs-abc.example.com?x=1":               false,
		"https://idcs-abc.example.com#frag":              false,
		"idcs-abc.identity.oraclecloud.com":              false,
		"https://":                                       false,
		"://":                                            false,
	}

	for identityDomainURL, valid := range testCases {
		t.Run(identityDomainURL, func(t *testing.T) {
			t.Parallel()

			err := validateConfig(&credentialsConfig{
				clientID:              "id",
				clientSecret:          "secret",
				identityDomainURL:     identityDomainURL,
				rsaPubKeyDer:          []byte("key"),
				identityTokenProvider: token.NewStaticIdentityTokenProvider("jwt"),
			})

			if valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// Following a redirect would repeat the ID token to the host it names.
func TestExchangeToken_DoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	var followed atomic.Bool

	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Store(true) }))
	t.Cleanup(target.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)

	_, err := exchangeToken(t.Context(), srv.URL, "id", "secret", "jwt", "key")
	require.Error(t, err)
	require.False(t, followed.Load(), "the redirect was followed")
}
