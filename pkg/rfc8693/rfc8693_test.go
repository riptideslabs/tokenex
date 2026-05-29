// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package rfc8693 //nolint:testpackage // Tests use unexported functions

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
)

type staticProvider struct {
	tok string
	err error
}

func (p *staticProvider) GetToken(_ context.Context, _ ...option.Option) (credential.Token, error) {
	return credential.Token{Token: p.tok}, p.err
}

func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return srv
}

func newLogger() logr.Logger {
	return logr.Discard()
}

func successHandler(accessToken string, expiresIn int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := tokenResponse{
			AccessToken:     accessToken,
			IssuedTokenType: string(TokenTypeAccessToken),
			TokenType:       "Bearer",
			ExpiresIn:       expiresIn,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}
}

func TestValidateConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *credentialsConfig
		wantErr bool
	}{
		{
			name: "valid",
			cfg: &credentialsConfig{
				tokenEndpointURL:     "https://example.com/token",
				subjectTokenProvider: &staticProvider{tok: "tok"},
			},
		},
		{
			name:    "missing endpoint",
			cfg:     &credentialsConfig{subjectTokenProvider: &staticProvider{}},
			wantErr: true,
		},
		{
			name:    "missing subject provider",
			cfg:     &credentialsConfig{tokenEndpointURL: "https://example.com/token"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateConfig(tt.cfg)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestExchangeToken_Success(t *testing.T) {
	t.Parallel()

	const wantToken = "test-access-token"

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var body map[string]string

		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, GrantType, body["grant_type"])
		assert.Equal(t, "my-subject-token", body["subject_token"])
		assert.Equal(t, string(TokenTypeJWT), body["subject_token_type"])

		successHandler(wantToken, 3600)(w, r)
	})

	cfg := &credentialsConfig{
		tokenEndpointURL:     srv.URL,
		subjectTokenProvider: &staticProvider{tok: "my-subject-token"},
		subjectTokenType:     TokenTypeJWT,
	}

	tok, err := exchangeToken(t.Context(), srv.Client(), cfg, "my-subject-token", "")
	require.NoError(t, err)
	require.Equal(t, wantToken, tok.AccessToken)
	require.False(t, tok.Expiry.IsZero())
}

func TestExchangeToken_NoExpiry(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, successHandler("tok-no-expiry", 0))

	cfg := &credentialsConfig{
		tokenEndpointURL: srv.URL,
		subjectTokenType: TokenTypeJWT,
	}

	tok, err := exchangeToken(t.Context(), srv.Client(), cfg, "subject", "")
	require.NoError(t, err)
	require.True(t, tok.Expiry.IsZero())
}

func TestExchangeToken_WithActorToken(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string

		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck

		assert.Equal(t, "actor-jwt", body["actor_token"])
		assert.Equal(t, string(TokenTypeJWT), body["actor_token_type"])

		successHandler("tok", 60)(w, r)
	})

	cfg := &credentialsConfig{
		tokenEndpointURL: srv.URL,
		subjectTokenType: TokenTypeJWT,
	}

	_, err := exchangeToken(t.Context(), srv.Client(), cfg, "subject", "actor-jwt")
	require.NoError(t, err)
}

func TestExchangeToken_WithAdditionalFields(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string

		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		assert.Equal(t, "idp-123", body["identity_provider_id"])

		successHandler("tok", 60)(w, r)
	})

	cfg := &credentialsConfig{
		tokenEndpointURL: srv.URL,
		subjectTokenType: TokenTypeJWT,
		additionalFields: map[string]string{"identity_provider_id": "idp-123"},
	}

	_, err := exchangeToken(t.Context(), srv.Client(), cfg, "subject", "")
	require.NoError(t, err)
}

func TestExchangeToken_ScopeAndAudience(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string

		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		assert.Equal(t, "read write", body["scope"])
		assert.Equal(t, "my-service", body["audience"])

		successHandler("tok", 60)(w, r)
	})

	cfg := &credentialsConfig{
		tokenEndpointURL: srv.URL,
		subjectTokenType: TokenTypeJWT,
		scopes:           []string{"read", "write"},
		audience:         "my-service",
	}

	_, err := exchangeToken(t.Context(), srv.Client(), cfg, "subject", "")
	require.NoError(t, err)
}

func TestExchangeToken_HTTPError(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"error":             "invalid_client",
			"error_description": "bad credentials",
		})
	})

	cfg := &credentialsConfig{
		tokenEndpointURL: srv.URL,
		subjectTokenType: TokenTypeJWT,
	}

	_, err := exchangeToken(t.Context(), srv.Client(), cfg, "subject", "")
	require.Error(t, err)
}

func TestExchangeToken_EmptyAccessToken(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse{}) //nolint:errcheck
	})

	cfg := &credentialsConfig{
		tokenEndpointURL: srv.URL,
		subjectTokenType: TokenTypeJWT,
	}

	_, err := exchangeToken(t.Context(), srv.Client(), cfg, "subject", "")
	require.Error(t, err)
}

func TestGetCredentials_ReceivesToken(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, successHandler("creds-token", 3600))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)

	cp, err := NewCredentialsProvider(ctx, newLogger())
	require.NoError(t, err)

	ch, err := cp.GetCredentials(
		ctx,
		srv.URL,
		&staticProvider{tok: "subject"},
		WithHTTPClient(srv.Client()),
	)
	require.NoError(t, err)

	cred, ok := <-ch
	require.True(t, ok, "channel closed without sending a credential")
	require.NoError(t, cred.Err)
	require.NotNil(t, cred.Credential)
}

func TestGetCredentials_ValidationError(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	cp, err := NewCredentialsProvider(ctx, newLogger())
	require.NoError(t, err)

	_, err = cp.GetCredentials(ctx, "https://example.com/token", nil)
	require.Error(t, err)
}

func TestGetOpenAICredentials_RequestShape(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string

		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck

		assert.Equal(t, "idp-xyz", body["identity_provider_id"])
		assert.Equal(t, "sa-abc", body["service_account_id"])
		assert.Equal(t, "client-1", body["client_id"])
		assert.Equal(t, string(TokenTypeJWT), body["subject_token_type"])

		successHandler("openai-tok", 1800)(w, r)
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)

	subjectProvider := token.IdentityTokenProviderFunc(func(_ context.Context, _ ...option.Option) (credential.Token, error) {
		return credential.Token{Token: "my-id-token"}, nil
	})

	wif := OpenAIWIFConfig{
		ClientID:           "client-1",
		IdentityProviderID: "idp-xyz",
		ServiceAccountID:   "sa-abc",
	}

	ch, err := GetOpenAICredentials(
		ctx,
		newLogger(),
		subjectProvider,
		wif,
		WithTokenEndpointURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)
	require.NoError(t, err)

	cred, ok := <-ch
	require.True(t, ok, "channel closed without sending a credential")
	require.NoError(t, cred.Err)
}

func TestGetOpenAICredentials_NoClientID(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string

		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		assert.NotContains(t, body, "client_id")

		successHandler("tok", 60)(w, r)
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)

	subjectProvider := token.IdentityTokenProviderFunc(func(_ context.Context, _ ...option.Option) (credential.Token, error) {
		return credential.Token{Token: "id-token"}, nil
	})

	wif := OpenAIWIFConfig{
		IdentityProviderID: "idp-1",
		ServiceAccountID:   "sa-1",
	}

	ch, err := GetOpenAICredentials(
		ctx,
		newLogger(),
		subjectProvider,
		wif,
		WithTokenEndpointURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)
	require.NoError(t, err)

	cred := <-ch
	require.NoError(t, cred.Err)
}
