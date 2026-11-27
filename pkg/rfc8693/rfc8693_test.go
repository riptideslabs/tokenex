// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package rfc8693 //nolint:testpackage // Tests use unexported functions

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	"go.riptides.io/tokenex/internal/httpx"
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
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, GrantType, r.PostForm.Get("grant_type"))
		assert.Equal(t, "my-subject-token", r.PostForm.Get("subject_token"))
		assert.Equal(t, string(TokenTypeJWT), r.PostForm.Get("subject_token_type"))

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

func TestExchangeToken_JSONBody(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		var body map[string]string
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "subject", body["subject_token"])
		successHandler("json-token", 60)(w, r)
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	cp, err := NewCredentialsProvider(ctx, newLogger())
	require.NoError(t, err)
	ch, err := cp.GetCredentials(ctx, srv.URL, &staticProvider{tok: "subject"},
		WithBodyFormat(BodyFormatJSON), WithHTTPClient(srv.Client()))
	require.NoError(t, err)
	cred := <-ch
	require.NoError(t, cred.Err)
	tok, ok := cred.Credential.(*credential.Oauth2Creds)
	require.True(t, ok)
	assert.Equal(t, "json-token", tok.AccessToken)
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
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "actor-jwt", r.PostForm.Get("actor_token"))
		assert.Equal(t, string(TokenTypeJWT), r.PostForm.Get("actor_token_type"))

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
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "idp-123 & team", r.PostForm.Get("identity_provider_id"))

		successHandler("tok", 60)(w, r)
	})

	cfg := &credentialsConfig{
		tokenEndpointURL: srv.URL,
		subjectTokenType: TokenTypeJWT,
		additionalFields: map[string]string{"identity_provider_id": "idp-123 & team"},
	}

	_, err := exchangeToken(t.Context(), srv.Client(), cfg, "subject", "")
	require.NoError(t, err)
}

func TestExchangeToken_ScopeAndAudience(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "read write", r.PostForm.Get("scope"))
		assert.Equal(t, "my-service", r.PostForm.Get("audience"))

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

// Following a redirect would repeat the subject token to the host it names.
func TestGetCredentials_DoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	var followed atomic.Bool

	target := newTestServer(t, func(http.ResponseWriter, *http.Request) { followed.Store(true) })
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})

	cp, err := NewCredentialsProvider(t.Context(), newLogger())
	require.NoError(t, err)

	ch, err := cp.GetCredentials(t.Context(), srv.URL, &staticProvider{tok: "subject"})
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

			_, err := exchangeToken(t.Context(), srv.Client(), &credentialsConfig{tokenEndpointURL: srv.URL}, "subject", "")
			require.ErrorIs(t, err, httpx.ErrBodyTooLarge)
		})
	}

	t.Run("error message", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, huge[:64<<10]) //nolint:errcheck
		})

		_, err := exchangeToken(t.Context(), srv.Client(), &credentialsConfig{tokenEndpointURL: srv.URL}, "subject", "")
		require.Error(t, err)
		require.Less(t, len(err.Error()), 1024)
	})
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
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
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
		WithBodyFormat(BodyFormatForm), // OpenAI must still use JSON.
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
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
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

func TestFetchSpanConfigAttrs_BodyFormat(t *testing.T) {
	t.Parallel()

	for format, want := range map[BodyFormat]string{BodyFormatForm: "form", BodyFormatJSON: "json"} {
		attrs := fetchSpanConfigAttrs(&credentialsConfig{bodyFormat: format}, "correlation")
		assert.Contains(t, attrs, attribute.String("cfg.body_format", want))
	}
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

			tok, err := exchangeToken(t.Context(), srv.Client(), &credentialsConfig{tokenEndpointURL: srv.URL}, "subject", "")
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

	ch, err := cp.GetCredentials(ctx, srv.URL, &staticProvider{tok: "subject"})
	require.NoError(t, err)

	got := make([]credential.Result, 0, 1)
	for res := range ch {
		got = append(got, res)
	}

	require.Len(t, got, 1)
	require.Error(t, got[0].Err)
	require.Nil(t, got[0].Credential)
}
