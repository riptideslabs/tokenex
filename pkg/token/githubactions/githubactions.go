// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

// Package githubactions provides an IdentityTokenProvider that fetches OIDC ID tokens from the
// GitHub Actions runtime, so a workflow can exchange them with any tokenex credentials provider.
// The job needs the `id-token: write` permission.
package githubactions

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"

	"emperror.dev/errors"
	"github.com/golang-jwt/jwt/v5"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
)

const (
	requestURLEnvVar   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	requestTokenEnvVar = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

type providerConfig struct {
	audience     string
	requestURL   string
	requestToken string
	httpClient   *http.Client
}

// IdentityTokenProvider fetches GitHub Actions OIDC ID tokens.
type IdentityTokenProvider struct {
	requestURL   string
	requestToken string
	httpClient   *http.Client
}

var _ token.IdentityTokenProvider = (*IdentityTokenProvider)(nil)

// NewIdentityTokenProvider creates a provider for GitHub Actions OIDC ID tokens.
// The request URL and bearer token default to the ACTIONS_ID_TOKEN_REQUEST_URL and
// ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variables, which the runner sets for jobs
// with the `id-token: write` permission.
func NewIdentityTokenProvider(opts ...option.Option) (*IdentityTokenProvider, error) {
	cfg := &providerConfig{
		requestURL:   os.Getenv(requestURLEnvVar),
		requestToken: os.Getenv(requestTokenEnvVar),
	}

	for _, opt := range opts {
		if o, ok := isProviderOption(opt); ok {
			o.Apply(cfg)
		}
	}

	if cfg.requestURL == "" {
		return nil, errors.Errorf("%s is not set (the job needs the id-token: write permission)", requestURLEnvVar)
	}

	if cfg.requestToken == "" {
		return nil, errors.Errorf("%s is not set (the job needs the id-token: write permission)", requestTokenEnvVar)
	}

	u, err := url.Parse(cfg.requestURL)
	if err != nil {
		return nil, errors.WrapIf(err, "could not parse token request URL")
	}

	if cfg.audience != "" {
		q := u.Query()
		q.Set("audience", cfg.audience)
		u.RawQuery = q.Encode()
	}

	httpClient := cfg.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &IdentityTokenProvider{
		requestURL:   u.String(),
		requestToken: cfg.requestToken,
		httpClient:   httpClient,
	}, nil
}

type tokenResponse struct {
	Value string `json:"value"`
}

// GetToken fetches a new ID token on every call. Tokens are not cached, since relying parties
// such as Anthropic WIF reject a token whose jti was already exchanged.
func (p *IdentityTokenProvider) GetToken(ctx context.Context, _ ...option.Option) (credential.Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.requestURL, nil)
	if err != nil {
		return credential.Token{}, errors.WrapIf(err, "could not build token request")
	}

	req.Header.Set("Authorization", "Bearer "+p.requestToken)
	req.Header.Set("Accept", "application/json; api-version=2.0")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return credential.Token{}, errors.WrapIf(err, "token request failed")
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return credential.Token{}, errors.WrapIf(err, "could not read token response body")
	}

	if resp.StatusCode != http.StatusOK {
		return credential.Token{}, errors.Errorf("token request returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return credential.Token{}, errors.WrapIf(err, "could not parse token response")
	}

	if tokenResp.Value == "" {
		return credential.Token{}, errors.New("token response has no value")
	}

	t, _, err := jwt.NewParser().ParseUnverified(tokenResp.Value, jwt.MapClaims{})
	if err != nil {
		return credential.Token{}, errors.WrapIf(err, "could not parse ID token")
	}

	exp, err := t.Claims.GetExpirationTime()
	if err != nil {
		return credential.Token{}, errors.WrapIf(err, "could not get ID token expiration time")
	}

	if exp == nil {
		return credential.Token{}, errors.New("ID token has no exp claim")
	}

	return credential.Token{
		Token:     tokenResp.Value,
		ExpiresAt: exp.Time,
	}, nil
}
