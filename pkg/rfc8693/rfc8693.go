// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

// Package rfc8693 implements an OAuth2 token exchange provider based on RFC 8693
// (OAuth 2.0 Token Exchange).
//
// The provider accepts an identity JWT from any IdentityTokenProvider and exchanges
// it at a token endpoint using the token-exchange grant type:
//
//	grant_type=urn:ietf:params:oauth:grant-type:token-exchange
//	subject_token=<identity-jwt>
//	subject_token_type=urn:ietf:params:oauth:token-type:jwt
//
// The resulting OAuth2 access token is returned via a channel and automatically
// refreshed before expiration.
package rfc8693

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/go-logr/logr"
	"golang.org/x/oauth2"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
	"go.riptides.io/tokenex/pkg/util"
)

const (
	// GrantType is the OAuth2 grant type defined by RFC 8693.
	GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
)

type TokenType string

const (
	TokenTypeJWT         TokenType = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeIDToken     TokenType = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeAccessToken TokenType = "urn:ietf:params:oauth:token-type:access_token"
)

type (
	Credential = credential.Result
)

type Provider interface {
	isRFC8693Provider()
}

func (cp *credentialsProvider) isRFC8693Provider() {}

type CredentialsProvider interface {
	GetCredentials(ctx context.Context, tokenEndpointURL string, subjectTokenProvider token.IdentityTokenProvider, opts ...option.Option) (<-chan Credential, error)
}

var _ CredentialsProvider = &credentialsProvider{}

type credentialsConfig struct {
	tokenEndpointURL     string
	subjectTokenProvider token.IdentityTokenProvider
	subjectTokenType     TokenType
	actorTokenProvider   token.IdentityTokenProvider
	actorTokenType       TokenType
	requestedTokenType   string
	audience             string
	scopes               []string
	additionalFields     map[string]string
	httpClient           *http.Client
}

type credentialsProvider struct {
	logger logr.Logger
}

func NewCredentialsProvider(_ context.Context, logger logr.Logger) (*credentialsProvider, error) {
	return &credentialsProvider{logger: logger}, nil
}

// GetCredentialsWithOptions implements credential.Provider using option-based configuration.
//
// Required options: WithTokenEndpointURL, WithTokenProvider.
func (cp *credentialsProvider) GetCredentialsWithOptions(ctx context.Context, opts ...option.Option) (<-chan Credential, error) {
	cfg := &credentialsConfig{}

	for _, opt := range opts {
		if o, ok := isCredentialsOption(opt); ok {
			o.Apply(cfg)
		}
	}

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return cp.GetCredentials(ctx, cfg.tokenEndpointURL, cfg.subjectTokenProvider, opts...)
}

func (cp *credentialsProvider) GetCredentials(
	ctx context.Context,
	tokenEndpointURL string,
	subjectTokenProvider token.IdentityTokenProvider,
	opts ...option.Option,
) (<-chan Credential, error) {
	cfg := &credentialsConfig{
		tokenEndpointURL:     tokenEndpointURL,
		subjectTokenProvider: subjectTokenProvider,
		subjectTokenType:     TokenTypeJWT,
	}

	for _, opt := range opts {
		if o, ok := isCredentialsOption(opt); ok {
			o.Apply(cfg)
		}
	}

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	credsChan := make(chan credential.Result, 1)

	go func() {
		defer close(credsChan)
		cp.refreshCredentialsLoop(ctx, cfg, credsChan)
	}()

	return credsChan, nil
}

func validateConfig(cfg *credentialsConfig) error {
	if cfg.tokenEndpointURL == "" {
		return errors.New("tokenEndpointURL is required")
	}

	if cfg.subjectTokenProvider == nil {
		return errors.New("subjectTokenProvider is required")
	}

	return nil
}

func (cp *credentialsProvider) refreshCredentialsLoop(
	ctx context.Context,
	cfg *credentialsConfig,
	credsChan chan credential.Result,
) {
	httpClient := cfg.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		identityToken, err := cfg.subjectTokenProvider.GetToken(ctx)
		if err != nil {
			util.SendErrorToChannel(credsChan, errors.WrapIf(err, "could not get subject token"))

			return
		}

		var actorToken string

		if cfg.actorTokenProvider != nil {
			at, err := cfg.actorTokenProvider.GetToken(ctx)
			if err != nil {
				util.SendErrorToChannel(credsChan, errors.WrapIf(err, "could not get actor token"))

				return
			}

			actorToken = at.Token
		}

		tok, err := exchangeToken(ctx, httpClient, cfg, identityToken.Token, actorToken)
		if err != nil {
			util.SendErrorToChannel(credsChan, errors.WrapIf(err, "could not exchange token"))

			return
		}

		cred := credential.Oauth2Creds(*tok)

		util.SendToChannel(credsChan, Credential{
			Event:      credential.UpdateEventType,
			Credential: &cred,
		})

		cp.logger.V(1).Info("token sent", "expires", tok.Expiry)

		if tok.Expiry.IsZero() {
			// Token has no expiry — treat as valid until context is cancelled.
			<-ctx.Done()

			return
		}

		timeUntilExpiry := time.Until(tok.Expiry)

		if timeUntilExpiry <= 0 {
			util.SendErrorToChannel(credsChan, errors.NewWithDetails("received already expired token", "expiresAt", tok.Expiry))

			return
		}

		refreshBuffer := util.CalculateRefreshBuffer(timeUntilExpiry)
		refreshTime := timeUntilExpiry - refreshBuffer

		cp.logger.V(1).Info("scheduling token refresh", "refreshIn", refreshTime, "refreshBuffer", refreshBuffer, "expiresAt", tok.Expiry)

		select {
		case <-ctx.Done():
			return
		case <-time.After(refreshTime):
			cp.logger.V(1).Info("refreshing token")
		}
	}
}

type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
}

type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func exchangeToken(ctx context.Context, client *http.Client, cfg *credentialsConfig, subjectToken, actorToken string) (*oauth2.Token, error) {
	body := map[string]string{
		"grant_type":         GrantType,
		"subject_token":      subjectToken,
		"subject_token_type": string(cfg.subjectTokenType),
	}

	if actorToken != "" {
		body["actor_token"] = actorToken
		actorTokenType := cfg.actorTokenType
		if actorTokenType == "" {
			actorTokenType = TokenTypeJWT
		}
		body["actor_token_type"] = string(actorTokenType)
	}

	if len(cfg.scopes) > 0 {
		body["scope"] = strings.Join(cfg.scopes, " ")
	}

	if cfg.requestedTokenType != "" {
		body["requested_token_type"] = cfg.requestedTokenType
	}

	if cfg.audience != "" {
		body["audience"] = cfg.audience
	}

	maps.Copy(body, cfg.additionalFields)

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, errors.WrapIf(err, "could not encode token request")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.tokenEndpointURL, bytes.NewReader(encoded))
	if err != nil {
		return nil, errors.WrapIf(err, "could not build token request")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WrapIf(err, "token request failed")
	}

	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WrapIf(err, "could not read token response body")
	}

	if resp.StatusCode != http.StatusOK {
		var errResp errorResponse

		if jsonErr := json.Unmarshal(respBody, &errResp); jsonErr == nil && errResp.Error != "" {
			return nil, errors.Errorf("token endpoint error %d: %s — %s", resp.StatusCode, errResp.Error, errResp.ErrorDescription)
		}

		return nil, errors.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp tokenResponse

	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, errors.WrapIf(err, "could not parse token response")
	}

	if tokenResp.AccessToken == "" {
		return nil, errors.New("token endpoint returned empty access_token")
	}

	tok := &oauth2.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
	}

	if tokenResp.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return tok, nil
}
