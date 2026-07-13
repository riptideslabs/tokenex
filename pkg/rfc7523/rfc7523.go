// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

// Package rfc7523 implements an OAuth2 token exchange provider based on RFC 7523
// (JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants).
//
// The provider accepts an identity JWT from any IdentityTokenProvider and exchanges
// it at a token endpoint using the jwt-bearer grant type:
//
//	grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
//	assertion=<identity-jwt>
//
// The resulting OAuth2 access token is returned via a channel and automatically
// refreshed before expiration.
package rfc7523

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	tokenextelemetry "go.riptides.io/tokenex/pkg/telemetry"
	"go.riptides.io/tokenex/pkg/token"
	"go.riptides.io/tokenex/pkg/util"
)

const (
	// GrantType is the OAuth2 grant type defined by RFC 7523.
	GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

type (
	Credential = credential.Result
)

type Provider interface {
	isRFC7523Provider()
}

func (cp *credentialsProvider) isRFC7523Provider() {}

// CredentialsProvider exchanges identity JWTs for OAuth2 access tokens via the
// RFC 7523 jwt-bearer grant type.
type CredentialsProvider interface {
	// GetCredentials returns a channel that receives OAuth2 access tokens obtained
	// by exchanging the JWT produced by tokenProvider at tokenEndpointURL.
	// The channel is closed when the context is cancelled or an unrecoverable error occurs.
	GetCredentials(ctx context.Context, tokenEndpointURL string, tokenProvider token.IdentityTokenProvider, opts ...option.Option) (<-chan Credential, error)
}

var _ CredentialsProvider = &credentialsProvider{}

// BodyFormat controls how the token exchange request body is encoded.
type BodyFormat int

const (
	// BodyFormatForm encodes the request as application/x-www-form-urlencoded (RFC 7523 default).
	BodyFormatForm BodyFormat = iota
	// BodyFormatJSON encodes the request as application/json (required by Anthropic WIF).
	BodyFormatJSON
)

type credentialsConfig struct {
	tokenEndpointURL string
	tokenProvider    token.IdentityTokenProvider
	scopes           []string
	// additionalParams are extra key→values merged into a form-encoded body.
	additionalParams map[string][]string
	// additionalFields are extra key→value pairs merged into a JSON body.
	additionalFields map[string]string
	bodyFormat       BodyFormat
	httpClient       *http.Client

	tracerProvider trace.TracerProvider
}

type credentialsProvider struct {
	logger logr.Logger
}

// NewCredentialsProvider creates a new RFC 7523 jwt-bearer credentials provider.
func NewCredentialsProvider(ctx context.Context, logger logr.Logger) (*credentialsProvider, error) {
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

	return cp.GetCredentials(ctx, cfg.tokenEndpointURL, cfg.tokenProvider, opts...)
}

// GetCredentials exchanges identity tokens for OAuth2 access tokens at tokenEndpointURL.
func (cp *credentialsProvider) GetCredentials(
	ctx context.Context,
	tokenEndpointURL string,
	tokenProvider token.IdentityTokenProvider,
	opts ...option.Option,
) (<-chan Credential, error) {
	cfg := &credentialsConfig{
		tokenEndpointURL: tokenEndpointURL,
		tokenProvider:    tokenProvider,
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

	if cfg.tokenProvider == nil {
		return errors.New("tokenProvider is required")
	}

	return nil
}

func fetchCredentials(ctx context.Context, tracer trace.Tracer, configAttrs []attribute.KeyValue, httpClient *http.Client, cfg *credentialsConfig) (*oauth2.Token, error) {
	fetchCtx, span := tracer.Start(ctx, fetchSpanName, trace.WithAttributes(configAttrs...))
	defer span.End()

	identityToken, err := cfg.tokenProvider.GetToken(fetchCtx)
	if err != nil {
		err = errors.WrapIf(err, "could not get identity token")
		tokenextelemetry.RecordResult(span, err)

		return nil, err
	}

	span.SetAttributes(tokenextelemetry.IdentityTokenAttrs("id_token", identityToken.Token, identityToken.ExpiresAt)...)

	tok, err := exchangeToken(fetchCtx, httpClient, cfg, identityToken.Token)
	if err != nil {
		err = errors.WrapIf(err, "could not exchange jwt-bearer token")
		tokenextelemetry.RecordResult(span, err)

		return nil, err
	}

	span.SetAttributes(fetchSpanResultAttrs(tok)...)
	tokenextelemetry.RecordResult(span, nil)

	return tok, nil
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

	tracer := tokenextelemetry.Tracer(ctx, cfg.tracerProvider, instrumentationScopeName)
	correlationID := uuid.NewString()
	configAttrs := fetchSpanConfigAttrs(cfg, correlationID)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		tok, err := fetchCredentials(ctx, tracer, configAttrs, httpClient, cfg)
		if err != nil {
			util.SendErrorToChannel(credsChan, err)

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

// tokenResponse is the JSON body returned by a successful token endpoint response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// errorResponse is the JSON body returned by a token endpoint error.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func exchangeToken(ctx context.Context, client *http.Client, cfg *credentialsConfig, assertion string) (*oauth2.Token, error) {
	var (
		bodyReader  *strings.Reader
		contentType string
	)

	switch cfg.bodyFormat {
	case BodyFormatJSON:
		body := map[string]string{
			"grant_type": GrantType,
			"assertion":  assertion,
		}

		if len(cfg.scopes) > 0 {
			body["scope"] = strings.Join(cfg.scopes, " ")
		}

		maps.Copy(body, cfg.additionalFields)

		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, errors.WrapIf(err, "could not encode token request")
		}

		bodyReader = strings.NewReader(string(encoded))
		contentType = "application/json"

	default: // BodyFormatForm
		params := url.Values{
			"grant_type": {GrantType},
			"assertion":  {assertion},
		}

		if len(cfg.scopes) > 0 {
			params.Set("scope", strings.Join(cfg.scopes, " "))
		}

		maps.Copy(params, cfg.additionalParams)

		bodyReader = strings.NewReader(params.Encode())
		contentType = "application/x-www-form-urlencoded"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.tokenEndpointURL, bodyReader)
	if err != nil {
		return nil, errors.WrapIf(err, "could not build token request")
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WrapIf(err, "token request failed")
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WrapIf(err, "could not read token response body")
	}

	if resp.StatusCode != http.StatusOK {
		var errResp errorResponse

		if jsonErr := json.Unmarshal(body, &errResp); jsonErr == nil && errResp.Error != "" {
			return nil, errors.Errorf("token endpoint error %d: %s — %s", resp.StatusCode, errResp.Error, errResp.ErrorDescription)
		}

		return nil, errors.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse

	if err := json.Unmarshal(body, &tokenResp); err != nil {
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
