// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
	"go.riptides.io/tokenex/pkg/util"
)

// credentialsConfig holds the configuration for GetCredentials.
type credentialsConfig struct {
	clientID              string
	clientSecret          string
	identityDomainURL     string
	rsaPubKeyDer          []byte
	identityTokenProvider token.IdentityTokenProvider
}

// CredentialsProvider defines the interface for obtaining OCI credentials.
// It exchanges ID tokens for OCI User Principal Session Tokens (UPST) using OCI's Workload Identity Federation.
type CredentialsProvider interface {
	// GetCredentials exchanges an ID token for an OCI UPST and returns a channel to receive them.
	// The channel provides updates when credentials are refreshed or removed.
	// For the first credential and each refresh, an Update event is sent.
	// In case of errors, the Err field is populated, Credential is nil, and the refresh loop exits.
	// When the refresh loop exits, the channel is closed.
	// The tokenProvider is used to obtain the ID token for exchange.
	// Options can be provided to configure the request (e.g., client ID, client secret, identity domain URL).
	GetCredentials(ctx context.Context, tokenProvider token.IdentityTokenProvider, opts ...option.Option) (<-chan credential.Result, error)
}

var _ CredentialsProvider = &credentialsProvider{}

// credentialsProvider is the internal implementation of CredentialsProvider.
type credentialsProvider struct {
	logger logr.Logger
}

// validateConfig validates the configuration and returns an error if any required field is missing.
func validateConfig(cfg *credentialsConfig) error {
	if cfg.clientID == "" {
		return errors.New("clientID is required")
	}

	if cfg.clientSecret == "" {
		return errors.New("clientSecret is required")
	}

	if cfg.identityDomainURL == "" {
		return errors.New("identityDomainURL is required")
	}

	if _, err := url.Parse(cfg.identityDomainURL); err != nil {
		return errors.WrapIf(err, "identityDomainURL is invalid")
	}

	if cfg.rsaPubKeyDer == nil {
		return errors.New("rsaPubKeyDer is required")
	}

	if cfg.identityTokenProvider == nil {
		return errors.New("identity token provider must be specified")
	}

	return nil
}

type Provider interface {
	isOCI()
}

func (cp *credentialsProvider) isOCI() {}

// refreshCredentialsLoop handles the credential retrieval and refresh loop.
func (cp *credentialsProvider) refreshCredentialsLoop(ctx context.Context, cfg *credentialsConfig, credsChan chan credential.Result) {
	tokenEndpoint := getTokenEndpoint(cfg.identityDomainURL)
	publicKey := base64.StdEncoding.EncodeToString(cfg.rsaPubKeyDer)

	for {
		idToken, err := cfg.identityTokenProvider.GetToken(ctx)
		if err != nil {
			util.SendToChannel(credsChan, credential.Result{
				Credential: nil,
				Err:        errors.WrapIf(err, "failed to get identity token"),
			})

			return
		}

		authToken, err := exchangeToken(ctx, tokenEndpoint, cfg.clientID, cfg.clientSecret, idToken.Token, publicKey)
		if err != nil {
			util.SendToChannel(credsChan, credential.Result{
				Credential: nil,
				Err:        errors.WrapIf(err, "token exchange failed"),
			})

			return
		}

		expTime, err := getTokenExpiration(authToken)
		if err != nil {
			util.SendToChannel(credsChan, credential.Result{
				Credential: nil,
				Err:        errors.WrapIf(err, "failed to get expiration time of the received UPST"),
			})

			return
		}

		// Send credentials
		ociCredential := credential.Token{
			Token:     authToken.Raw,
			ExpiresAt: expTime,
		}

		// Calculate when to refresh
		timeUntilExpiry := time.Until(ociCredential.ExpiresAt)

		// If credentials are already expired, this is an error
		if timeUntilExpiry <= 0 {
			util.SendToChannel(credsChan, credential.Result{
				Credential: nil,
				Err:        errors.NewWithDetails("received already expired credentials", "expiresAt", ociCredential.ExpiresAt),
			})

			return
		}

		util.SendToChannel(credsChan, credential.Result{
			Credential: &ociCredential,
			Err:        nil,
			Event:      credential.UpdateEventType,
		})

		cp.logger.V(2).Info("Sent credentials", "expires", ociCredential.ExpiresAt)

		refreshBuffer := util.CalculateRefreshBuffer(timeUntilExpiry)
		refreshTime := timeUntilExpiry - refreshBuffer

		cp.logger.V(1).Info("Scheduling credential refresh", "refreshIn", refreshTime, "refreshBuffer", refreshBuffer, "expiresAt", ociCredential.ExpiresAt)

		select {
		case <-ctx.Done():
			cp.logger.V(1).Info("Context cancelled, stopping credential refresh")

			return
		case <-time.After(refreshTime):
			// Continue to next iteration to refresh
			cp.logger.V(2).Info("Refreshing credentials")
		}
	}
}

// NewCredentialsProvider creates a new instance of CredentialsProvider for OCI.
// The returned provider can be used to obtain OCI User Principal Session Tokens (UPST) by exchanging ID tokens
// using OCI's Workload Identity Federation functionality.
//
// Parameters:
//   - ctx: The context for the operation
//   - logger: Logger for logging credential operations
//
// Returns:
//   - A credential provider that can exchange ID tokens for OCI UPSTs
//   - An error if the provider cannot be created
func NewCredentialsProvider(ctx context.Context, logger logr.Logger) (*credentialsProvider, error) {
	return &credentialsProvider{
		logger: logger.WithName("oci_credentials"),
	}, nil
}

// GetCredentialsWithOptions returns OCI credentials using the provided options.
// It applies any credential-specific options, validates the config, and delegates to GetCredentials.
// This method implements the credential.Provider interface and is the primary entry point for obtaining OCI credentials.
// The returned channel will receive credential updates, including initial credentials and refreshed credentials before expiration.
//
// Options can include:
//   - Client ID for the OCI application
//   - Client secret for the OCI application
//   - Identity domain URL for the OCI tenant
//   - RSA public key DER for token verification
//   - Identity token provider
func (cp *credentialsProvider) GetCredentialsWithOptions(ctx context.Context, opts ...option.Option) (<-chan credential.Result, error) {
	cfg := &credentialsConfig{}

	for _, opt := range opts {
		if opt, ok := isCredentialsOption(opt); ok {
			opt.Apply(cfg)
		}
	}

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return cp.GetCredentials(ctx, cfg.identityTokenProvider, opts...)
}

func (cp *credentialsProvider) GetCredentials(ctx context.Context, tokenProvider token.IdentityTokenProvider, opts ...option.Option) (<-chan credential.Result, error) {
	cfg := &credentialsConfig{
		identityTokenProvider: tokenProvider,
	}

	for _, opt := range opts {
		if o, ok := isCredentialsOption(opt); ok {
			o.Apply(cfg)
		}
	}

	if err := validateConfig(cfg); err != nil {
		return nil, errors.WrapIf(err, "invalid configuration")
	}

	// Validate that we can get an initial token
	_, err := tokenProvider.GetToken(ctx)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to get initial ID token")
	}

	credsChan := make(chan credential.Result, 1)

	go func() {
		defer close(credsChan)
		cp.refreshCredentialsLoop(ctx, cfg, credsChan)
	}()

	return credsChan, nil
}

// getTokenEndpoint constructs the OCI token endpoint URL from domainURL.
func getTokenEndpoint(identityDomainURL string) string {
	endpoint, _ := url.JoinPath(identityDomainURL, "/oauth2/v1/token")

	return endpoint
}

// buildTokenExchangeRequest builds an HTTP request for exchanging an IDP JWT for an OCI UPST
func buildTokenExchangeRequest(
	ctx context.Context,
	tokenEndpoint string,
	clientID string,
	clientSecret string,
	subjectToken string,
	publicKey string,
) (*http.Request, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("requested_token_type", "urn:oci:token-type:oci-upst")
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", "jwt")
	form.Set("public_key", publicKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.WrapIf(err, "failed to create token exchange request")
	}

	// Add headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")

	// Add Basic Auth
	req.SetBasicAuth(clientID, clientSecret)

	return req, nil
}

func exchangeToken(
	ctx context.Context,
	tokenEndpoint string,
	clientID string,
	clientSecret string,
	idToken string,
	publicKey string,
) (*jwt.Token, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := buildTokenExchangeRequest(
		ctx,
		tokenEndpoint,
		clientID,
		clientSecret,
		idToken,
		publicKey,
	)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to build token exchange request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to execute token exchange request")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to read token exchange response body")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.NewWithDetails("token exchange request failed", "status", resp.Status, "statusCode", resp.StatusCode, "err_response", string(body))
	}

	var respJSON struct {
		Token string `json:"token"`
	}

	if err := json.Unmarshal(body, &respJSON); err != nil {
		return nil, errors.WrapIf(err, "failed to decode token exchange response")
	}

	jwtParser := jwt.NewParser()

	token, _, err := jwtParser.ParseUnverified(respJSON.Token, jwt.MapClaims{})
	if err != nil {
		return nil, errors.WrapIf(err, "failed to parse UPST received from OCI")
	}

	return token, nil
}

func getTokenExpiration(token *jwt.Token) (time.Time, error) {
	if token.Claims == nil {
		return time.Time{}, errors.New("token has no claims")
	}

	exp, err := token.Claims.GetExpirationTime()
	if err != nil {
		return time.Time{}, errors.WrapIf(err, "failed to get token expiration time")
	}

	return exp.Time, nil
}
