// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package gcp

import (
	"context"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/go-logr/logr"
	"golang.org/x/oauth2"
	google_option "google.golang.org/api/option"
	stsv1 "google.golang.org/api/sts/v1"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
	"go.riptides.io/tokenex/pkg/util"
)

// credentialsConfig holds the configuration for GetCredentials.
type credentialsConfig struct {
	serviceAccountEmail   string // Email of the service account to impersonate, optional. If set, it will generate an access token for this service account.
	audience              string
	scopes                []string // Scope for the access token, defaults to ["https://www.googleapis.com/auth/cloud-platform", "https://www.googleapis.com/auth/userinfo.email"]
	tokenLifetime         *int64   // Lifetime in seconds for the access token of the impersonated service account, optional. If set it should be less than or equal to 1 hour
	identityTokenProvider token.IdentityTokenProvider
}

// CredentialsProvider defines the interface for obtaining GCP credentials.
// It exchanges ID tokens for GCP access tokens using GCP's Workload Identity Federation.
// Optionally, it can also impersonate a service account if configured.
type CredentialsProvider interface {
	// GetCredentials exchanges an ID token for GCP access tokens and returns a channel to receive them.
	// The channel provides updates when credentials are refreshed or removed.
	// For the first credential and each refresh, an Update event is sent.
	// In case of errors, the Err field is populated, Credential is nil, and the refresh loop exits.
	// When the refresh loop exits, the channel is closed.
	// The tokenProvider is used to obtain the ID token for exchange.
	// Options can be provided to configure the request (e.g., audience, scopes, service account impersonation).
	GetCredentials(ctx context.Context, tokenProvider token.IdentityTokenProvider, opts ...option.Option) (<-chan credential.Result, error)
}

var _ CredentialsProvider = &credentialsProvider{}

// credentialsProvider is the internal implementation of CredentialsProvider.
type credentialsProvider struct {
	logger     logr.Logger
	stsService *stsv1.Service
}

// setDefaults sets default values for the credentialsConfig.
func setDefaults(cfg *credentialsConfig) {
	if len(cfg.scopes) == 0 {
		cfg.scopes = []string{"https://www.googleapis.com/auth/cloud-platform", "https://www.googleapis.com/auth/userinfo.email"}
	}
}

// validateConfig validates the configuration and returns an error if any required field is missing.
func validateConfig(cfg *credentialsConfig) error {
	if cfg.audience == "" {
		return errors.New("audience is required")
	}

	if cfg.serviceAccountEmail != "" {
		if cfg.tokenLifetime != nil && *cfg.tokenLifetime > 3600 { // 1 hour in seconds
			return errors.New("tokenLifetime must be less than or equal to 3600 seconds (1 hour)")
		}
	}

	if cfg.identityTokenProvider == nil {
		return errors.New("identity token provider must be specified")
	}

	if len(cfg.scopes) == 0 {
		return errors.New("at least one scope must be specified")
	}

	return nil
}

// refreshCredentialsLoop handles the credential retrieval and refresh loop.
func (cp *credentialsProvider) refreshCredentialsLoop(
	ctx context.Context,
	genAccessTokenFunc func() (*oauth2.Token, error),
	credsChan chan credential.Result,
) {
	for {
		accessToken, err := genAccessTokenFunc()
		if err != nil {
			util.SendToChannel(credsChan, credential.Result{
				Credential: nil,
				Err:        errors.WrapIf(err, "failed to get access token"),
			})

			return
		}

		// Send credentials
		gcpCredential := credential.Oauth2Creds(*accessToken)
		util.SendToChannel(credsChan, credential.Result{
			Credential: &gcpCredential,
			Err:        nil,
			Event:      credential.UpdateEventType,
		})

		cp.logger.V(2).Info("Sent credentials", "expires", accessToken.Expiry)

		// Calculate when to refresh
		timeUntilExpiry := time.Until(accessToken.Expiry)

		// If credentials are already expired, this is an error
		if timeUntilExpiry <= 0 {
			util.SendToChannel(credsChan, credential.Result{
				Credential: nil,
				Err:        errors.NewWithDetails("received already expired credentials", "expiresAt", accessToken.Expiry),
			})

			return
		}

		refreshBuffer := util.CalculateRefreshBuffer(timeUntilExpiry)
		refreshTime := timeUntilExpiry - refreshBuffer

		cp.logger.V(1).Info("Scheduling credential refresh", "refreshIn", refreshTime, "refreshBuffer", refreshBuffer, "expiresAt", accessToken.Expiry)

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

// NewCredentialsProvider creates a new instance of CredentialsProvider for GCP.
// The returned provider can be used to obtain GCP access tokens by exchanging ID tokens
// using GCP's Workload Identity Federation functionality.
//
// Parameters:
//   - ctx: The context for the operation
//   - logger: Logger for logging credential operations
//
// Returns:
//   - A credential provider that can exchange ID tokens for GCP access tokens
//   - An error if the provider cannot be created
func NewCredentialsProvider(ctx context.Context, logger logr.Logger) (*credentialsProvider, error) {
	stsService, err := stsv1.NewService(ctx, google_option.WithoutAuthentication())
	if err != nil {
		return nil, errors.WrapIf(err, "failed to create STS service")
	}

	return &credentialsProvider{
		logger:     logger.WithName("gcp_credentials"),
		stsService: stsService,
	}, nil
}

type Provider interface {
	isGCP()
}

func (cp *credentialsProvider) isGCP() {}

// GetCredentialsWithOptions returns GCP credentials using the provided options.
// It applies any credential-specific options, validates the config, and delegates to GetCredentials.
// This method implements the credential.Provider interface and is the primary entry point for obtaining GCP credentials.
// The returned channel will receive credential updates, including initial credentials and refreshed credentials before expiration.
//
// Options can include:
//   - Audience for the token exchange
//   - Scopes for the access token
//   - Service account email for impersonation
//   - Token lifetime for impersonated service account tokens
//   - Identity token provider
func (cp *credentialsProvider) GetCredentialsWithOptions(ctx context.Context, opts ...option.Option) (<-chan credential.Result, error) {
	cfg := &credentialsConfig{}

	setDefaults(cfg)

	// Apply options
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

// GetCredentials exchanges an ID token for GCP credentials and returns a channel to receive them.
func (cp *credentialsProvider) GetCredentials(
	ctx context.Context,
	tokenProvider token.IdentityTokenProvider,
	opts ...option.Option,
) (<-chan credential.Result, error) {
	// Initialize configuration
	cfg := &credentialsConfig{
		identityTokenProvider: tokenProvider,
	}

	setDefaults(cfg)

	// Apply options
	for _, opt := range opts {
		if opt, ok := isCredentialsOption(opt); ok {
			opt.Apply(cfg)
		}
	}

	// Validate mandatory configurations
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	// Validate that we can get an initial token
	tokenOpts := []option.Option{}
	if cfg.serviceAccountEmail == "" {
		option.WithBoolean(AlwaysGenerateIDTokenOptionID, true)
	}
	_, err := tokenProvider.GetToken(ctx, tokenOpts...)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to get initial ID token")
	}

	var scope string
	if cfg.serviceAccountEmail != "" {
		// set scope needed for service account impersonation
		scope = "https://www.googleapis.com/auth/iam"
	} else {
		// STS expects multiple scopes to be provided as space separated strings
		scope = strings.Join(cfg.scopes, " ")
	}

	stsAccessTokenSource := &stsAccessTokenSource{
		stsService:      cp.stsService,
		idTokenProvider: tokenProvider,
		audience:        cfg.audience,
		scope:           scope,
		ctx:             ctx,
	}

	stsAccessToken, err := stsAccessTokenSource.Token()
	if err != nil {
		return nil, errors.WrapIf(err, "failed to get initial STS access token")
	}

	cp.logger.V(2).Info("Initial STS access token retrieved", "expiry", stsAccessToken.Expiry)

	genAccessTokenFunc := func() (*oauth2.Token, error) {
		// if no service account impersonation is needed, return the STS access token
		return stsAccessTokenSource.Token()
	}

	if cfg.serviceAccountEmail != "" {
		stsAccessToken := oauth2.ReuseTokenSource(stsAccessToken, stsAccessTokenSource)

		// if service account impersonation is needed, generate access token for the service account
		genAccessTokenFunc = func() (*oauth2.Token, error) {
			return generateAccessToken(ctx, stsAccessToken, cfg.serviceAccountEmail, cfg.scopes, cfg.tokenLifetime)
		}
	}

	credsChan := make(chan credential.Result, 1)

	go func() {
		defer close(credsChan)
		cp.refreshCredentialsLoop(ctx, genAccessTokenFunc, credsChan)
	}()

	return credsChan, nil
}
