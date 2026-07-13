// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package azure

import (
	"context"
	"time"

	"emperror.dev/errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	tokenextelemetry "go.riptides.io/tokenex/pkg/telemetry"
	"go.riptides.io/tokenex/pkg/token"
	"go.riptides.io/tokenex/pkg/util"
)

// credentialsConfig holds the configuration for GetCredentials.
type credentialsConfig struct {
	tenantID              string
	clientID              string
	scope                 string
	identityTokenProvider token.IdentityTokenProvider

	tracerProvider trace.TracerProvider
}

// CredentialsProvider defines the interface for obtaining Azure credentials.
// It exchanges ID tokens for Azure access tokens using Microsoft Entra ID's Workload Identity Federation.
type CredentialsProvider interface {
	// GetCredentials exchanges an ID token for Azure access tokens and returns a channel to receive them.
	// The channel provides updates when credentials are refreshed or removed.
	// For the first credential and each refresh, an Update event is sent.
	// In case of errors, the Err field is populated, Credential is nil, and the refresh loop exits.
	// When the refresh loop exits, the channel is closed.
	// The tokenProvider is used to obtain the ID token for exchange.
	// Options can be provided to configure the request (e.g., tenant ID, client ID, scope).
	GetCredentials(ctx context.Context, tokenProvider token.IdentityTokenProvider, opts ...option.Option) (<-chan credential.Result, error)
}

var _ CredentialsProvider = &credentialsProvider{}

// credentialsProvider is the internal implementation of CredentialsProvider.
type credentialsProvider struct {
	logger logr.Logger
}

// validateConfig validates the configuration and returns an error if any required field is missing.
func validateConfig(cfg *credentialsConfig) error {
	if cfg.tenantID == "" {
		return errors.New("tenantID is required")
	}

	if cfg.clientID == "" {
		return errors.New("clientID is required")
	}

	if cfg.scope == "" {
		return errors.New("scope is required")
	}

	if cfg.identityTokenProvider == nil {
		return errors.New("identity token provider must be specified")
	}

	return nil
}

type Provider interface {
	isAzure()
}

func (cp *credentialsProvider) isAzure() {}

func fetchCredentials(ctx context.Context, tracer trace.Tracer, configAttrs []attribute.KeyValue, cred *azidentity.ClientAssertionCredential, cfg *credentialsConfig) (azcore.AccessToken, error) {
	fetchCtx, span := tracer.Start(ctx, fetchSpanName, trace.WithAttributes(configAttrs...))
	defer span.End()

	tok, err := cred.GetToken(fetchCtx, policy.TokenRequestOptions{
		TenantID: cfg.tenantID,
		Scopes:   []string{cfg.scope},
	})
	if err != nil {
		err = errors.WrapIf(err, "failed to retrieve credentials")
		tokenextelemetry.RecordResult(span, err)

		return azcore.AccessToken{}, err
	}

	span.SetAttributes(fetchSpanResultAttrs(tok)...)
	tokenextelemetry.RecordResult(span, nil)

	return tok, nil
}

// refreshCredentialsLoop handles the credential retrieval and refresh loop.
func (cp *credentialsProvider) refreshCredentialsLoop(
	ctx context.Context,
	cfg *credentialsConfig,
	cred *azidentity.ClientAssertionCredential,
	credsChan chan credential.Result,
) {
	tracer := tokenextelemetry.Tracer(ctx, cfg.tracerProvider, instrumentationScopeName)
	correlationID := uuid.NewString()
	configAttrs := fetchSpanConfigAttrs(cfg, correlationID)

	for {
		tok, err := fetchCredentials(ctx, tracer, configAttrs, cred, cfg)
		if err != nil {
			util.SendErrorToChannel(credsChan, err)

			return
		}

		// Calculate when to refresh
		timeUntilExpiry := time.Until(tok.ExpiresOn)

		// If credentials are already expired, this is an error
		if timeUntilExpiry <= 0 {
			util.SendErrorToChannel(credsChan, errors.NewWithDetails("received already expired credentials", "expiresAt", tok.ExpiresOn))

			return
		}

		// Send credentials
		azureCredential := &credential.Oauth2Creds{
			AccessToken: tok.Token,
			TokenType:   "Bearer",
			Expiry:      tok.ExpiresOn,
		}
		util.SendToChannel(credsChan, credential.Result{
			Credential: azureCredential,
			Err:        nil,
			Event:      credential.UpdateEventType,
		})
		cp.logger.V(2).Info("Sent credentials", "expires", tok.ExpiresOn)

		refreshBuffer := util.CalculateRefreshBuffer(timeUntilExpiry)
		refreshTime := timeUntilExpiry - refreshBuffer

		if !tok.RefreshOn.IsZero() {
			// if refresh time is recommended in the received token, use that
			cp.logger.V(2).Info("Using RefreshOn time from token", "refreshOn", tok.RefreshOn)

			rt := time.Until(tok.RefreshOn)
			if rt > 0 {
				refreshTime = rt
			} else {
				cp.logger.V(2).Info("RefreshOn time is in the past, using calculated refresh time", "refreshTime", refreshTime)
			}
		}

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

// NewCredentialsProvider creates a new instance of CredentialsProvider for Azure.
// The returned provider can be used to obtain Azure access tokens by exchanging ID tokens
// using Microsoft Entra ID's Workload Identity Federation functionality.
//
// Parameters:
//   - ctx: The context for the operation
//   - logger: Logger for logging credential operations
//
// Returns:
//   - A credential provider that can exchange ID tokens for Azure access tokens
//   - An error if the provider cannot be created
func NewCredentialsProvider(ctx context.Context, logger logr.Logger) (*credentialsProvider, error) {
	return &credentialsProvider{
		logger: logger.WithName("azure_credentials"),
	}, nil
}

// GetCredentialsWithOptions returns Azure credentials using the provided options.
// It applies any credential-specific options, validates the config, and delegates to GetCredentials.
// This method implements the credential.Provider interface and is the primary entry point for obtaining Azure credentials.
// The returned channel will receive credential updates, including initial credentials and refreshed credentials before expiration.
//
// Options can include:
//   - Tenant ID for the Azure AD tenant
//   - Client ID for the application
//   - Scope for the access token
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

// GetCredentials exchanges an ID token for Azure credentials and returns a channel to receive them.
func (cp *credentialsProvider) GetCredentials(
	ctx context.Context,
	tokenProvider token.IdentityTokenProvider,
	opts ...option.Option,
) (<-chan credential.Result, error) {
	// Initialize configuration
	cfg := &credentialsConfig{
		identityTokenProvider: tokenProvider,
	}

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
	_, err := tokenProvider.GetToken(ctx)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to get initial ID token")
	}

	cred, err := azidentity.NewClientAssertionCredential(
		cfg.tenantID,
		cfg.clientID,
		func(ctx context.Context) (string, error) {
			idToken, err := tokenProvider.GetToken(ctx)
			if err != nil {
				return "", err
			}

			trace.SpanFromContext(ctx).SetAttributes(tokenextelemetry.IdentityTokenAttrs("id_token", idToken.Token, idToken.ExpiresAt)...)

			return idToken.Token, nil
		},
		nil,
	)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to create ClientAssertionCredential")
	}

	credsChan := make(chan credential.Result, 1)

	go func() {
		defer close(credsChan)
		cp.refreshCredentialsLoop(ctx, cfg, cred, credsChan)
	}()

	return credsChan, nil
}
