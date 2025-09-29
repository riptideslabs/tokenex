// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package generic

import (
	"context"
	"time"

	"emperror.dev/errors"
	"github.com/go-logr/logr"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
	"go.riptides.io/tokenex/pkg/util"
)

type (
	Credential = credential.Result
)

// CredentialsProvider defines the interface for obtaining generic credentials.
// It simply returns the token provided by the identity token provider and refreshes it before expiration.
// This provider is useful when you just need to pass through tokens from an identity provider.
type CredentialsProvider interface {
	// GetCredentials returns a channel that receives the tokens from the provided token provider.
	// The channel provides updates when tokens are refreshed or removed.
	// For the first token and each refresh, an Update event is sent.
	// In case of errors, the Err field is populated, Credential is nil, and the refresh loop exits.
	// When the refresh loop exits, the channel is closed.
	// The tokenProvider is used to obtain the tokens.
	// Options can be provided to configure the token provider.
	GetCredentials(ctx context.Context, tokenProvider token.IdentityTokenProvider, opts ...option.Option) (<-chan Credential, error)
}

var _ CredentialsProvider = &credentialsProvider{}

type credentialsConfig struct {
	tokenProvider token.IdentityTokenProvider
}

type credentialsProvider struct {
	logger logr.Logger
}

type Provider interface {
	isGenericTokenProvider()
}

func (cp *credentialsProvider) isGenericTokenProvider() {}

// validateConfig validates the configuration and returns an error if any required field is missing.
func validateConfig(cfg *credentialsConfig) error {
	if cfg.tokenProvider == nil {
		return errors.NewPlain("token provider must be specified")
	}

	return nil
}

// NewCredentialsProvider creates a new instance of CredentialsProvider for generic token handling.
// The returned provider simply passes through tokens from the identity token provider and refreshes them before expiration.
// This provider is useful when you just need to use tokens directly from an identity provider without exchanging them.
//
// Parameters:
//   - ctx: The context for the operation
//   - logger: Logger for logging credential operations
//
// Returns:
//   - A credential provider that passes through tokens from the identity token provider
//   - An error if the provider cannot be created
func NewCredentialsProvider(ctx context.Context, logger logr.Logger) (*credentialsProvider, error) {
	return &credentialsProvider{
		logger: logger,
	}, nil
}

// GetCredentialsWithOptions returns generic credentials using the provided options.
// It applies any credential-specific options, validates the config, and delegates to GetCredentials.
// This method implements the credential.Provider interface and is the primary entry point for obtaining generic credentials.
// The returned channel will receive token updates, including initial tokens and refreshed tokens before expiration.
//
// Options can include:
//   - Token provider
func (cp *credentialsProvider) GetCredentialsWithOptions(ctx context.Context, opts ...option.Option) (<-chan Credential, error) {
	cfg := &credentialsConfig{}

	for _, opt := range opts {
		if opt, ok := isCredentialsOption(opt); ok {
			opt.Apply(cfg)
		}
	}

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return cp.GetCredentials(ctx, cfg.tokenProvider, opts...)
}

func (cp *credentialsProvider) GetCredentials(
	ctx context.Context,
	tokenProvider token.IdentityTokenProvider,
	opts ...option.Option,
) (<-chan Credential, error) {
	// Initialize configuration
	cfg := &credentialsConfig{
		tokenProvider: tokenProvider,
	}

	// Validate configuration
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	// Apply options
	for _, opt := range opts {
		if opt, ok := isCredentialsOption(opt); ok {
			opt.Apply(cfg)
		}
	}

	credsChan := make(chan credential.Result, 1)

	go func() {
		defer close(credsChan)
		cp.refreshCredentialsLoop(ctx, cfg.tokenProvider, credsChan, opts...)
	}()

	return credsChan, nil
}

// refreshCredentialsLoop handles the credential retrieval and refresh loop.
func (cp *credentialsProvider) refreshCredentialsLoop(
	ctx context.Context,
	tokenProvider token.IdentityTokenProvider,
	credsChan chan credential.Result,
	opts ...option.Option,
) {
	var err error
	var token credential.Token

loop:
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if token.Token != "" && token.ExpiresAt.IsZero() {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second * 5):
					// the received token never expires
					continue loop
				}
			}

			token, err = tokenProvider.GetToken(ctx, opts...)
			if err != nil {
				util.SendToChannel(credsChan, credential.Result{
					Credential: nil,
					Err:        errors.WrapIf(err, "could not create token"),
				})

				return
			}

			util.SendToChannel(credsChan, credential.Result{
				Credential: &credential.Token{
					Token:     token.Token,
					ExpiresAt: token.ExpiresAt,
				},
				Err:   nil,
				Event: credential.UpdateEventType,
			})

			// the received token never expires
			if token.ExpiresAt.IsZero() {
				cp.logger.V(2).Info("credential sent", "expiresAt", "never")

				continue
			}

			cp.logger.V(2).Info("credential sent", "expiresAt", token.ExpiresAt.Format(time.DateTime))

			// Calculate when to refresh
			timeUntilExpiry := time.Until(token.ExpiresAt)

			// If credentials are already expired, this is an error
			if timeUntilExpiry <= 0 {
				util.SendToChannel(credsChan, credential.Result{
					Credential: nil,
					Err:        errors.NewWithDetails("received already expired credentials", "expiresAt", token.ExpiresAt.Format(time.DateTime)),
				})

				return
			}

			refreshBuffer := util.CalculateRefreshBuffer(timeUntilExpiry)
			refreshTime := timeUntilExpiry - refreshBuffer

			cp.logger.V(2).Info("schedule credential refresh", "refreshIn", refreshTime, "refreshBuffer", refreshBuffer, "expiresAt", token.ExpiresAt.Format(time.DateTime))

			select {
			case <-ctx.Done():
				cp.logger.V(2).Info("context cancelled, stopping credential refresh")

				return
			case <-time.After(refreshTime):
				// Continue to next iteration to refresh
				cp.logger.V(2).Info("refreshing credentials")
			}
		}
	}
}
