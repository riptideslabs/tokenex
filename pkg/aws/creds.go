// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package aws

import (
	"context"
	"time"

	"emperror.dev/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/go-logr/logr"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
	"go.riptides.io/tokenex/pkg/util"
)

// credentialsConfig holds the configuration for GetCredentials.
type credentialsConfig struct {
	roleArn               string
	roleSessionName       string
	durationSeconds       *int32
	identityTokenProvider token.IdentityTokenProvider
}

// CredentialsProvider defines the interface for obtaining AWS credentials.
// It exchanges ID tokens for AWS temporary session credentials using AWS's Workload Identity Federation.
type CredentialsProvider interface {
	// GetCredentials exchanges an ID token for AWS temporary session credentials and returns a channel to receive them.
	// The channel provides updates when credentials are refreshed or removed.
	// For the first credential and each refresh, an Update event is sent.
	// In case of errors, the Err field is populated, Credential is nil, and the refresh loop exits.
	// When the refresh loop exits, the channel is closed.
	// The tokenProvider is used to obtain the ID token for exchange.
	// Options can be provided to configure the request (e.g., role ARN, session name, duration).
	GetCredentials(ctx context.Context, tokenProvider token.IdentityTokenProvider, opts ...option.Option) (<-chan credential.Result, error)
}

var _ CredentialsProvider = &credentialsProvider{}

// credentialsProvider is the internal implementation of CredentialsProvider.
type credentialsProvider struct {
	logger    logr.Logger
	stsClient *sts.Client
}

// validateConfig validates the configuration and returns an error if any required field is missing.
func validateConfig(cfg *credentialsConfig) error {
	if cfg.roleArn == "" {
		return errors.New("roleArn is required")
	}

	if cfg.roleSessionName == "" {
		return errors.New("roleSessionName is required")
	}

	if cfg.identityTokenProvider == nil {
		return errors.New("identity token provider must be specified")
	}

	return nil
}

type Provider interface {
	isAWS()
}

func (cp *credentialsProvider) isAWS() {}

// refreshCredentialsLoop handles the credential retrieval and refresh loop.
func (cp *credentialsProvider) refreshCredentialsLoop(ctx context.Context, provider *stscreds.WebIdentityRoleProvider, credsChan chan credential.Result) {
	for {
		// Get credentials
		awsCreds, err := provider.Retrieve(ctx)
		if err != nil {
			util.SendToChannel(credsChan, credential.Result{
				Credential: nil,
				Err:        errors.WrapIf(err, "failed to retrieve credentials"),
			})

			return
		}

		// Send credentials
		creds := credential.AWSCreds(awsCreds)
		util.SendToChannel(credsChan, credential.Result{
			Credential: &creds,
			Err:        nil,
			Event:      credential.UpdateEventType,
		})

		// Check if credentials can expire
		if !awsCreds.CanExpire {
			cp.logger.V(1).Info("Credentials do not expire, no refresh needed")
			// Wait for context cancellation since credentials don't expire
			<-ctx.Done()
			cp.logger.V(1).Info("Context cancelled, stopping credential refresh")

			return
		}

		cp.logger.V(2).Info("Sent credentials", "expires", awsCreds.Expires)

		// Calculate when to refresh
		timeUntilExpiry := time.Until(awsCreds.Expires)

		// If credentials are already expired, this is an error
		if timeUntilExpiry <= 0 {
			util.SendToChannel(credsChan, credential.Result{
				Credential: nil,
				Err:        errors.NewWithDetails("received already expired credentials", "expiresAt", awsCreds.Expires),
			})

			return
		}

		refreshBuffer := util.CalculateRefreshBuffer(timeUntilExpiry)
		refreshTime := timeUntilExpiry - refreshBuffer

		cp.logger.V(1).Info("Scheduling credential refresh", "refreshIn", refreshTime, "refreshBuffer", refreshBuffer, "expiresAt", awsCreds.Expires)

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

// NewCredentialsProvider creates a new instance of CredentialsProvider for AWS.
// It accepts an optional AWS configuration. If not provided, it will use the default configuration.
// The returned provider can be used to obtain AWS temporary session credentials by exchanging ID tokens
// using AWS's Workload Identity Federation functionality.
//
// Parameters:
//   - ctx: The context for the operation
//   - logger: Logger for logging credential operations
//   - awsConfig: Optional AWS configuration. If nil, default configuration will be used.
//
// Returns:
//   - A credential provider that can exchange ID tokens for AWS credentials
//   - An error if the provider cannot be created
func NewCredentialsProvider(ctx context.Context, logger logr.Logger, awsConfig *aws.Config) (*credentialsProvider, error) {
	var cfg aws.Config

	var err error

	if awsConfig != nil {
		cfg = *awsConfig
	} else {
		cfg, err = config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to load default AWS config")
		}
	}

	stsClient := sts.NewFromConfig(cfg)

	return &credentialsProvider{
		stsClient: stsClient,
		logger:    logger.WithName("aws_credentials"),
	}, nil
}

// GetCredentialsWithOptions returns AWS credentials using the provided options.
// It applies any credential-specific options, validates the config, and delegates to GetCredentials.
// This method implements the credential.Provider interface and is the primary entry point for obtaining AWS credentials.
// The returned channel will receive credential updates, including initial credentials and refreshed credentials before expiration.
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

// GetCredentials exchanges an ID token for AWS credentials and returns a channel to receive them.
func (cp *credentialsProvider) GetCredentials(ctx context.Context, tokenProvider token.IdentityTokenProvider, opts ...option.Option) (<-chan credential.Result, error) {
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

	// Create WebIdentityRoleProvider options
	providerOpts := []func(*stscreds.WebIdentityRoleOptions){
		func(o *stscreds.WebIdentityRoleOptions) {
			o.RoleSessionName = cfg.roleSessionName
			if cfg.durationSeconds != nil {
				o.Duration = time.Duration(*cfg.durationSeconds) * time.Second
			}
		},
	}

	// Create the WebIdentityRoleProvider
	provider := stscreds.NewWebIdentityRoleProvider(
		cp.stsClient,
		cfg.roleArn,
		&tokenRetriever{provider: tokenProvider, ctx: ctx},
		providerOpts...,
	)

	credsChan := make(chan credential.Result, 1)

	go func() {
		defer close(credsChan)
		cp.refreshCredentialsLoop(ctx, provider, credsChan)
	}()

	return credsChan, nil
}
