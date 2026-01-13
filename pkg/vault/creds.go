// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package vault

import (
	"context"
	"time"

	"emperror.dev/errors"
	"github.com/go-logr/logr"
	jwtauth "github.com/openbao/openbao/api/auth/jwt/v2"
	"github.com/openbao/openbao/api/v2"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
	"go.riptides.io/tokenex/pkg/util"
)

// ErrDataNotFound is returned when secret at a the specified secret path does not exist in Vault.
var ErrDataNotFound = errors.New("data not found")

// credentialsConfig holds the configuration for GetCredentials.
type credentialsConfig struct {
	jwtAuthMethodPath     string
	jwtAuthRoleName       string
	secretFullPath        string
	pollInterval          time.Duration
	reqData               map[string][]string
	identityTokenProvider token.IdentityTokenProvider
}

// credentialData holds the secret data and expiration information returned from Vault.
type credentialData struct {
	// Data contains the secret data retrieved from Vault.
	Data map[string]interface{}

	// ExpiresAt is the time when the credentials expire and should no longer be used.
	ExpiresAt time.Time

	// RefreshOn is an optional field specifying when to refresh the credentials.
	// If set, the refresh should occur at this time instead of being calculated from ExpiresAt.
	RefreshOn time.Time
}

// CredentialsProvider defines the interface for obtaining Vault credentials.
// It exchanges ID tokens for Vault tokens using Vault's JWT auth method,
// then retrieves secrets from various secret engines.
type CredentialsProvider interface {
	// GetCredentials exchanges an ID token for a Vault token and retrieves secrets.
	// The channel provides updates when credentials are refreshed or removed.
	// For the first credential and each refresh, an Update event is sent.
	// In case of errors, the Err field is populated, Credential is nil, and the refresh loop exits.
	// When the refresh loop exits, the channel is closed.
	// The tokenProvider is used to obtain the ID token for exchange.
	// Options can be provided to configure the request (e.g., vault address, JWT role, secret path).
	GetCredentials(ctx context.Context, tokenProvider token.IdentityTokenProvider, opts ...option.Option) (<-chan credential.Result, error)
}

var _ CredentialsProvider = &credentialsProvider{}

// credentialsProvider is the internal implementation of CredentialsProvider.
type credentialsProvider struct {
	logger logr.Logger
	client *api.Client
}

func setDefaults(cfg *credentialsConfig) {
	if len(cfg.jwtAuthMethodPath) == 0 {
		cfg.jwtAuthMethodPath = "jwt"
	}

	if cfg.pollInterval == 0 {
		cfg.pollInterval = 15 * time.Minute
	}
}

// validateConfig validates the configuration and returns an error if any required field is missing.
func validateConfig(cfg *credentialsConfig) error {
	if cfg.jwtAuthMethodPath == "" {
		return errors.New("JWT auth method path is required")
	}

	if cfg.jwtAuthRoleName == "" {
		return errors.New("JWT Auth role is required")
	}

	if cfg.secretFullPath == "" {
		return errors.New("secret path is required")
	}

	if cfg.pollInterval <= 0 {
		return errors.New("poll interval must be greater than zero")
	}

	if cfg.identityTokenProvider == nil {
		return errors.New("identity token provider must be specified")
	}

	return nil
}

type Provider interface {
	isVault()
}

func (cp *credentialsProvider) isVault() {}

// authenticateWithJWT exchanges an ID token for a Vault token using JWT auth method
func (cp *credentialsProvider) authenticateWithJWT(ctx context.Context, idToken credential.Token, jwtAuthMethodPath string, roleName string) error {
	authMethod, err := jwtauth.New(
		roleName,
		jwtauth.WithMountPath(jwtAuthMethodPath),
		jwtauth.WithToken(idToken.Token),
	)
	if err != nil {
		return errors.WrapIfWithDetails(err, "failed to create JWT auth method", "auth_path", jwtAuthMethodPath, "role", roleName)
	}

	secret, err := cp.client.Auth().Login(ctx, authMethod)
	if err != nil {
		return errors.WrapIfWithDetails(err, "failed to authenticate with Vault using JWT", "auth_path", jwtAuthMethodPath, "role", roleName)
	}

	if secret == nil || secret.Auth == nil {
		return errors.NewWithDetails("no authentication data returned from Vault", "auth_path", jwtAuthMethodPath, "role", roleName)
	}

	// Set the token for subsequent requests
	cp.client.SetToken(secret.Auth.ClientToken)

	return nil
}

// retrieveCredentials retrieves a secret from Vault at the specified path.
// For dynamic secrets (with a lease), expiration is based on the lease duration.
// For static secrets (no lease), expiration is based on the secret's TTL if available,
// or falls back to the poll interval to ensure periodic refresh.
func (cp *credentialsProvider) retrieveCredentials(ctx context.Context, secretPath string, pollInterval time.Duration) (*credentialData, error) {
	secret, err := cp.client.Logical().ReadWithContext(ctx, secretPath)
	if err != nil {
		return nil, errors.WrapIfWithDetails(err, "failed to read secret", "path", secretPath)
	}
	if secret == nil {
		return nil, errors.WithDetails(ErrDataNotFound, "path", secretPath)
	}

	var expiresAt time.Time
	// If LeaseID is present, this is a dynamic credential (e.g., database, cloud secret).
	// Set expiration based on the lease duration returned by Vault.
	if secret.LeaseID != "" {
		expiresAt = time.Now().Add(time.Duration(secret.LeaseDuration) * time.Second)

		return &credentialData{
			Data:      secret.Data,
			ExpiresAt: expiresAt,
		}, nil
	}

	// No lease ID present, so this is a static credential.
	// For static credentials, check if a TTL is associated with the secret.
	// If a TTL is present, Vault will automatically rotate the secret after the TTL expires.
	// If no TTL is present, fall back to using the poll interval to ensure the secret is periodically refreshed.
	ttl, err := secret.TokenTTL()
	if err != nil {
		return nil, errors.WrapIfWithDetails(err, "failed to get secret TTL", "path", secretPath)
	}

	// Add a small leeway to allow Vault to rotate static credentials before we attempt to refresh.
	staticCredsRotationLeeway := 5 * time.Second
	if ttl == 0 {
		// No TTL means the secret does not expire and Vault will not rotate it automatically.
		// In this case, set the expiration to the poll interval to ensure we periodically check for updates to the secret in Vault.
		ttl = pollInterval
		staticCredsRotationLeeway = 0 // No leeway needed since Vault won't rotate this credential.
	}
	expiresAt = time.Now().Add(ttl)

	return &credentialData{
		Data:      secret.Data,
		ExpiresAt: expiresAt,
		RefreshOn: expiresAt.Add(staticCredsRotationLeeway),
	}, nil
}

// refreshCredentialsLoop handles the credential retrieval and refresh loop.
func (cp *credentialsProvider) refreshCredentialsLoop(ctx context.Context, cfg *credentialsConfig, credsChan chan credential.Result) {
	for {
		// Get ID token
		idToken, err := cfg.identityTokenProvider.GetToken(ctx)
		if err != nil {
			util.SendToChannel(credsChan, credential.Result{
				Credential: nil,
				Err:        errors.WrapIf(err, "failed to get ID token"),
			})

			return
		}

		// Authenticate with Vault using JWT
		err = cp.authenticateWithJWT(ctx, idToken, cfg.jwtAuthMethodPath, cfg.jwtAuthRoleName)
		if err != nil {
			util.SendToChannel(credsChan, credential.Result{
				Credential: nil,
				Err:        errors.WrapIf(err, "failed to authenticate with Vault"),
			})

			return
		}

		// Retrieve the secret
		creds, err := cp.retrieveCredentials(ctx, cfg.secretFullPath, cfg.pollInterval, cfg.reqData)
		if err != nil {
			util.SendToChannel(credsChan, credential.Result{
				Credential: nil,
				Err:        errors.WrapIf(err, "failed to retrieve secret"),
			})

			return
		}

		// Calculate when to refresh
		timeUntilExpiry := time.Until(creds.ExpiresAt)

		// If credentials are already expired, this is an error
		if timeUntilExpiry <= 0 {
			util.SendToChannel(credsChan, credential.Result{
				Credential: nil,
				Err:        errors.NewWithDetails("received already expired credentials", "secret_path", cfg.secretFullPath, "expiresAt", creds.ExpiresAt),
			})

			return
		}

		// Send credentials
		util.SendToChannel(credsChan, credential.Result{
			Credential: &credential.VaultSecret{
				Data: creds.Data,
			},
			Err:   nil,
			Event: credential.UpdateEventType,
		})

		cp.logger.V(2).Info("Published Vault secret", "secret_path", cfg.secretFullPath, "expiresAt", creds.ExpiresAt)

		// Apply refresh buffer
		var refreshBuffer, refreshTime time.Duration

		if !creds.RefreshOn.IsZero() {
			// if refresh time is specified in the received credentials, use that
			cp.logger.V(2).Info("Using RefreshOn time from credentials", "refreshOn", creds.RefreshOn)

			refreshTime = time.Until(creds.RefreshOn)
		} else {
			refreshBuffer = util.CalculateRefreshBuffer(timeUntilExpiry)
			refreshTime = timeUntilExpiry - refreshBuffer
		}

		cp.logger.V(1).Info("Scheduling credential refresh", "refreshIn", refreshTime, "refreshBuffer", refreshBuffer, "secret_path", cfg.secretFullPath)

		select {
		case <-ctx.Done():
			cp.logger.V(1).Info("Context cancelled, stopping credential refresh")

			return
		case <-time.After(refreshTime):
			// Continue to next iteration to refresh
			cp.logger.V(2).Info("Refreshing credentials", "secret_path", cfg.secretFullPath)
		}
	}
}

// NewCredentialsProvider creates a new instance of CredentialsProvider for Vault.
// The returned provider can be used to obtain secrets from Vault by exchanging ID tokens
// for Vault tokens using Vault's JWT authentication method.
//
// Parameters:
//   - ctx: The context for the operation
//   - logger: Logger for logging credential operations
//   - vaultAddr: The Vault server address (e.g., "https://vault.example.com:8200")
//
// Returns:
//   - A credential provider that can exchange ID tokens for Vault secrets
//   - An error if the provider cannot be created
func NewCredentialsProvider(ctx context.Context, logger logr.Logger, vaultAddr string) (*credentialsProvider, error) {
	if vaultAddr == "" {
		return nil, errors.New("vault address must be provided")
	}

	config := api.DefaultConfig()
	config.Address = vaultAddr

	client, err := api.NewClient(config)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to create Vault client")
	}

	return &credentialsProvider{
		logger: logger.WithName("vault_credentials"),
		client: client,
	}, nil
}

// GetCredentialsWithOptions returns Vault credentials using the provided options.
// It applies any credential-specific options, validates the config, and delegates to GetCredentials.
// This method implements the credential.Provider interface and is the primary entry point for obtaining Vault credentials.
// The returned channel will receive credential updates, including initial credentials and refreshed credentials before expiration.
func (cp *credentialsProvider) GetCredentialsWithOptions(ctx context.Context, opts ...option.Option) (<-chan credential.Result, error) {
	cfg := &credentialsConfig{}
	setDefaults(cfg)

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

// GetCredentials exchanges an ID token for Vault credentials and returns a channel to receive them.
func (cp *credentialsProvider) GetCredentials(ctx context.Context, tokenProvider token.IdentityTokenProvider, opts ...option.Option) (<-chan credential.Result, error) {
	cfg := &credentialsConfig{}
	setDefaults(cfg)

	cfg.identityTokenProvider = tokenProvider

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
	t, err := tokenProvider.GetToken(ctx)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to get initial ID token")
	}

	if t.ExpiresAt.Before(time.Now()) {
		return nil, errors.NewWithDetails("initial ID token is already expired", "expiry", t.ExpiresAt)
	}

	credsChan := make(chan credential.Result, 1)

	go func() {
		defer close(credsChan)
		cp.refreshCredentialsLoop(ctx, cfg, credsChan)
	}()

	return credsChan, nil
}
