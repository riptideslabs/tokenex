// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package vault

import (
	"context"
	"time"

	"emperror.dev/errors"
	"github.com/go-logr/logr"
	"github.com/go-viper/mapstructure/v2"
	jwtauth "github.com/openbao/openbao/api/auth/jwt/v2"
	"github.com/openbao/openbao/api/v2"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
	"go.riptides.io/tokenex/pkg/util"
)

// ErrDataNotFound is returned when secret at a the specified secret path does not exist in Vault.
var ErrDataNotFound = errors.New("data not found")

// gcpCredentialConfig holds configuration specific to GCP credentials returned by the Google Cloud secrets engine in Vault.
type gcpCredentialConfig struct {
	// Exchange service account key material for a short-lived access token
	// This option is used only when the Google Cloud secrets engine is configured to return service account keys.
	exchangeSAKeyForAccessToken bool

	// accessTokenScopes specifies the scopes to request when exchanging a service account key for an access token.
	// This option is used only when exchangeSAKeyForAccessToken is true.
	// If not set, it defaults to ["https://www.googleapis.com/auth/cloud-platform"].
	accessTokenScopes []string
}

func (g *gcpCredentialConfig) ExchangeSAKeyForAccessToken() bool {
	if g != nil {
		return g.exchangeSAKeyForAccessToken
	}

	return false
}

func (g *gcpCredentialConfig) AccessTokenScopes() []string {
	if g != nil {
		return g.accessTokenScopes
	}

	return nil
}

// azureCredentialConfig holds configuration specific to Azure credentials returned by the Azure secrets engine in Vault.
type azureCredentialConfig struct {
	// exchangeForAccessToken indicates whether to exchange the client ID and client secret returned by Vault for an Azure access token.
	exchangeForAccessToken bool

	// tenantID is the Azure tenant ID to use when exchanging Vault credentials for an Azure access token. This is required when exchangeForAccessToken is true.
	tenantID string

	// accessTokenScopes specifies the scopes to request when exchanging Azure credentials for an access token.
	// This option is used only when exchangeForAccessToken is true.
	// If not set, it defaults to ["https://management.azure.com/.default"].
	accessTokenScopes []string
}

func (a *azureCredentialConfig) ExchangeForAccessToken() bool {
	if a != nil {
		return a.exchangeForAccessToken
	}

	return false
}

func (a *azureCredentialConfig) TenantID() string {
	if a != nil {
		return a.tenantID
	}

	return ""
}

func (a *azureCredentialConfig) AccessTokenScopes() []string {
	if a != nil {
		return a.accessTokenScopes
	}

	return nil
}

// credentialsConfig holds the configuration for GetCredentials.
type credentialsConfig struct {
	jwtAuthMethodPath     string
	jwtAuthRoleName       string
	secretFullPath        string
	pollInterval          time.Duration
	reqData               map[string][]string
	identityTokenProvider token.IdentityTokenProvider

	gcp   *gcpCredentialConfig
	azure *azureCredentialConfig
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

	if cfg.azure != nil {
		if cfg.azure.exchangeForAccessToken && cfg.azure.tenantID == "" {
			return errors.New("Azure tenant ID must be specified when exchange for access token is enabled")
		}
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

func (cp *credentialsProvider) authenticate(ctx context.Context, cfg *credentialsConfig) error {
	// Get ID token
	idToken, err := cfg.identityTokenProvider.GetToken(ctx)
	if err != nil {
		return errors.WrapIf(err, "failed to get ID token")
	}

	// Authenticate with Vault using JWT
	err = cp.authenticateWithJWT(ctx, idToken, cfg.jwtAuthMethodPath, cfg.jwtAuthRoleName)
	if err != nil {
		return errors.WrapIfWithDetails(err, "failed to authenticate with Vault", "auth_path", cfg.jwtAuthMethodPath, "role", cfg.jwtAuthRoleName)
	}

	return nil
}

// retrieveCredentials retrieves a secret from Vault at the specified path.
// For dynamic secrets (with a lease), expiration is based on the lease duration.
// For static secrets (no lease), expiration is based on the secret's TTL if available,
// or falls back to the poll interval to ensure periodic refresh.
func (cp *credentialsProvider) retrieveCredentials(ctx context.Context, cfg *credentialsConfig) (*credentialData, error) {
	err := cp.authenticate(ctx, cfg)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to authenticate with Vault")
	}

	secret, err := cp.client.Logical().ReadWithDataWithContext(ctx, cfg.secretFullPath, cfg.reqData)
	if err != nil {
		return nil, errors.WrapIfWithDetails(err, "failed to read secret", "path", cfg.secretFullPath)
	}
	if secret == nil {
		return nil, errors.WithDetails(ErrDataNotFound, "path", cfg.secretFullPath)
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
		return nil, errors.WrapIfWithDetails(err, "failed to get secret TTL", "path", cfg.secretFullPath)
	}

	// Add a small leeway to allow Vault to rotate static credentials before we attempt to refresh.
	staticCredsRotationLeeway := 5 * time.Second
	if ttl == 0 {
		// No TTL means the secret does not expire and Vault will not rotate it automatically.
		// In this case, set the expiration to the poll interval to ensure we periodically check for updates to the secret in Vault.
		ttl = cfg.pollInterval
		staticCredsRotationLeeway = 0 // No leeway needed since Vault won't rotate this credential.
	}
	expiresAt = time.Now().Add(ttl)

	return &credentialData{
		Data:      secret.Data,
		ExpiresAt: expiresAt,
		RefreshOn: expiresAt.Add(staticCredsRotationLeeway),
	}, nil
}

// startGcpAccessTokenProvider starts a worker goroutine that exchanges a GCP service account key for an access token and refreshes it as needed until the context is canceled.
func (cp *credentialsProvider) startGcpAccessTokenProvider(ctx context.Context, secretData map[string]any, scopes []string) (<-chan credential.Result, error) {
	var serviceAccountKeySecret gcpServiceAccountKeySecret
	if err := mapstructure.Decode(secretData, &serviceAccountKeySecret); err != nil {
		return nil, errors.WrapIf(err, "failed to decode Vault secret data into GCP service account key credentials structure")
	}

	keyJSON, err := serviceAccountKeySecret.ServiceAccountKeyJSON()
	if err != nil {
		return nil, errors.WrapIf(err, "failed to get service account key JSON")
	}

	if len(scopes) == 0 {
		scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
	}

	provider := gcpAccessTokenProvider{
		serviceAccountKeyJSON: keyJSON,
		scopes:                scopes,
		logger:                logr.FromContextOrDiscard(ctx).WithName("gcp_access_token_provider"),
	}

	credsChan := make(chan credential.Result, 1)
	go func() {
		defer close(credsChan)
		provider.GetCredentials(ctx, credsChan)
	}()

	return credsChan, nil
}

// startAzureAccessTokenProvider starts a worker goroutine that exchanges Azure credentials for an access token and refreshes it as needed until the context is canceled.
func (cp *credentialsProvider) startAzureAccessTokenProvider(ctx context.Context, secretData map[string]any, tenantID string, scopes []string) (<-chan credential.Result, error) {
	var azureSecret vaultAzureSecret

	if err := mapstructure.Decode(secretData, &azureSecret); err != nil {
		return nil, errors.WrapIf(err, "failed to decode Vault secret data into Azure credentials structure")
	}

	if len(scopes) == 0 {
		scopes = []string{"https://management.azure.com/.default"}
	}

	provider := azureAccessTokenProvider{
		tenantID:     tenantID,
		clientID:     azureSecret.ClientID,
		clientSecret: azureSecret.ClientSecret,
		scopes:       scopes,
	}

	credsChan := make(chan credential.Result, 1)
	go func() {
		defer close(credsChan)
		provider.GetCredentials(ctx, credsChan)
	}()

	return credsChan, nil
}

// shouldStartWorker determines whether a worker goroutine should be started to handle credential exchange and refresh based on the configuration.
func shouldStartWorker(cfg *credentialsConfig) bool {
	return cfg.gcp.ExchangeSAKeyForAccessToken() || cfg.azure.ExchangeForAccessToken()
}

func (cp *credentialsProvider) startWorker(ctx context.Context, cfg *credentialsConfig, credsData map[string]any) (<-chan credential.Result, context.CancelFunc, error) {
	if cfg.gcp.ExchangeSAKeyForAccessToken() {
		// get access token using the service account key data in the Vault secret
		// and send the access token through the channel instead of the raw service account key data
		ctx, cancel := context.WithCancel(ctx)
		credsChan, err := cp.startGcpAccessTokenProvider(ctx, credsData, cfg.gcp.accessTokenScopes)
		if err != nil {
			return nil, cancel, errors.WrapIf(err, "failed to start GCP access token provider")
		}

		return credsChan, cancel, nil
	}

	if cfg.azure.ExchangeForAccessToken() {
		// get access token using the client ID and client secret data in the Vault secret
		ctx, cancel := context.WithCancel(ctx)
		credsChan, err := cp.startAzureAccessTokenProvider(ctx, credsData, cfg.azure.TenantID(), cfg.azure.AccessTokenScopes())
		if err != nil {
			return nil, cancel, errors.WrapIf(err, "failed to start Azure access token provider")
		}

		return credsChan, cancel, nil
	}

	return nil, nil, nil
}

// refreshCredentialsLoop handles the credential retrieval and refresh loop.
func (cp *credentialsProvider) refreshCredentialsLoop(ctx context.Context, cfg *credentialsConfig, credsChan chan credential.Result) {
	var cancelWorker context.CancelFunc
	var workerChan <-chan credential.Result

	var refreshBuffer, refreshTime time.Duration

	logger := cp.logger.WithValues("secret_path", cfg.secretFullPath)

	for {
		select {
		case <-ctx.Done():
			logger.V(1).Info("Context cancelled, stopping credential refresh")

			return
		case <-time.After(refreshTime):
			logger.V(2).Info("Refreshing credentials")
			if cancelWorker != nil {
				cancelWorker() // cancel any existing worker goroutine before starting a new one to refresh credentials
				cancelWorker = nil
			}

			// Retrieve the secret
			creds, err := cp.retrieveCredentials(ctx, cfg)
			if err != nil {
				util.SendErrorToChannel(credsChan, errors.WrapIfWithDetails(err, "failed to retrieve secret", "secret_path", cfg.secretFullPath))

				return
			}

			// Calculate when to refresh
			timeUntilExpiry := time.Until(creds.ExpiresAt)

			// If credentials are already expired, this is an error
			if timeUntilExpiry <= 0 {
				util.SendErrorToChannel(credsChan, errors.NewWithDetails("received already expired credentials", "secret_path", cfg.secretFullPath, "expiresAt", creds.ExpiresAt))

				return
			}

			if shouldStartWorker(cfg) {
				workerChan, cancelWorker, err = cp.startWorker(logr.NewContext(ctx, logger), cfg, creds.Data)
				if err != nil {
					util.SendErrorToChannel(credsChan, errors.WrapIf(err, "failed to start credential worker"))

					return
				}
			} else {
				// Send credentials
				util.SendToChannel(credsChan, credential.Result{
					Credential: &credential.VaultSecret{
						Data: creds.Data,
					},
					Err:   nil,
					Event: credential.UpdateEventType,
				})
				logger.V(2).Info("Published Vault secret", "secret_path", cfg.secretFullPath, "expiresAt", creds.ExpiresAt)
			}

			if !creds.RefreshOn.IsZero() {
				// if refresh time is specified in the received credentials, use that
				logger.V(2).Info("Using RefreshOn time from credentials", "refreshOn", creds.RefreshOn)

				refreshTime = time.Until(creds.RefreshOn)
			} else {
				refreshBuffer = util.CalculateRefreshBuffer(timeUntilExpiry)
				refreshTime = timeUntilExpiry - refreshBuffer
			}

			logger.V(1).Info("Scheduling credential refresh", "refreshIn", refreshTime, "refreshBuffer", refreshBuffer, "secret_path", cfg.secretFullPath)
		case result, ok := <-workerChan:
			if !ok {
				// Worker channel closed, likely due to an error in the worker goroutine
				util.SendErrorToChannel(credsChan, errors.New("credential worker stopped unexpectedly"))

				return
			}

			if result.Err != nil {
				util.SendErrorToChannel(credsChan, result.Err)

				return
			}

			util.SendToChannel(credsChan, result)
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
//   - clientTLSConfig: Optional client TLS configuration for secure communication with Vault
//
// Returns:
//   - A credential provider that can exchange ID tokens for Vault secrets
//   - An error if the provider cannot be created
func NewCredentialsProvider(ctx context.Context, logger logr.Logger, vaultAddr string, clientTLSConfig *api.TLSConfig) (*credentialsProvider, error) {
	if vaultAddr == "" {
		return nil, errors.New("vault address must be provided")
	}

	config := &api.Config{
		Address: vaultAddr,
	}

	// Configure TLS if provided
	if clientTLSConfig != nil {
		err := config.ConfigureTLS(clientTLSConfig)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to configure TLS for Vault client")
		}
	}

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
