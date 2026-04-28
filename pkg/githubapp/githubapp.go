// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package githubapp

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strconv"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v66/github"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/util"
)

// credentialsConfig holds the configuration for a GetCredentials call.
type credentialsConfig struct {
	appID          int64
	installationID int64
	privateKey     *rsa.PrivateKey

	repositories  []string
	repositoryIDs []int64
	permissions   *github.InstallationPermissions

	baseURL    string
	httpClient *http.Client
}

func setDefaults(cfg *credentialsConfig) {
	if cfg.baseURL == "" {
		cfg.baseURL = "https://api.github.com"
	}

	cfg.baseURL = strings.TrimRight(cfg.baseURL, "/")

	if cfg.httpClient == nil {
		cfg.httpClient = http.DefaultClient
	}
}

func validateConfig(cfg *credentialsConfig) error {
	if cfg.appID == 0 {
		return errors.New("appID is required")
	}

	if cfg.installationID == 0 {
		return errors.New("installationID is required")
	}

	if cfg.privateKey == nil {
		return errors.New("privateKey is required")
	}

	if len(cfg.repositories) > 0 && len(cfg.repositoryIDs) > 0 {
		return errors.New("specify either repositories or repositoryIDs, not both")
	}

	return nil
}

// ParsePrivateKey parses a PEM-encoded RSA private key. It accepts both PKCS#1
// ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY" wrapping an RSA key) blocks.
// Non-RSA keys and non-PEM inputs return an error.
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("private key is not PEM-encoded")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to parse PKCS#1 RSA private key")
		}

		return key, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to parse PKCS#8 private key")
		}

		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.Errorf("PKCS#8 private key is not RSA (type %T)", parsed)
		}

		return key, nil
	default:
		return nil, errors.Errorf("unexpected PEM block type %q (want \"RSA PRIVATE KEY\" or \"PRIVATE KEY\")", block.Type)
	}
}

// signAppJWT mints a short-lived RS256 JWT used to authenticate as the GitHub
// App when calling the installation token endpoint. iat is set 60s in the past
// to absorb minor clock skew (GitHub's documented recommendation), and exp is
// set 9 minutes ahead — under GitHub's 10-minute cap, with headroom for the
// exchange call.
func signAppJWT(appID int64, privateKey *rsa.PrivateKey) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    strconv.FormatInt(appID, 10),
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signed, err := tok.SignedString(privateKey)
	if err != nil {
		return "", errors.WrapIf(err, "failed to sign App JWT")
	}

	return signed, nil
}

// appJWTTransport is an http.RoundTripper that signs a fresh GitHub App JWT
// and injects it as an Authorization: Bearer header before delegating to a
// base transport. The base transport is whatever the user supplied via
// WithHTTPClient (or http.DefaultTransport otherwise).
type appJWTTransport struct {
	base       http.RoundTripper
	appID      int64
	privateKey *rsa.PrivateKey
}

// RoundTrip implements http.RoundTripper.
func (t *appJWTTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	signed, err := signAppJWT(t.appID, t.privateKey)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to sign App JWT for request")
	}

	// http.RoundTripper contract requires not modifying the request; clone first.
	cloned := req.Clone(req.Context())
	cloned.Header.Set("Authorization", "Bearer "+signed)

	return t.base.RoundTrip(cloned)
}

// newAppClient builds a *github.Client whose transport signs an App JWT on every
// request. When cfg.baseURL is the github.com default the standard client is
// returned; for any other baseURL (GHES) WithEnterpriseURLs is applied.
func newAppClient(cfg *credentialsConfig) (*github.Client, error) {
	base := cfg.httpClient.Transport
	if base == nil {
		base = http.DefaultTransport
	}

	httpClient := &http.Client{
		Transport: &appJWTTransport{
			base:       base,
			appID:      cfg.appID,
			privateKey: cfg.privateKey,
		},
		Timeout: cfg.httpClient.Timeout,
	}

	client := github.NewClient(httpClient)

	if cfg.baseURL == "https://api.github.com" {
		return client, nil
	}

	// Pass cfg.baseURL for both the API and Upload URLs. This provider only
	// mints installation tokens — it never uploads — so go-github's derived
	// UploadURL is unused and intentionally not computed correctly.
	withEnterprise, err := client.WithEnterpriseURLs(cfg.baseURL, cfg.baseURL)
	if err != nil {
		return nil, errors.WrapIfWithDetails(err, "failed to configure GitHub Enterprise base URL", "baseURL", cfg.baseURL)
	}

	return withEnterprise, nil
}

// CredentialsProvider issues GitHub App installation access tokens.
//
// Each call to GetCredentials starts a goroutine that mints a token, sends it
// on the returned channel as a credential.Update event, and refreshes it before
// expiry. On any error the loop exits, an error result is sent, and the channel
// is closed — caller is responsible for restart/retry. The loop also exits when
// the context is cancelled.
type CredentialsProvider interface {
	GetCredentials(ctx context.Context, opts ...option.Option) (<-chan credential.Result, error)
}

// Provider is a marker interface so callers can identify a githubapp provider
// at the type level, matching the convention used by the other providers.
type Provider interface {
	isGithubApp()
}

type credentialsProvider struct {
	logger logr.Logger
}

func (cp *credentialsProvider) isGithubApp() {}

var (
	_ CredentialsProvider = (*credentialsProvider)(nil)
	_ credential.Provider = (*credentialsProvider)(nil)
)

// NewCredentialsProvider creates a new GitHub App installation token provider.
func NewCredentialsProvider(_ context.Context, logger logr.Logger) (*credentialsProvider, error) {
	return &credentialsProvider{
		logger: logger.WithName("github_app_credentials"),
	}, nil
}

// GetCredentialsWithOptions implements credential.Provider. Because every input
// is option-shaped, it simply delegates to GetCredentials.
func (cp *credentialsProvider) GetCredentialsWithOptions(ctx context.Context, opts ...option.Option) (<-chan credential.Result, error) {
	return cp.GetCredentials(ctx, opts...)
}

// GetCredentials starts the refresh loop and returns a channel of installation
// token updates.
func (cp *credentialsProvider) GetCredentials(ctx context.Context, opts ...option.Option) (<-chan credential.Result, error) {
	cfg := &credentialsConfig{}

	for _, opt := range opts {
		if o, ok := isCredentialsOption(opt); ok {
			o.Apply(cfg)
		}
	}

	setDefaults(cfg)

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	credsChan := make(chan credential.Result, 1)

	go func() {
		defer close(credsChan)
		cp.refreshLoop(ctx, cfg, credsChan)
	}()

	return credsChan, nil
}

func (cp *credentialsProvider) refreshLoop(ctx context.Context, cfg *credentialsConfig, credsChan chan credential.Result) {
	logger := cp.logger.WithValues("appID", cfg.appID, "installationID", cfg.installationID)

	client, err := newAppClient(cfg)
	if err != nil {
		util.SendErrorToChannel(credsChan, err)

		return
	}

	opts := &github.InstallationTokenOptions{
		Repositories:  cfg.repositories,
		RepositoryIDs: cfg.repositoryIDs,
		Permissions:   cfg.permissions,
	}

	for {
		tok, _, err := client.Apps.CreateInstallationToken(ctx, cfg.installationID, opts)
		if err != nil {
			util.SendErrorToChannel(credsChan, errors.WrapIfWithDetails(err, "failed to mint installation token", "appID", cfg.appID, "installationID", cfg.installationID))

			return
		}

		if tok.GetToken() == "" {
			util.SendErrorToChannel(credsChan, errors.NewWithDetails("empty installation token returned", "appID", cfg.appID, "installationID", cfg.installationID))

			return
		}

		expiresAt := tok.GetExpiresAt().Time
		if expiresAt.IsZero() {
			util.SendErrorToChannel(credsChan, errors.NewWithDetails("installation token has no expires_at", "appID", cfg.appID, "installationID", cfg.installationID))

			return
		}

		timeUntilExpiry := time.Until(expiresAt)
		if timeUntilExpiry <= 0 {
			util.SendErrorToChannel(credsChan, errors.NewWithDetails(
				"received already expired installation token",
				"appID", cfg.appID,
				"installationID", cfg.installationID,
				"expiresAt", expiresAt,
			))

			return
		}

		util.SendToChannel(credsChan, credential.Result{
			Credential: &credential.Token{
				Token:     tok.GetToken(),
				ExpiresAt: expiresAt,
			},
			Event: credential.UpdateEventType,
		})

		logger.V(2).Info("installation token sent", "expiresAt", expiresAt.Format(time.DateTime))

		refreshBuffer := util.CalculateRefreshBuffer(timeUntilExpiry)
		refreshTime := timeUntilExpiry - refreshBuffer

		logger.V(2).Info("scheduling installation token refresh", "refreshIn", refreshTime, "refreshBuffer", refreshBuffer)

		t := time.NewTimer(refreshTime)

		select {
		case <-ctx.Done():
			t.Stop()
			logger.V(2).Info("context cancelled, stopping installation token refresh")

			return
		case <-t.C:
			logger.V(2).Info("refreshing installation token")
		}
	}
}
