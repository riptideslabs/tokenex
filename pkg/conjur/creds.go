// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

// Package conjur retrieves secrets from CyberArk Conjur (CyberArk Secrets Manager, Self-Hosted and SaaS).
//
// The provider exchanges an identity JWT for a short-lived Conjur access token using the JWT
// authenticator (authn-jwt), then reads the configured variables in one batch request. Conjur
// variables carry no lease, so they are read again every poll interval to pick up rotated values.
package conjur

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"emperror.dev/errors"
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

// CredentialsProvider defines the interface for obtaining secrets from Conjur.
type CredentialsProvider interface {
	// GetCredentials exchanges an ID token for a Conjur access token and retrieves the configured variables.
	// The channel receives an Update event with a *credential.Secret for the first read and each poll.
	// In case of errors, the Err field is populated, Credential is nil, and the refresh loop exits.
	// When the refresh loop exits, the channel is closed.
	GetCredentials(ctx context.Context, tokenProvider token.IdentityTokenProvider, opts ...option.Option) (<-chan credential.Result, error)
}

var _ CredentialsProvider = &credentialsProvider{}

type credentialsConfig struct {
	account               string
	serviceID             string
	hostID                string
	variables             map[string]string
	pollInterval          time.Duration
	identityTokenProvider token.IdentityTokenProvider

	tracerProvider trace.TracerProvider
}

type credentialsProvider struct {
	logger       logr.Logger
	applianceURL string
	httpClient   *http.Client
}

type Provider interface {
	isConjur()
}

func (cp *credentialsProvider) isConjur() {}

func setDefaults(cfg *credentialsConfig) {
	if cfg.pollInterval == 0 {
		cfg.pollInterval = 15 * time.Minute
	}
}

func validateConfig(cfg *credentialsConfig) error {
	if cfg.account == "" {
		return errors.New("account is required")
	}

	if cfg.serviceID == "" {
		return errors.New("service ID is required")
	}

	if len(cfg.variables) == 0 {
		return errors.New("at least one variable is required")
	}

	for key, id := range cfg.variables {
		if key == "" {
			return errors.NewWithDetails("variable key must not be empty", "variable_id", id)
		}

		if id == "" {
			return errors.NewWithDetails("variable ID must not be empty", "key", key)
		}

		// The batch retrieval endpoint separates variable IDs with commas.
		if strings.Contains(id, ",") {
			return errors.NewWithDetails("variable ID must not contain a comma", "variable_id", id)
		}
	}

	if cfg.pollInterval <= 0 {
		return errors.New("poll interval must be greater than zero")
	}

	if cfg.identityTokenProvider == nil {
		return errors.New("identity token provider must be specified")
	}

	return nil
}

// hostLogin returns the Conjur login of a host, which carries a "host/" prefix.
func hostLogin(hostID string) string {
	if strings.HasPrefix(hostID, "host/") {
		return hostID
	}

	return "host/" + hostID
}

// variableIDs returns the distinct variable IDs in sorted order.
func variableIDs(variables map[string]string) []string {
	ids := slices.Collect(maps.Values(variables))
	slices.Sort(ids)

	return slices.Compact(ids)
}

// authenticate exchanges an ID token for a Conjur access token using the JWT authenticator.
// The access token is returned base64 encoded, the form it takes in the Authorization header.
func (cp *credentialsProvider) authenticate(ctx context.Context, cfg *credentialsConfig) (string, error) {
	idToken, err := cfg.identityTokenProvider.GetToken(ctx)
	if err != nil {
		return "", errors.WrapIf(err, "failed to get ID token")
	}

	trace.SpanFromContext(ctx).SetAttributes(tokenextelemetry.IdentityTokenAttrs("id_token", idToken.Token, idToken.ExpiresAt)...)

	authnURL := cp.applianceURL + "/authn-jwt/" + url.PathEscape(cfg.serviceID) + "/" + url.PathEscape(cfg.account)
	if cfg.hostID != "" {
		authnURL += "/" + url.PathEscape(hostLogin(cfg.hostID))
	}
	authnURL += "/authenticate"

	body := url.Values{"jwt": {idToken.Token}}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authnURL, strings.NewReader(body))
	if err != nil {
		return "", errors.WrapIf(err, "failed to create authentication request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := cp.httpClient.Do(req)
	if err != nil {
		return "", errors.WrapIf(err, "authentication request failed")
	}

	defer resp.Body.Close()

	accessToken, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.WrapIf(err, "could not read authentication response body")
	}

	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("failed to authenticate with Conjur, status %d: %s", resp.StatusCode, accessToken)
	}

	if len(accessToken) == 0 {
		return "", errors.New("empty access token returned by Conjur")
	}

	return base64.StdEncoding.EncodeToString(accessToken), nil
}

// retrieveVariables reads all configured variables in one batch request and returns their values
// keyed by variable ID.
func (cp *credentialsProvider) retrieveVariables(ctx context.Context, cfg *credentialsConfig, accessToken string) (map[string]string, error) {
	ids := variableIDs(cfg.variables)

	fullIDs := make([]string, len(ids))
	for i, id := range ids {
		fullIDs[i] = cfg.account + ":variable:" + id
	}

	secretsURL := cp.applianceURL + "/secrets?variable_ids=" + url.QueryEscape(strings.Join(fullIDs, ","))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, secretsURL, nil)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to create secrets request")
	}
	req.Header.Set("Authorization", `Token token="`+accessToken+`"`)
	// Ask for base64 encoded values so binary secrets survive the JSON response.
	req.Header.Set("Accept-Encoding", "base64")

	resp, err := cp.httpClient.Do(req)
	if err != nil {
		return nil, errors.WrapIf(err, "secrets request failed")
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WrapIf(err, "could not read secrets response body")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("failed to retrieve variables, status %d: %s", resp.StatusCode, body)
	}

	var byFullID map[string]string
	if err := json.Unmarshal(body, &byFullID); err != nil {
		return nil, errors.WrapIf(err, "failed to parse secrets response")
	}

	// Conjur versions without base64 support ignore Accept-Encoding and return the values as they are.
	decode := resp.Header.Get("Content-Encoding") == "base64"

	values := make(map[string]string, len(ids))
	for i, id := range ids {
		v, ok := byFullID[fullIDs[i]]
		if !ok {
			return nil, errors.NewWithDetails("variable missing from secrets response", "variable_id", id)
		}

		if decode {
			b, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, errors.WrapIfWithDetails(err, "failed to decode variable value", "variable_id", id)
			}
			v = string(b)
		}

		values[id] = v
	}

	return values, nil
}

// retrieveSecret authenticates to Conjur and returns the configured variables under their keys.
func (cp *credentialsProvider) retrieveSecret(ctx context.Context, cfg *credentialsConfig) (*credential.Secret, error) {
	accessToken, err := cp.authenticate(ctx, cfg)
	if err != nil {
		return nil, err
	}

	values, err := cp.retrieveVariables(ctx, cfg, accessToken)
	if err != nil {
		return nil, err
	}

	data := make(map[string]any, len(cfg.variables))
	for key, id := range cfg.variables {
		data[key] = values[id]
	}

	return &credential.Secret{Data: data}, nil
}

func fetchCredentials(ctx context.Context, tracer trace.Tracer, configAttrs []attribute.KeyValue, cp *credentialsProvider, cfg *credentialsConfig) (*credential.Secret, error) {
	ctx, span := tracer.Start(ctx, fetchSpanName, trace.WithAttributes(configAttrs...))
	defer span.End()

	secret, err := cp.retrieveSecret(ctx, cfg)
	if err != nil {
		tokenextelemetry.RecordResult(span, err)

		return nil, err
	}

	span.SetAttributes(fetchSpanResultAttrs()...)
	tokenextelemetry.RecordResult(span, nil)

	return secret, nil
}

// refreshCredentialsLoop reads the variables every poll interval until the context is canceled or a read fails.
func (cp *credentialsProvider) refreshCredentialsLoop(ctx context.Context, cfg *credentialsConfig, credsChan chan credential.Result) {
	tracer := tokenextelemetry.Tracer(ctx, cfg.tracerProvider, instrumentationScopeName)
	configAttrs := fetchSpanConfigAttrs(cfg, cp.applianceURL, uuid.NewString())

	logger := cp.logger.WithValues("service_id", cfg.serviceID, "variable_ids", variableIDs(cfg.variables))

	for {
		select {
		case <-ctx.Done():
			logger.V(1).Info("Context cancelled, stopping credential refresh")

			return
		default:
		}

		secret, err := fetchCredentials(ctx, tracer, configAttrs, cp, cfg)
		if err != nil {
			util.SendErrorToChannel(credsChan, err)

			return
		}

		util.SendToChannel(credsChan, credential.Result{
			Credential: secret,
			Event:      credential.UpdateEventType,
		})
		logger.V(2).Info("Published Conjur secret", "nextPollIn", cfg.pollInterval)

		select {
		case <-ctx.Done():
			logger.V(1).Info("Context cancelled, stopping credential refresh")

			return
		case <-time.After(cfg.pollInterval):
		}
	}
}

// NewCredentialsProvider creates a CredentialsProvider for the Conjur instance at applianceURL,
// e.g. "https://conjur.example.com" for Self-Hosted or "https://<subdomain>.secretsmgr.cyberark.cloud/api"
// for SaaS. tlsConfig is optional; set its RootCAs when Conjur's certificate is issued by a private CA.
func NewCredentialsProvider(_ context.Context, logger logr.Logger, applianceURL string, tlsConfig *tls.Config) (*credentialsProvider, error) {
	u, err := url.Parse(applianceURL)
	if err != nil {
		return nil, errors.WrapIfWithDetails(err, "invalid Conjur appliance URL", "url", applianceURL)
	}

	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.NewWithDetails("Conjur appliance URL must be an absolute http(s) URL without query or fragment", "url", applianceURL)
	}

	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = t.Clone()
	}

	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig.Clone()
	}

	return &credentialsProvider{
		logger:       logger.WithName("conjur_credentials"),
		applianceURL: strings.TrimSuffix(applianceURL, "/"),
		httpClient:   &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}, nil
}

// GetCredentialsWithOptions returns Conjur secrets using the provided options.
// This method implements the credential.Provider interface.
//
// Required options: WithAccount, WithServiceID, WithVariables, WithIdentityTokenProvider.
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

// GetCredentials exchanges an ID token for Conjur secrets and returns a channel to receive them.
func (cp *credentialsProvider) GetCredentials(ctx context.Context, tokenProvider token.IdentityTokenProvider, opts ...option.Option) (<-chan credential.Result, error) {
	cfg := &credentialsConfig{}
	setDefaults(cfg)

	cfg.identityTokenProvider = tokenProvider

	for _, opt := range opts {
		if opt, ok := isCredentialsOption(opt); ok {
			opt.Apply(cfg)
		}
	}

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	// Validate that we can get an initial token
	t, err := cfg.identityTokenProvider.GetToken(ctx)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to get initial ID token")
	}

	if t.ExpiresAt.Before(time.Now()) {
		return nil, errors.NewWithDetails("initial ID token is expired or has no expiry", "expiry", t.ExpiresAt)
	}

	credsChan := make(chan credential.Result, 1)

	go func() {
		defer close(credsChan)
		cp.refreshCredentialsLoop(ctx, cfg, credsChan)
	}()

	return credsChan, nil
}
