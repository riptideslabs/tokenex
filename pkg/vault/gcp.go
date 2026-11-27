// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/cenkalti/backoff/v5"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"go.riptides.io/tokenex/internal/httpx"
	"go.riptides.io/tokenex/pkg/credential"
	tokenextelemetry "go.riptides.io/tokenex/pkg/telemetry"
	"go.riptides.io/tokenex/pkg/util"
)

const gcpExchangeSpanName = "vault.gcp.exchange_access_token"

func gcpExchangeSpanConfigAttrs(scopes []string, correlationID string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.StringSlice("cfg.scopes", scopes),
		attribute.String("correlation_id", correlationID),
	}
}

func gcpExchangeSpanResultAttrs(tok *oauth2.Token) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Bool("credential.expires", true),
		attribute.String("credential.expires_at", tok.Expiry.UTC().Format(time.RFC3339)),
	}
}

// gcpServiceAccountKeySecret represents the structure of the service account key material returned by Vault's Google Cloud secrets engine when configured to return service account keys.
// It contains the base64-encoded private key data.
type gcpServiceAccountKeySecret struct {
	PrivateKeyData string `mapstructure:"private_key_data"`
}

// ServiceAccountKeyJSON decodes the base64-encoded private key data from the Vault secret and returns it as a byte slice.
func (s *gcpServiceAccountKeySecret) ServiceAccountKeyJSON() ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s.PrivateKeyData)
	if err != nil {
		return nil, errors.WrapIf(err, "private_key_data in Vault secret data for GCP credentials is not valid base64 encoded string")
	}

	return key, nil
}

// gcpTokenHosts are the hosts of Google's OAuth 2.0 token endpoints outside googleapis.com.
var gcpTokenHosts = []string{"accounts.google.com"}

// isGCPTokenHost accepts Google's token hosts: any googleapis.com host, which
// covers regional and Private Service Connect endpoints, and oauth2.<domain>
// for the universe domain the caller allowed. The key names its own universe
// domain too, but the key is what is being checked.
func isGCPTokenHost(host, universeDomain string) bool {
	host = strings.ToLower(host)

	if host == "googleapis.com" || strings.HasSuffix(host, ".googleapis.com") || slices.Contains(gcpTokenHosts, host) {
		return true
	}

	return universeDomain != "" && host == "oauth2."+strings.ToLower(universeDomain)
}

// checkGCPTokenURI rejects a service account key whose token_uri is not one
// of Google's, or of the universe domain the caller allowed. The key comes
// from the Vault secret, and the signed assertion is sent to that URI.
func checkGCPTokenURI(keyJSON []byte, universeDomain string) error {
	var key struct {
		TokenURI string `json:"token_uri"`
	}

	if err := json.Unmarshal(keyJSON, &key); err != nil {
		return errors.WrapIf(err, "service account key is not valid JSON")
	}

	if key.TokenURI == "" {
		return nil
	}

	u, err := url.Parse(key.TokenURI)
	if err != nil || u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") || !isGCPTokenHost(u.Hostname(), universeDomain) {
		return errors.NewWithDetails("token_uri of the service account key is not a Google token endpoint", "token_uri", httpx.RedactURL(key.TokenURI))
	}

	return nil
}

// gcpAccessTokenProvider is responsible for exchanging a GCP service account key for an access token and refreshing it as needed until stopped.
type gcpAccessTokenProvider struct {
	serviceAccountKeyJSON []byte
	scopes                []string
	tracer                trace.Tracer

	logger logr.Logger
}

func (r *gcpAccessTokenProvider) fetchAccessToken(ctx context.Context, parentSpanContext trace.SpanContext, configAttrs []attribute.KeyValue) (*oauth2.Token, error) {
	fetchCtx, span := r.tracer.Start(ctx, gcpExchangeSpanName, trace.WithAttributes(configAttrs...), trace.WithLinks(trace.Link{SpanContext: parentSpanContext}))
	defer span.End()

	// The token source takes its HTTP client from the context. The default one
	// has no timeout and follows redirects.
	fetchCtx = context.WithValue(fetchCtx, oauth2.HTTPClient, httpx.ExchangeClient(nil))

	// use the service account key to authenticate to GCP and obtain an access token
	gcpCreds, err := google.CredentialsFromJSONWithType(fetchCtx, r.serviceAccountKeyJSON, google.ServiceAccount, r.scopes...)
	if err != nil {
		err = errors.WrapIf(err, "failed to obtain GCP credentials from service account key")
		tokenextelemetry.RecordResult(span, err)

		return nil, err
	}

	// if the SA key was just created it's possible that it may take a few seconds for GCP to propagate the key and allow it to be used for authentication.
	// This can result in transient errors when trying to exchange the key for an access token.
	b := backoff.NewExponentialBackOff()
	token, err := backoff.Retry(fetchCtx, func() (*oauth2.Token, error) {
		token, err := gcpCreds.TokenSource.Token()
		if err != nil {
			if strings.Contains(err.Error(), "invalid_grant") {
				r.logger.V(2).Info("Received invalid_grant error when exchanging service account key for access token, likely due to GCP propagation delay. Retrying...", "error", err)

				return nil, err
			}

			return nil, backoff.Permanent(errors.WrapIf(err, "failed to exchange service account key for access token"))
		}

		return token, nil
	}, backoff.WithBackOff(b), backoff.WithMaxElapsedTime(30*time.Second))
	if err != nil {
		err = errors.WrapIf(err, "failed to obtain access token from GCP using service account key")
		tokenextelemetry.RecordResult(span, err)

		return nil, err
	}

	span.SetAttributes(gcpExchangeSpanResultAttrs(token)...)
	tokenextelemetry.RecordResult(span, nil)

	return token, nil
}

// GetCredentials begins the process of exchanging the service account key for an access token and refreshing it as needed until the context is canceled.
func (r *gcpAccessTokenProvider) GetCredentials(ctx context.Context, parentSpanContext trace.SpanContext, credsChan chan credential.Result) {
	correlationID := uuid.NewString()
	configAttrs := gcpExchangeSpanConfigAttrs(r.scopes, correlationID)

	for {
		token, err := r.fetchAccessToken(ctx, parentSpanContext, configAttrs)
		if err != nil {
			util.SendErrorToChannel(credsChan, err)

			return
		}

		// Calculate when to refresh
		timeUntilExpiry := time.Until(token.Expiry)

		// If credentials are already expired, this is an error
		if timeUntilExpiry <= 0 {
			util.SendErrorToChannel(credsChan, errors.NewWithDetails("received already expired access token from GCP", "expiresAt", token.Expiry))

			return
		}

		gcpCredential := credential.Oauth2Creds(*token)
		util.SendToChannel(credsChan, credential.Result{
			Credential: &gcpCredential,
			Err:        nil,
			Event:      credential.UpdateEventType,
		})

		r.logger.V(2).Info("Published access token", "expiresAt", token.Expiry)

		refreshBuffer := util.CalculateRefreshBuffer(timeUntilExpiry)
		refreshTime := timeUntilExpiry - refreshBuffer

		r.logger.V(0).Info("Scheduling access token refresh", "refreshIn", refreshTime, "refreshBuffer", refreshBuffer)

		select {
		case <-ctx.Done():
			r.logger.V(1).Info("Context cancelled, stopping access token refresh")

			return
		case <-time.After(refreshTime):
			// Continue to next iteration to refresh
			r.logger.V(2).Info("Refreshing access token")
		}
	}
}
