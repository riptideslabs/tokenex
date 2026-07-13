// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package vault

import (
	"context"
	"time"

	"emperror.dev/errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/cenkalti/backoff/v5"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"go.riptides.io/tokenex/pkg/credential"
	tokenextelemetry "go.riptides.io/tokenex/pkg/telemetry"
	"go.riptides.io/tokenex/pkg/util"
)

const azureExchangeSpanName = "vault.azure.exchange_access_token"

func azureExchangeSpanConfigAttrs(tenantID string, clientID string, scopes []string, correlationID string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("cfg.tenant_id", tenantID),
		attribute.String("cfg.client_id", clientID),
		attribute.StringSlice("cfg.scopes", scopes),
		attribute.String("correlation_id", correlationID),
	}
}

func azureExchangeSpanResultAttrs(tok azcore.AccessToken) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Bool("credential.expires", true),
		attribute.String("credential.expires_at", tok.ExpiresOn.UTC().Format(time.RFC3339)),
	}
}

// VaultAzureSecret represents the structure of the secret data returned by Vault's Azure secrets engine when configured to return Azure credentials.
type vaultAzureSecret struct {
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
}

type azureAccessTokenProvider struct {
	tenantID     string
	clientID     string
	clientSecret string
	scopes       []string
	tracer       trace.Tracer

	logger logr.Logger
}

func (r *azureAccessTokenProvider) fetchAccessToken(ctx context.Context, parentSpanContext trace.SpanContext, configAttrs []attribute.KeyValue) (azcore.AccessToken, error) {
	fetchCtx, span := r.tracer.Start(ctx, azureExchangeSpanName, trace.WithAttributes(configAttrs...), trace.WithLinks(trace.Link{SpanContext: parentSpanContext}))
	defer span.End()

	azClientCreds, err := azidentity.NewClientSecretCredential(r.tenantID, r.clientID, r.clientSecret, nil)
	if err != nil {
		err = errors.WrapIf(err, "failed to create Azure client secret credential")
		tokenextelemetry.RecordResult(span, err)

		return azcore.AccessToken{}, err
	}

	b := backoff.NewExponentialBackOff()
	token, err := backoff.Retry(fetchCtx, func() (azcore.AccessToken, error) {
		token, err := azClientCreds.GetToken(fetchCtx, policy.TokenRequestOptions{
			Scopes: r.scopes,
		})

		return token, err
	}, backoff.WithBackOff(b), backoff.WithMaxElapsedTime(30*time.Second))
	if err != nil {
		err = errors.WrapIf(err, "failed to get Azure access token from client secret credential")
		tokenextelemetry.RecordResult(span, err)

		return azcore.AccessToken{}, err
	}

	span.SetAttributes(azureExchangeSpanResultAttrs(token)...)
	tokenextelemetry.RecordResult(span, nil)

	return token, nil
}

// GetCredentials begins the process of exchanging the client ID and client secret for an Azure access token and refreshing it as needed until the context is canceled.
func (r *azureAccessTokenProvider) GetCredentials(ctx context.Context, parentSpanContext trace.SpanContext, credsChan chan credential.Result) {
	correlationID := uuid.NewString()
	configAttrs := azureExchangeSpanConfigAttrs(r.tenantID, r.clientID, r.scopes, correlationID)

	for {
		token, err := r.fetchAccessToken(ctx, parentSpanContext, configAttrs)
		if err != nil {
			util.SendErrorToChannel(credsChan, err)

			return
		}

		// Calculate when to refresh
		timeUntilExpiry := time.Until(token.ExpiresOn)

		// If credentials are already expired, this is an error
		if timeUntilExpiry <= 0 {
			util.SendErrorToChannel(credsChan, errors.NewWithDetails("received already expired access token from Azure", "expiresAt", token.ExpiresOn))

			return
		}

		// Send credentials
		azureCredential := &credential.Oauth2Creds{
			AccessToken: token.Token,
			TokenType:   "Bearer",
			Expiry:      token.ExpiresOn,
		}
		util.SendToChannel(credsChan, credential.Result{
			Credential: azureCredential,
			Err:        nil,
			Event:      credential.UpdateEventType,
		})
		r.logger.V(2).Info("Sent credentials", "expires", token.ExpiresOn)

		refreshBuffer := util.CalculateRefreshBuffer(timeUntilExpiry)
		refreshTime := timeUntilExpiry - refreshBuffer

		if !token.RefreshOn.IsZero() {
			// if refresh time is recommended in the received token, use that
			r.logger.V(2).Info("Using RefreshOn time from token", "refreshOn", token.RefreshOn)

			rt := time.Until(token.RefreshOn)
			if rt > 0 {
				refreshTime = rt
			} else {
				r.logger.V(2).Info("RefreshOn time is in the past, using calculated refresh time", "refreshTime", refreshTime)
			}
		}

		select {
		case <-ctx.Done():
			r.logger.V(1).Info("Context cancelled, stopping credential refresh")

			return
		case <-time.After(refreshTime):
			// Continue to next iteration to refresh
			r.logger.V(2).Info("Refreshing access token")
		}
	}
}
