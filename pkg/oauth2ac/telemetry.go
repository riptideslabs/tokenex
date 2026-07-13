// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package oauth2ac

import (
	"time"

	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/oauth2"
)

const fetchSpanName = "credential.fetch"

const instrumentationScopeName = "go.riptides.io/tokenex/pkg/oauth2ac"

func exchangeSpanConfigAttrs(cfg *CredentialsConfig, clientID string, correlationID string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("cfg.grant_type", "authorization_code"),
		attribute.String("cfg.authorization_endpoint_url", cfg.AuthorizationEndpointURL),
		attribute.String("cfg.token_endpoint_url", cfg.TokenEndpointURL),
		attribute.StringSlice("cfg.scopes", cfg.Scopes),
		attribute.Bool("cfg.use_pkce", cfg.UsePKCE),
		attribute.String("cfg.client_id", clientID),
		attribute.String("correlation_id", correlationID),
	}
}

func fetchSpanConfigAttrs(cfg *CredentialsConfig, clientID string, correlationID string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("cfg.grant_type", "refresh_token"),
		attribute.String("cfg.token_endpoint_url", cfg.TokenEndpointURL),
		attribute.StringSlice("cfg.scopes", cfg.Scopes),
		attribute.String("cfg.client_id", clientID),
		attribute.String("correlation_id", correlationID),
	}
}

func resultAttrs(tok *oauth2.Token) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.Bool("credential.expires", !tok.Expiry.IsZero()),
	}
	if !tok.Expiry.IsZero() {
		attrs = append(attrs, attribute.String("credential.expires_at", tok.Expiry.UTC().Format(time.RFC3339)))
	}

	return attrs
}
