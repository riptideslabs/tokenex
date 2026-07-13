// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package gcp

import (
	"time"

	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/oauth2"
)

const fetchSpanName = "credential.fetch"

const instrumentationScopeName = "go.riptides.io/tokenex/pkg/gcp"

func fetchSpanConfigAttrs(cfg *credentialsConfig, correlationID string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("cfg.audience", cfg.audience),
		attribute.StringSlice("cfg.scopes", cfg.scopes),
		attribute.String("correlation_id", correlationID),
	}
	if cfg.serviceAccountEmail != "" {
		attrs = append(attrs, attribute.String("cfg.service_account_email", cfg.serviceAccountEmail))
	}
	if cfg.tokenLifetime != nil {
		attrs = append(attrs, attribute.Int64("cfg.token_lifetime_seconds", *cfg.tokenLifetime))
	}

	return attrs
}

func fetchSpanResultAttrs(tok *oauth2.Token, impersonated bool) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Bool("credential.expires", true),
		attribute.String("credential.expires_at", tok.Expiry.UTC().Format(time.RFC3339)),
		attribute.Bool("credential.service_account_impersonation", impersonated),
	}
}
