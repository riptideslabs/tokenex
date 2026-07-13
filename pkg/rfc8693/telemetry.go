// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package rfc8693

import (
	"time"

	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/oauth2"
)

const fetchSpanName = "credential.fetch"

const instrumentationScopeName = "go.riptides.io/tokenex/pkg/rfc8693"

// allowedAdditionalFieldKeys defines the cfg.additionalFields keys that may be
// exposed in telemetry. These fields are populated by the OpenAI WIF integration
// and are restricted to non-secret identifiers.
var allowedAdditionalFieldKeys = []string{
	"identity_provider_id",
	"service_account_id",
	"client_id",
}

func fetchSpanConfigAttrs(cfg *credentialsConfig, correlationID string) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 7+len(allowedAdditionalFieldKeys))
	attrs = append(attrs,
		attribute.String("cfg.token_endpoint_url", cfg.tokenEndpointURL),
		attribute.StringSlice("cfg.scopes", cfg.scopes),
		attribute.String("cfg.subject_token_type", string(cfg.subjectTokenType)),
		attribute.String("correlation_id", correlationID),
	)

	if cfg.actorTokenProvider != nil {
		actorTokenType := cfg.actorTokenType
		if actorTokenType == "" {
			actorTokenType = TokenTypeJWT
		}

		attrs = append(attrs, attribute.String("cfg.actor_token_type", string(actorTokenType)))
	}

	if cfg.requestedTokenType != "" {
		attrs = append(attrs, attribute.String("cfg.requested_token_type", cfg.requestedTokenType))
	}

	if cfg.audience != "" {
		attrs = append(attrs, attribute.String("cfg.audience", cfg.audience))
	}

	for _, k := range allowedAdditionalFieldKeys {
		if v, ok := cfg.additionalFields[k]; ok {
			attrs = append(attrs, attribute.String("cfg."+k, v))
		}
	}

	return attrs
}

func fetchSpanResultAttrs(tok *oauth2.Token) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.Bool("credential.expires", !tok.Expiry.IsZero()),
	}
	if !tok.Expiry.IsZero() {
		attrs = append(attrs, attribute.String("credential.expires_at", tok.Expiry.UTC().Format(time.RFC3339)))
	}

	return attrs
}
