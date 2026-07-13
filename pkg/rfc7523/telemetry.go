// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package rfc7523

import (
	"time"

	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/oauth2"
)

const fetchSpanName = "credential.fetch"

const instrumentationScopeName = "go.riptides.io/tokenex/pkg/rfc7523"

// allowedAdditionalFieldKeys defines the cfg.additionalFields keys that may be
// exposed in telemetry. These fields are populated by the Anthropic WIF
// integration and are limited to non-secret identifiers.
var allowedAdditionalFieldKeys = []string{
	"federation_rule_id",
	"organization_id",
	"service_account_id",
	"workspace_id",
}

func bodyFormatString(f BodyFormat) string {
	switch f {
	case BodyFormatJSON:
		return "json"
	default:
		return "form"
	}
}

func fetchSpanConfigAttrs(cfg *credentialsConfig, correlationID string) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 4+len(allowedAdditionalFieldKeys))
	attrs = append(attrs,
		attribute.String("cfg.token_endpoint_url", cfg.tokenEndpointURL),
		attribute.StringSlice("cfg.scopes", cfg.scopes),
		attribute.String("cfg.body_format", bodyFormatString(cfg.bodyFormat)),
		attribute.String("correlation_id", correlationID),
	)

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
