// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package oauth2cc

import (
	"time"

	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/oauth2"
)

const fetchSpanName = "credential.fetch"

const instrumentationScopeName = "go.riptides.io/tokenex/pkg/oauth2cc"

func authStyleString(s oauth2.AuthStyle) string {
	switch s {
	case oauth2.AuthStyleInParams:
		return "in_params"
	case oauth2.AuthStyleInHeader:
		return "in_header"
	default:
		return "auto_detect"
	}
}

func fetchSpanConfigAttrs(cfg *credentialsConfig, clientID string, correlationID string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("cfg.token_endpoint_url", cfg.tokenEndpointURL),
		attribute.StringSlice("cfg.scopes", cfg.scopes),
		attribute.String("cfg.auth_style", authStyleString(cfg.authStyle)),
		attribute.String("cfg.client_id", clientID),
		attribute.String("correlation_id", correlationID),
	}
}

func fetchSpanResultAttrs(tok *oauth2.Token) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Bool("credential.expires", true),
		attribute.String("credential.expires_at", tok.Expiry.UTC().Format(time.RFC3339)),
	}
}
