// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package oci

import (
	"time"

	"go.opentelemetry.io/otel/attribute"
)

const fetchSpanName = "credential.fetch"

const instrumentationScopeName = "go.riptides.io/tokenex/pkg/oci"

func fetchSpanConfigAttrs(cfg *credentialsConfig, correlationID string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("cfg.client_id", cfg.clientID),
		attribute.String("cfg.identity_domain_url", cfg.identityDomainURL),
		attribute.String("correlation_id", correlationID),
	}

	return attrs
}

func fetchSpanResultAttrs(expiresAt time.Time) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Bool("credential.expires", true),
		attribute.String("credential.expires_at", expiresAt.UTC().Format(time.RFC3339)),
	}
}
