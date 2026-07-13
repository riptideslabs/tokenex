// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package azure

import (
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"go.opentelemetry.io/otel/attribute"
)

const fetchSpanName = "credential.fetch"

const instrumentationScopeName = "go.riptides.io/tokenex/pkg/azure"

func fetchSpanConfigAttrs(cfg *credentialsConfig, correlationID string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("cfg.tenant_id", cfg.tenantID),
		attribute.String("cfg.client_id", cfg.clientID),
		attribute.String("cfg.scope", cfg.scope),
		attribute.String("correlation_id", correlationID),
	}
}

func fetchSpanResultAttrs(tok azcore.AccessToken) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Bool("credential.expires", true),
		attribute.String("credential.expires_at", tok.ExpiresOn.UTC().Format(time.RFC3339)),
	}
}
