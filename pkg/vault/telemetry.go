// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package vault

import (
	"time"

	"go.opentelemetry.io/otel/attribute"
)

const fetchSpanName = "credential.fetch"

const instrumentationScopeName = "go.riptides.io/tokenex/pkg/vault"

func fetchSpanConfigAttrs(cfg *credentialsConfig, vaultAddr string, correlationID string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("cfg.vault_addr", vaultAddr),
		attribute.String("cfg.jwt_auth_method_path", cfg.jwtAuthMethodPath),
		attribute.String("cfg.jwt_auth_role_name", cfg.jwtAuthRoleName),
		attribute.String("cfg.secret_full_path", cfg.secretFullPath),
		attribute.String("correlation_id", correlationID),
	}
}

func fetchSpanResultAttrs(creds *credentialData) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Bool("credential.expires", true),
		attribute.String("credential.expires_at", creds.ExpiresAt.UTC().Format(time.RFC3339)),
	}
}
