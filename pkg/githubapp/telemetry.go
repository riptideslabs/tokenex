// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package githubapp

import (
	"time"

	"github.com/google/go-github/v66/github"
	"go.opentelemetry.io/otel/attribute"
)

const fetchSpanName = "credential.fetch"

const instrumentationScopeName = "go.riptides.io/tokenex/pkg/githubapp"

func fetchSpanConfigAttrs(cfg *credentialsConfig, correlationID string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Int64("cfg.app_id", cfg.appID),
		attribute.Int64("cfg.installation_id", cfg.installationID),
		attribute.String("cfg.base_url", cfg.baseURL),
		attribute.String("correlation_id", correlationID),
	}
}

func fetchSpanResultAttrs(tok *github.InstallationToken) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Bool("credential.expires", true),
		attribute.String("credential.expires_at", tok.GetExpiresAt().Time.UTC().Format(time.RFC3339)),
	}
}
