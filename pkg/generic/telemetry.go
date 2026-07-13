// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package generic

import (
	"time"

	"go.opentelemetry.io/otel/attribute"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
)

const fetchSpanName = "credential.fetch"

const instrumentationScopeName = "go.riptides.io/tokenex/pkg/generic"

func fetchSpanConfigAttrs(opts []option.Option, correlationID string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("correlation_id", correlationID),
	}

	for _, opt := range opts {
		if audiences, ok := IsAudiencesOption(opt); ok {
			attrs = append(attrs, attribute.StringSlice("cfg.audiences", audiences))
		}
		if lifetime, ok := IsLifetimeOption(opt); ok {
			attrs = append(attrs, attribute.String("cfg.lifetime", lifetime.String()))
		}
	}

	return attrs
}

func fetchSpanResultAttrs(tok credential.Token) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.Bool("credential.expires", !tok.ExpiresAt.IsZero()),
	}
	if !tok.ExpiresAt.IsZero() {
		attrs = append(attrs, attribute.String("credential.expires_at", tok.ExpiresAt.UTC().Format(time.RFC3339)))
	}

	return attrs
}
