// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package conjur

import (
	"go.opentelemetry.io/otel/attribute"
)

const fetchSpanName = "credential.fetch"

const instrumentationScopeName = "go.riptides.io/tokenex/pkg/conjur"

func fetchSpanConfigAttrs(cfg *credentialsConfig, applianceURL string, correlationID string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("cfg.appliance_url", applianceURL),
		attribute.String("cfg.account", cfg.account),
		attribute.String("cfg.service_id", cfg.serviceID),
		attribute.StringSlice("cfg.variable_ids", variableIDs(cfg.variables)),
		attribute.String("correlation_id", correlationID),
	}

	if cfg.hostID != "" {
		attrs = append(attrs, attribute.String("cfg.host_id", hostLogin(cfg.hostID)))
	}

	return attrs
}

func fetchSpanResultAttrs() []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Bool("credential.expires", false),
	}
}
