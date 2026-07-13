// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package k8ssecret

import (
	"go.opentelemetry.io/otel/attribute"
)

const fetchSpanName = "credential.fetch"

const removeSpanName = "credential.removed"

const instrumentationScopeName = "go.riptides.io/tokenex/pkg/k8ssecret"

func spanConfigAttrs(secretRef SecretRef, correlationID string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("cfg.secret_name", secretRef.Name),
		attribute.String("cfg.secret_namespace", secretRef.Namespace),
		attribute.String("cfg.secret_key", secretRef.Key),
		attribute.String("correlation_id", correlationID),
	}
}

func fetchSpanResultAttrs() []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Bool("credential.expires", false),
	}
}
