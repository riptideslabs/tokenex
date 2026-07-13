// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package aws

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"go.opentelemetry.io/otel/attribute"
)

const fetchSpanName = "credential.fetch"

const instrumentationScopeName = "go.riptides.io/tokenex/pkg/aws"

func fetchSpanConfigAttrs(cfg *credentialsConfig, region string, correlationID string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("cfg.role_arn", cfg.roleArn),
		attribute.String("cfg.role_session_name", cfg.roleSessionName),
		attribute.String("correlation_id", correlationID),
	}
	if cfg.durationSeconds != nil {
		attrs = append(attrs, attribute.Int64("cfg.duration_seconds", int64(*cfg.durationSeconds)))
	}
	if region != "" {
		attrs = append(attrs, attribute.String("cfg.region", region))
	}

	return attrs
}

func fetchSpanResultAttrs(awsCreds aws.Credentials) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.Bool("credential.expires", awsCreds.CanExpire),
		attribute.String("credential.aws.source", awsCreds.Source),
	}
	if awsCreds.AccountID != "" {
		attrs = append(attrs, attribute.String("credential.aws.account_id", awsCreds.AccountID))
	}
	if awsCreds.CanExpire {
		attrs = append(attrs, attribute.String("credential.expires_at", awsCreds.Expires.UTC().Format(time.RFC3339)))
	}

	return attrs
}
