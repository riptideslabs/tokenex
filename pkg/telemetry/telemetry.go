// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

// Package telemetry lets tokenex credential providers receive an OTel
// TracerProvider from their consumer, and derive their own
// appropriately-scoped Tracer from it.
package telemetry

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Tracer returns a Tracer scoped to scopeName from tp. If tp is nil, it
// falls back to the TracerProvider of the current span in ctx (if any), and
// finally to the OTel global TracerProvider. Providers should call this with
// their own package's instrumentation scope name rather than accepting a
// Tracer directly, so the scope always reflects the actual source of the
// spans regardless of what the consumer supplies.
func Tracer(ctx context.Context, tp trace.TracerProvider, scopeName string) trace.Tracer {
	if tp == nil {
		if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
			tp = span.TracerProvider()
		} else {
			tp = otel.GetTracerProvider()
		}
	}

	return tp.Tracer(scopeName)
}

// IdentityTokenAttrs returns span attributes describing an identity token
// presented to a downstream exchange: <prefix>.expires_at always, plus
// <prefix>.subject / <prefix>.audience / <prefix>.iss when rawToken parses as
// a JWT and carries those claims (rawToken is parsed unverified — this is for
// telemetry, not validation).
func IdentityTokenAttrs(prefix string, rawToken string, expiresAt time.Time) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(prefix+".expires_at", expiresAt.UTC().Format(time.RFC3339)),
	}

	tok, _, err := jwt.NewParser().ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		return attrs
	}

	if sub, err := tok.Claims.GetSubject(); err == nil && sub != "" {
		attrs = append(attrs, attribute.String(prefix+".subject", sub))
	}
	if aud, err := tok.Claims.GetAudience(); err == nil && len(aud) > 0 {
		attrs = append(attrs, attribute.StringSlice(prefix+".audience", aud))
	}
	if iss, err := tok.Claims.GetIssuer(); err == nil && iss != "" {
		attrs = append(attrs, attribute.String(prefix+".iss", iss))
	}

	return attrs
}

// RecordResult records err on span (if non-nil) and sets the span's final
// status accordingly. It does not end the span — callers should
// `defer span.End()` right after starting it, so the span is always closed
// regardless of which return path is taken.
func RecordResult(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}
}
