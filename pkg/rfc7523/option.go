// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package rfc7523

import (
	"net/http"

	"go.opentelemetry.io/otel/trace"

	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
)

type (
	CredentialsOption interface {
		Apply(*credentialsConfig)
	}
	credentialsOption struct {
		option.Option

		f func(*credentialsConfig)
	}
)

func (o *credentialsOption) Apply(c *credentialsConfig) {
	o.f(c)
}

func withCredentialsOption(f func(*credentialsConfig)) option.Option {
	return &credentialsOption{option.OptionImpl{}, f}
}

func isCredentialsOption(opt any) (CredentialsOption, bool) {
	if o, ok := opt.(*credentialsOption); ok {
		return o, ok
	}

	return nil, false
}

// WithTokenEndpointURL sets the OAuth2 token endpoint URL.
func WithTokenEndpointURL(tokenEndpointURL string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.tokenEndpointURL = tokenEndpointURL
	})
}

// WithTokenProvider sets the identity token provider whose JWT will be used as the assertion.
func WithTokenProvider(tp token.IdentityTokenProvider) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.tokenProvider = tp
	})
}

// WithScopes sets the OAuth2 scopes to request.
func WithScopes(scopes []string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.scopes = scopes
	})
}

// WithAdditionalParams sets extra key→values merged into a form-encoded request body.
// Only effective when BodyFormatForm is used (the default).
func WithAdditionalParams(params map[string][]string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.additionalParams = params
	})
}

// WithAdditionalFields sets extra key→value pairs merged into a JSON request body.
// Only effective when BodyFormatJSON is used.
func WithAdditionalFields(fields map[string]string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.additionalFields = fields
	})
}

// WithBodyFormat selects the token request encoding.
// Use BodyFormatJSON for the Anthropic WIF endpoint; BodyFormatForm (default) for standard RFC 7523 endpoints.
func WithBodyFormat(f BodyFormat) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.bodyFormat = f
	})
}

// WithHTTPClient sets a custom HTTP client for token endpoint requests.
// Defaults to http.DefaultClient when not provided.
func WithHTTPClient(client *http.Client) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.httpClient = client
	})
}

// WithTracerProvider sets the OTel TracerProvider used to emit credential.fetch spans.
// If not set, the tracer falls back to the current span's TracerProvider (if any), then the OTel global TracerProvider.
func WithTracerProvider(tracerProvider trace.TracerProvider) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.tracerProvider = tracerProvider
	})
}
