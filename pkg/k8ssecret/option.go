// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package k8ssecret

import (
	"go.opentelemetry.io/otel/trace"

	"go.riptides.io/tokenex/pkg/option"
)

// Option is a function that modifies the credentialsConfig.
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

// WithSecretRef sets the k8s secret reference.
func WithSecretRef(sr SecretRef) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.secretRef = sr
	})
}

// WithTracerProvider sets the OTel TracerProvider used to emit credential.fetch spans.
// If not set, the tracer falls back to the current span's TracerProvider (if any), then the OTel global TracerProvider.
func WithTracerProvider(tracerProvider trace.TracerProvider) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.tracerProvider = tracerProvider
	})
}
