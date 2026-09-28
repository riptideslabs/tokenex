// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package conjur

import (
	"maps"
	"time"

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

// WithAccount sets the Conjur account. This option is required.
// It is "conjur" for CyberArk Secrets Manager SaaS.
func WithAccount(account string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.account = account
	})
}

// WithServiceID sets the service ID of the JWT authenticator, the <service-id> in authn-jwt/<service-id>.
// This option is required.
func WithServiceID(serviceID string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.serviceID = serviceID
	})
}

// WithHostID sets the Conjur host to authenticate as. The "host/" prefix is added if missing.
// Leave it unset when the authenticator reads the identity from the JWT through token-app-property.
func WithHostID(hostID string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.hostID = hostID
	})
}

// WithVariables sets the Conjur variables to retrieve, keyed by the name each value gets in the
// returned Secret. For example {"username": "prod/db/username", "password": "prod/db/password"}.
// Use plain variable IDs, not the fully qualified <account>:variable:<id> form.
// This option is required. All variables are read in one batch request, so a rotated pair is
// never returned half updated.
func WithVariables(variables map[string]string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.variables = maps.Clone(variables)
	})
}

// WithIdentityTokenProvider sets the provider of the JWT presented to the JWT authenticator.
// This option is required.
func WithIdentityTokenProvider(idtp token.IdentityTokenProvider) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.identityTokenProvider = idtp
	})
}

// WithPollInterval sets how often the variables are read again to pick up rotated values.
// If not set, it defaults to 15 minutes.
func WithPollInterval(d time.Duration) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.pollInterval = d
	})
}

// WithTracerProvider sets the OTel TracerProvider used to emit credential.fetch spans.
// If not set, the tracer falls back to the current span's TracerProvider (if any), then the OTel global TracerProvider.
func WithTracerProvider(tracerProvider trace.TracerProvider) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.tracerProvider = tracerProvider
	})
}
