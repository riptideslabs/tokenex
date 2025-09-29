// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package gcp

import (
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
)

var AlwaysGenerateIDTokenOptionID = option.NewOptionID("always-generate-id-token")

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

// WithServiceAccountEmail sets the service account email to impersonate.
func WithServiceAccountEmail(email string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.serviceAccountEmail = email
	})
}

// WithAudience sets the audience for the token exchange. This identifies the Workload Identity Provider
// the ID token is exchanged against.
func WithAudience(audience string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.audience = audience
	})
}

// WithScopes sets the scope for the access token.
func WithScopes(scopes ...string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.scopes = scopes
	})
}

// WithTokenLifetime sets the lifetime in seconds for the access token.
// The value must be less than or equal to 3600 seconds (1 hour).
func WithTokenLifetime(lifetime int64) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.tokenLifetime = &lifetime
	})
}

// WithIdentityTokenProvider sets an identity token provider.
func WithIdentityTokenProvider(idtp token.IdentityTokenProvider) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.identityTokenProvider = idtp
	})
}
