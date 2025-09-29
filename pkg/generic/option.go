// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package generic

import (
	"time"

	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
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

// WithIdentityTokenProvider sets the id token provider.
func WithIdentityTokenProvider(tokenProvider token.IdentityTokenProvider) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.tokenProvider = tokenProvider
	})
}

var (
	audiencesOptionID = option.NewOptionID("audiences")
	claimsOptionID    = option.NewOptionID("claims")
	lifetimeOptionID  = option.NewOptionID("lifetime")
)

// WithAudiences sets the audiences for the token.
func WithAudiences(audiences []string) option.Option {
	return option.WithStringSlice(audiencesOptionID, audiences)
}

// IsAudiencesOption checks if the provided option is an audiences option.
func IsAudiencesOption(opt option.Option) ([]string, bool) {
	if o, ok := option.IsStringSliceOption(opt); ok {
		if o.ID() == audiencesOptionID {
			return o.Value(), true
		}
	}

	return nil, false
}

// WithClaims sets additional claims to be included in the token.
func WithClaims(claims map[string]any) option.Option {
	return option.WithAnyMap(claimsOptionID, claims)
}

// IsClaimsOption checks if the provided option is a claims option.
func IsClaimsOption(opt option.Option) (map[string]any, bool) {
	if o, ok := option.IsAnyMapOption(opt); ok {
		if o.ID() == claimsOptionID {
			return o.Value(), true
		}
	}

	return nil, false
}

// WithLifetime sets the lifetime duration for the token.
func WithLifetime(lifetime time.Duration) option.Option {
	return option.WithDuration(lifetimeOptionID, lifetime)
}

// IsLifetimeOption checks if the provided option is a lifetime option.
func IsLifetimeOption(opt option.Option) (time.Duration, bool) {
	if o, ok := option.IsDurationOption(opt); ok {
		if o.ID() == lifetimeOptionID {
			return o.Value(), true
		}
	}

	return 0, false
}
