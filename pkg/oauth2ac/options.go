// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package oauth2ac

import (
	"time"

	"go.riptides.io/tokenex/pkg/option"
)

// CredentialsProviderOption is a function that modifies the credentialsProvider.
type (
	CredentialsProviderOption interface {
		Apply(*credentialsProvider)
	}
	credentialsProviderOption struct {
		option.Option

		f func(*credentialsProvider)
	}
)

func (o *credentialsProviderOption) Apply(cp *credentialsProvider) {
	o.f(cp)
}

func withCredentialsProviderOption(f func(*credentialsProvider)) option.Option {
	return &credentialsProviderOption{option.OptionImpl{}, f}
}

func isCredentialsProviderOption(opt any) (CredentialsProviderOption, bool) {
	if o, ok := opt.(*credentialsProviderOption); ok {
		return o, ok
	}

	return nil, false
}

// WithAuthStateTTL sets how long an auth state is kept before being considered expired.
// Defaults to 5 minutes.
func WithAuthStateTTL(ttl time.Duration) option.Option {
	return withCredentialsProviderOption(func(cp *credentialsProvider) {
		cp.authStateTTL = ttl
	})
}

// WithAuthStateCleanupInterval sets how often expired auth states are swept.
// Defaults to 5 seconds.
func WithAuthStateCleanupInterval(d time.Duration) option.Option {
	return withCredentialsProviderOption(func(cp *credentialsProvider) {
		cp.authStateCleanupInterval = d
	})
}
