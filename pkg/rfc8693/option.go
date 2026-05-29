// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package rfc8693

import (
	"net/http"

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

func WithTokenEndpointURL(tokenEndpointURL string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.tokenEndpointURL = tokenEndpointURL
	})
}

func WithSubjectTokenProvider(tp token.IdentityTokenProvider) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.subjectTokenProvider = tp
	})
}

func WithSubjectTokenType(t TokenType) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.subjectTokenType = t
	})
}

// WithActorTokenProvider
// Enables delegation semantics per RFC 8693 Section 2.1.
func WithActorTokenProvider(tp token.IdentityTokenProvider) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.actorTokenProvider = tp
	})
}

func WithActorTokenType(t TokenType) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.actorTokenType = t
	})
}

func WithRequestedTokenType(t string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.requestedTokenType = t
	})
}

func WithAudience(audience string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.audience = audience
	})
}

func WithScopes(scopes []string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.scopes = scopes
	})
}

func WithAdditionalFields(fields map[string]string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.additionalFields = fields
	})
}

func WithHTTPClient(client *http.Client) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.httpClient = client
	})
}
