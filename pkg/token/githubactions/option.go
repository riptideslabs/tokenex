// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package githubactions

import (
	"net/http"

	"go.riptides.io/tokenex/pkg/option"
)

type (
	ProviderOption interface {
		Apply(*providerConfig)
	}
	providerOption struct {
		option.Option

		f func(*providerConfig)
	}
)

func (o *providerOption) Apply(c *providerConfig) {
	o.f(c)
}

func withProviderOption(f func(*providerConfig)) option.Option {
	return &providerOption{option.OptionImpl{}, f}
}

func isProviderOption(opt any) (ProviderOption, bool) {
	if o, ok := opt.(*providerOption); ok {
		return o, ok
	}

	return nil, false
}

// WithAudience sets the aud claim of the issued ID tokens. It must match what the relying party expects.
// If not set, GitHub uses its default audience (the URL of the repository owner).
func WithAudience(audience string) option.Option {
	return withProviderOption(func(c *providerConfig) {
		c.audience = audience
	})
}

// WithRequestURL overrides the token request URL read from ACTIONS_ID_TOKEN_REQUEST_URL.
// Useful when the provider runs somewhere the runner's environment is not inherited, e.g. a container.
func WithRequestURL(requestURL string) option.Option {
	return withProviderOption(func(c *providerConfig) {
		c.requestURL = requestURL
	})
}

// WithRequestToken overrides the bearer token read from ACTIONS_ID_TOKEN_REQUEST_TOKEN.
func WithRequestToken(requestToken string) option.Option {
	return withProviderOption(func(c *providerConfig) {
		c.requestToken = requestToken
	})
}

// WithHTTPClient sets the HTTP client used for token requests. Defaults to http.DefaultClient.
func WithHTTPClient(client *http.Client) option.Option {
	return withProviderOption(func(c *providerConfig) {
		c.httpClient = client
	})
}
