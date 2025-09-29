// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package oauth2cc

import (
	"golang.org/x/oauth2"

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

// WithSecretRef sets the Kubernetes secret reference containing the OAuth2 client credentials.
// The secret should contain a key with value in format "client_id:client_secret".
func WithSecretRef(sr SecretRef) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.secretRef = sr
	})
}

// WithTokenEndpointURL sets the OAuth2 token endpoint URL.
// This is the URL where the client credentials will be exchanged for an access token.
func WithTokenEndpointURL(tokenEndpointURL string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.tokenEndpointURL = tokenEndpointURL
	})
}

// WithScopes sets the OAuth2 scopes to request.
// Scopes define the access privileges requested from the authorization server.
func WithScopes(scopes []string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.scopes = scopes
	})
}

// WithAdditionalParams sets additional parameters to include in the OAuth2 token request.
// These parameters are added to the request when exchanging client credentials for an access token.
func WithAdditionalParams(params map[string][]string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.additionalParams = params
	})
}

// WithAuthStyle sets the OAuth2 authentication style for the token request.
// This determines how the client credentials are included in the request:
// - AuthStyleInParams: credentials in the request body (form parameters)
// - AuthStyleInHeader: credentials in the Authorization header (Basic auth)
// - AuthStyleAutoDetect: let the OAuth2 library determine the appropriate style
func WithAuthStyle(authStyle oauth2.AuthStyle) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.authStyle = authStyle
	})
}
