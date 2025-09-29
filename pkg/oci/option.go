// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package oci

import (
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
)

// Option types for configuring credentialsConfig.
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

// WithClientID sets the client ID for OCI workload identity federation.
// It is the client ID of the application registered in OCI which is allowed to exchange ID tokens for OCI user principal session tokens.
func WithClientID(clientID string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.clientID = clientID
	})
}

// WithClientSecret sets the client secret for OCI workload identity federation.
// It is the client secret of the application registered in OCI which is allowed to exchange ID tokens for OCI user principal session tokens.
func WithClientSecret(clientSecret string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.clientSecret = clientSecret
	})
}

// WithIdentityDomainURL sets the identity domain URL for OCI workload identity federation.
// It is the identity domain URL of the OCI tenancy where the application which is allowed to exchange ID tokens is registered.
func WithIdentityDomainURL(identityDomainURL string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.identityDomainURL = identityDomainURL
	})
}

// WithRsaPublicKeyDer sets the RSA public key in DER format.
// It is the RSA public key of the application(workload) which is going to use the OCI user principal session tokens for authentication.
func WithRsaPublicKeyDer(rsaPubKeyDer []byte) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.rsaPubKeyDer = rsaPubKeyDer
	})
}

// WithIdentityTokenProvider sets an identity token provider for OCI workload identity federation.
// The identity token provider is used to obtain ID tokens that are exchanged for OCI user principal session tokens.
func WithIdentityTokenProvider(tokenProvider token.IdentityTokenProvider) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.identityTokenProvider = tokenProvider
	})
}
