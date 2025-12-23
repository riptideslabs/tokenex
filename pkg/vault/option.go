// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package vault

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

// WithJWTAuthMethodPath sets the path where the JWT auth method is mounted on the API for authentication.
// This is a required option for Vault credential exchange. If not set it defaults to "jwt" .
// The path must correspond to the mount path of the JWT auth method in Vault.
func WithJWTAuthMethodPath(jwtAuthMethodPath string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.jwtAuthMethodPath = jwtAuthMethodPath
	})
}

// WithJWTAuthRoleName sets the JWT role name for authentication.
// This is a required option for Vault credential exchange.
// The role must be configured in Vault's JWT auth method.
func WithJWTAuthRoleName(jwtAuthRoleName string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.jwtAuthRoleName = jwtAuthRoleName
	})
}

// WithSecretFullPath sets the Vault full path to the secret to be retrieved.
// This option is required for Vault credential exchange.
// The path format depends on the secret engine used. For example:
//   - "database/creds/gen-dyn-dbuser-role" (Dynamic secrets from database secrets engine mounted at "database" API path)
//   - "database/static-creds/static-dbuser-role" (Static secrets from database secrets engine mounted at "database" API path)
//   - "kv2/data/path/to/secret" (KV version 2 secrets engine mounted at "kv2" API path)
//   - "kv1/path/to/secret" (KV version 1 secrets engine mounted at "kv1" API path)
//   - "ns1/kv2/data/path/to/secret" (KV version 2 secrets engine in namespace "ns1" mounted at "kv2" API path)
//   - "ns1/ns2/kv1/path/to/secret" (KV version 1 secrets engine in nested namespaces "ns1/ns2" mounted at "kv1" API path)
//
// The value should match the corresponding Vault API path.
func WithSecretFullPath(secretFullPath string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.secretFullPath = secretFullPath
	})
}

// WithIdentityTokenProvider sets an identity token provider.
// This is a required option for Vault credential exchange.
// The identity token provider supplies the ID token that will be exchanged for Vault credentials.
// The provider should handle token refreshing internally if needed.
func WithIdentityTokenProvider(idtp token.IdentityTokenProvider) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.identityTokenProvider = idtp
	})
}

// WithPollInterval sets the interval at which to poll Vault secrets for updates in case the secret has either no lease or TTL expiration.
// If not set, the default polling interval is 15 minutes.
// This option is useful for secrets that do not have automatic renewal mechanisms such as the secrets stored in Vault's KV secrets engine.
func WithPollInterval(d time.Duration) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.pollInterval = d
	})
}
