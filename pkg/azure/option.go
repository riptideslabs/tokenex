// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package azure

import (
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

// WithTenantID sets the tenant ID that will be used for the access token exchange.
func WithTenantID(tenantID string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.tenantID = tenantID
	})
}

func WithClientID(clientID string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.clientID = clientID
	})
}

// WithScope sets the requested scope for retrieved credetian (access token).
// e.g. `https://management.azure.com/.default` is the scope for Azure Resource Manager (ARM) service.
// An access token is issued for a single service.
//
// | Service                               | Scope to request                                                                          |
// | ------------------------------------- | ----------------------------------------------------------------------------------------- |
// | Microsoft Graph                       | `https://graph.microsoft.com/.default`                                                    |
// | Azure Resource Manager (ARM)          | `https://management.azure.com/.default`                                                   |
// | Azure Key Vault (management plane)    | `https://management.azure.com/.default`                                                   |
// | Azure Key Vault (data plane)          | `https://vault.azure.net/.default`                                                        |
// | Azure Storage (data plane)            | `https://storage.azure.com/.default`                                                      |
// | Azure SQL Database                    | `https://database.windows.net/.default`                                                   |
// | Azure Service Bus                     | `https://servicebus.azure.net/.default`                                                   |
// | Azure Event Hubs                      | `https://eventhubs.azure.net/.default`                                                    |
// | Azure Container Registry (data plane) | `https://management.azure.com/.default` or `https://containerregistry.azure.net/.default` |
// | Azure Monitor                         | `https://monitor.azure.com/.default`                                                      |
//
// For an up to date list of services and their corresponding scope check Azure documentation.
func WithScope(scope string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.scope = scope
	})
}

// WithIdentityTokenProvider sets an identity token provider.
func WithIdentityTokenProvider(idtp token.IdentityTokenProvider) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.identityTokenProvider = idtp
	})
}
