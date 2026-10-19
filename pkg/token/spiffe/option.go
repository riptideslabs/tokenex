// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package spiffe

import (
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

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

// WithAudience sets the aud claim of the issued JWT-SVIDs. It must match what the relying party expects,
// e.g. sts.amazonaws.com for AWS. Required.
func WithAudience(audience string, extra ...string) option.Option {
	return withProviderOption(func(c *providerConfig) {
		c.audience = audience
		c.extraAudiences = extra
	})
}

// WithSPIFFEID selects which SVID to fetch when the workload is entitled to more than one.
// If not set, the Workload API returns the workload's default SVID.
func WithSPIFFEID(id spiffeid.ID) option.Option {
	return withProviderOption(func(c *providerConfig) {
		c.spiffeID = id
	})
}

// WithAddr sets the Workload API address, e.g. unix:///run/spire/agent-sockets/spire-agent.sock.
// Defaults to the SPIFFE_ENDPOINT_SOCKET environment variable.
func WithAddr(addr string) option.Option {
	return withProviderOption(func(c *providerConfig) {
		c.addr = addr
	})
}

// WithSource fetches JWT-SVIDs from an existing source, e.g. a *workloadapi.Client or *workloadapi.JWTSource,
// instead of dialing the Workload API on each call. The caller owns the source and closes it.
func WithSource(source jwtsvid.Source) option.Option {
	return withProviderOption(func(c *providerConfig) {
		c.source = source
	})
}
