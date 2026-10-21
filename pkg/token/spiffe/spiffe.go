// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

// Package spiffe provides an IdentityTokenProvider that fetches JWT-SVIDs from the SPIFFE Workload API
// (e.g. a SPIRE agent), so a workload can exchange them with any tokenex credentials provider.
package spiffe

import (
	"context"

	"emperror.dev/errors"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
)

type providerConfig struct {
	audience       string
	extraAudiences []string
	spiffeID       spiffeid.ID
	addr           string
	source         jwtsvid.Source
}

// IdentityTokenProvider fetches JWT-SVIDs from the SPIFFE Workload API.
type IdentityTokenProvider struct {
	params jwtsvid.Params
	addr   string
	source jwtsvid.Source
}

var _ token.IdentityTokenProvider = (*IdentityTokenProvider)(nil)

// NewIdentityTokenProvider creates a provider for JWT-SVIDs. WithAudience is required.
// The Workload API address defaults to the SPIFFE_ENDPOINT_SOCKET environment variable.
func NewIdentityTokenProvider(opts ...option.Option) (*IdentityTokenProvider, error) {
	cfg := &providerConfig{}

	for _, opt := range opts {
		if o, ok := isProviderOption(opt); ok {
			o.Apply(cfg)
		}
	}

	if cfg.audience == "" {
		return nil, errors.New("audience is required")
	}

	p := &IdentityTokenProvider{
		params: jwtsvid.Params{
			Audience:       cfg.audience,
			ExtraAudiences: cfg.extraAudiences,
			Subject:        cfg.spiffeID,
		},
		source: cfg.source,
	}

	if p.source != nil {
		return p, nil
	}

	p.addr = cfg.addr
	if p.addr == "" {
		p.addr, _ = workloadapi.GetDefaultAddress()
	}

	if p.addr == "" {
		return nil, errors.Errorf("%s is not set and no Workload API address was given", workloadapi.SocketEnv)
	}

	if err := workloadapi.ValidateAddress(p.addr); err != nil {
		return nil, errors.WrapIf(err, "invalid Workload API address")
	}

	return p, nil
}

// GetToken asks the Workload API for a JWT-SVID on every call and does not cache it, so callers
// always get the SVID the agent currently serves.
func (p *IdentityTokenProvider) GetToken(ctx context.Context, _ ...option.Option) (credential.Token, error) {
	var (
		svid *jwtsvid.SVID
		err  error
	)

	if p.source != nil {
		svid, err = p.source.FetchJWTSVID(ctx, p.params)
	} else {
		svid, err = workloadapi.FetchJWTSVID(ctx, p.params, workloadapi.WithAddr(p.addr))
	}

	if err != nil {
		return credential.Token{}, errors.WrapIf(err, "could not fetch JWT-SVID")
	}

	return credential.Token{
		Token:     svid.Marshal(),
		ExpiresAt: svid.Expiry,
	}, nil
}
