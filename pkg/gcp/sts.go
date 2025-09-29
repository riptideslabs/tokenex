// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package gcp

import (
	"context"
	"time"

	"emperror.dev/errors"
	"golang.org/x/oauth2"
	stsv1 "google.golang.org/api/sts/v1"

	"go.riptides.io/tokenex/pkg/token"
)

type stsAccessTokenSource struct {
	oauth2.TokenSource
	stsService *stsv1.Service

	idTokenProvider token.IdentityTokenProvider
	audience        string
	scope           string
	ctx             context.Context //nolint:containedctx
}

func (s *stsAccessTokenSource) Token() (*oauth2.Token, error) {
	idToken, err := s.idTokenProvider.GetToken(s.ctx)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to get ID token")
	}

	// exchange ID token for STS token
	req := &stsv1.GoogleIdentityStsV1ExchangeTokenRequest{
		Audience:           s.audience,
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		Scope:              s.scope,
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		SubjectTokenType:   "urn:ietf:params:oauth:token-type:id_token",
		SubjectToken:       idToken.Token,
	}

	resp, err := s.stsService.V1.Token(req).Context(s.ctx).Do()
	if err != nil {
		return nil, errors.WrapIf(err, "failed to exchange ID token for STS token")
	}

	return &oauth2.Token{
		AccessToken: resp.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   resp.ExpiresIn,
		Expiry:      time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second),
	}, nil
}
