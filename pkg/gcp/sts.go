// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package gcp

import (
	"time"

	"emperror.dev/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
	stsv1 "google.golang.org/api/sts/v1"

	tokenextelemetry "go.riptides.io/tokenex/pkg/telemetry"
	"go.riptides.io/tokenex/pkg/token"
	"go.riptides.io/tokenex/pkg/util"
)

const stsExchangeSpanName = "exchange_token"

type stsAccessTokenSource struct {
	stsService *stsv1.Service

	idTokenProvider token.IdentityTokenProvider
	audience        string
	scope           string
	tracer          trace.Tracer

	ctx util.ContextHolder
}

func (s *stsAccessTokenSource) Token() (*oauth2.Token, error) {
	ctx, span := s.tracer.Start(s.ctx.Context(), stsExchangeSpanName, trace.WithAttributes(
		attribute.String("cfg.audience", s.audience),
		attribute.String("cfg.scope", s.scope),
	))
	defer span.End()

	idToken, err := s.idTokenProvider.GetToken(ctx)
	if err != nil {
		err = errors.WrapIf(err, "failed to get ID token")
		tokenextelemetry.RecordResult(span, err)

		return nil, err
	}

	span.SetAttributes(tokenextelemetry.IdentityTokenAttrs("id_token", idToken.Token, idToken.ExpiresAt)...)

	// exchange ID token for STS token
	req := &stsv1.GoogleIdentityStsV1ExchangeTokenRequest{
		Audience:           s.audience,
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		Scope:              s.scope,
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		SubjectTokenType:   "urn:ietf:params:oauth:token-type:id_token",
		SubjectToken:       idToken.Token,
	}

	resp, err := s.stsService.V1.Token(req).Context(ctx).Do()
	if err != nil {
		err = errors.WrapIf(err, "failed to exchange ID token for STS token")
		tokenextelemetry.RecordResult(span, err)

		return nil, err
	}

	tok := &oauth2.Token{
		AccessToken: resp.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   resp.ExpiresIn,
		Expiry:      time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second),
	}

	span.SetAttributes(attribute.String("sts.access_token.expires_at", tok.Expiry.UTC().Format(time.RFC3339)))
	tokenextelemetry.RecordResult(span, nil)

	return tok, nil
}
