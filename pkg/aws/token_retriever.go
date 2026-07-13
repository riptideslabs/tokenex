// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package aws

import (
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"go.opentelemetry.io/otel/trace"

	tokenextelemetry "go.riptides.io/tokenex/pkg/telemetry"
	"go.riptides.io/tokenex/pkg/token"
	"go.riptides.io/tokenex/pkg/util"
)

// tokenRetriever implements stscreds.IdentityTokenRetriever.
type tokenRetriever struct {
	provider token.IdentityTokenProvider

	ctx util.ContextHolder
}

// GetIdentityToken returns the token from the provider after validating it.
func (t *tokenRetriever) GetIdentityToken() ([]byte, error) {
	ctx := t.ctx.Context()

	idToken, err := t.provider.GetToken(ctx)
	if err != nil {
		return nil, err
	}

	trace.SpanFromContext(ctx).SetAttributes(tokenextelemetry.IdentityTokenAttrs("id_token", idToken.Token, idToken.ExpiresAt)...)

	return []byte(idToken.Token), nil
}

// Ensure tokenRetriever implements the interface.
var _ stscreds.IdentityTokenRetriever = (*tokenRetriever)(nil)
