// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"

	"go.riptides.io/tokenex/pkg/token"
)

// tokenRetriever implements stscreds.IdentityTokenRetriever.
type tokenRetriever struct {
	provider token.IdentityTokenProvider
	//nolint: containedctx
	ctx context.Context
}

// GetIdentityToken returns the token from the provider after validating it.
func (t *tokenRetriever) GetIdentityToken() ([]byte, error) {
	token, err := t.provider.GetToken(t.ctx)
	if err != nil {
		return nil, err
	}

	return []byte(token.Token), nil
}

// Ensure tokenRetriever implements the interface.
var _ stscreds.IdentityTokenRetriever = (*tokenRetriever)(nil)
