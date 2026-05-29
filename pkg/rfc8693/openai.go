// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package rfc8693

import (
	"context"
	"maps"

	"github.com/go-logr/logr"

	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
)

const openaiTokenEndpoint = "https://auth.openai.com/oauth/token"

// OpenAIWIFConfig
// See https://github.com/openai/openai-go/blob/main/auth/workloadidentity.go
type OpenAIWIFConfig struct {
	ClientID           string
	IdentityProviderID string
	ServiceAccountID   string
}

func GetOpenAICredentials(
	ctx context.Context,
	logger logr.Logger,
	subjectTokenProvider token.IdentityTokenProvider,
	wif OpenAIWIFConfig,
	opts ...option.Option,
) (<-chan Credential, error) {
	p, err := NewCredentialsProvider(ctx, logger)
	if err != nil {
		return nil, err
	}

	// Pre-collect any caller-supplied additional fields so we can merge them.
	// WIF fields win on conflict; the merged option is applied last so it is never overwritten.
	scratch := &credentialsConfig{}
	for _, opt := range opts {
		if o, ok := isCredentialsOption(opt); ok {
			o.Apply(scratch)
		}
	}

	fields := make(map[string]string)
	maps.Copy(fields, scratch.additionalFields)

	fields["identity_provider_id"] = wif.IdentityProviderID
	fields["service_account_id"] = wif.ServiceAccountID

	if wif.ClientID != "" {
		fields["client_id"] = wif.ClientID
	}

	all := make([]option.Option, 0, len(opts)+2)
	all = append(all, WithSubjectTokenType(TokenTypeJWT))
	all = append(all, opts...)
	all = append(all, WithAdditionalFields(fields))

	return p.GetCredentials(ctx, openaiTokenEndpoint, subjectTokenProvider, all...)
}
