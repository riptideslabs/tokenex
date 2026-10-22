// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package githubactions_test

import (
	"context"
	"log"

	"github.com/go-logr/logr"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/rfc7523"
	"go.riptides.io/tokenex/pkg/token/githubactions"
)

// Exchange the workflow's OIDC ID token for an Anthropic access token via Workload Identity Federation.
// The job needs the id-token: write permission.
func ExampleNewIdentityTokenProvider() { //nolint:testableexamples // needs a GitHub Actions runner
	ctx := context.Background()

	// Reads ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN from the environment.
	idTokenProvider, err := githubactions.NewIdentityTokenProvider(
		// Must match the audience the federation rule expects.
		githubactions.WithAudience("api.anthropic.com"),
	)
	if err != nil {
		log.Fatal(err)
	}

	credsCh, err := rfc7523.GetAnthropicCredentials(ctx, logr.Discard(), idTokenProvider, rfc7523.AnthropicWIFConfig{
		FederationRuleID: "fdrl_...",
		OrganizationID:   "...",
		ServiceAccountID: "...",
		WorkspaceID:      "...",
	})
	if err != nil {
		log.Fatal(err)
	}

	for res := range credsCh {
		if res.Err != nil {
			log.Fatal(res.Err)
		}

		if tok, ok := res.Credential.(*credential.Oauth2Creds); ok {
			log.Printf("got Anthropic access token, expires %s", tok.Expiry)
		}
	}
}
