// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package gcp

import (
	"context"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	"cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"emperror.dev/errors"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
)

// generateAccessToken generates an access token that impersonates a service account.
func generateAccessToken(
	ctx context.Context,
	stsAccessTokenSource oauth2.TokenSource,
	serviceAccountEmail string,
	scopes []string,
	lifetime *int64,
) (*oauth2.Token, error) {
	// Create the IAM Credentials API client using the STS token
	iamClient, err := credentials.NewIamCredentialsClient(ctx, option.WithTokenSource(stsAccessTokenSource))
	if err != nil {
		return nil, errors.WrapIf(err, "failed to create IAM credentials client")
	}
	defer iamClient.Close()

	// Prepare the request for service account access token
	req := &credentialspb.GenerateAccessTokenRequest{
		Name:  "projects/-/serviceAccounts/" + serviceAccountEmail,
		Scope: scopes,
	}

	// Set lifetime if provided
	if lifetime != nil {
		req.Lifetime = &durationpb.Duration{
			Seconds: *lifetime,
		}
	}

	// Generate access token
	resp, err := iamClient.GenerateAccessToken(ctx, req)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to generate access token")
	}

	return &oauth2.Token{
		AccessToken: resp.GetAccessToken(),
		TokenType:   "Bearer",
		Expiry:      resp.GetExpireTime().AsTime(),
	}, nil
}
