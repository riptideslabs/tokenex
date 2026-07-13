// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package gcp

import (
	"context"
	"time"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	"cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"emperror.dev/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	durationpb "google.golang.org/protobuf/types/known/durationpb"

	tokenextelemetry "go.riptides.io/tokenex/pkg/telemetry"
)

const iamImpersonateSpanName = "impersonate_service_account"

func iamImpersonateSpanConfigAttrs(serviceAccountEmail string, scopes []string, lifetime *int64) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("cfg.service_account_email", serviceAccountEmail),
		attribute.StringSlice("cfg.scopes", scopes),
	}
	if lifetime != nil {
		attrs = append(attrs, attribute.Int64("cfg.token_lifetime_seconds", *lifetime))
	}

	return attrs
}

func generateAccessToken(
	ctx context.Context,
	tracer trace.Tracer,
	stsSource *stsAccessTokenSource,
	tokenSource oauth2.TokenSource,
	serviceAccountEmail string,
	scopes []string,
	lifetime *int64,
) (*oauth2.Token, error) {
	ctx, span := tracer.Start(ctx, iamImpersonateSpanName, trace.WithAttributes(iamImpersonateSpanConfigAttrs(serviceAccountEmail, scopes, lifetime)...))
	defer span.End()

	stsSource.ctx.Store(ctx)

	// Create the IAM Credentials API client using the STS token
	iamClient, err := credentials.NewIamCredentialsClient(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		err = errors.WrapIf(err, "failed to create IAM credentials client")
		tokenextelemetry.RecordResult(span, err)

		return nil, err
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
		err = errors.WrapIf(err, "failed to generate access token")
		tokenextelemetry.RecordResult(span, err)

		return nil, err
	}

	tok := &oauth2.Token{
		AccessToken: resp.GetAccessToken(),
		TokenType:   "Bearer",
		Expiry:      resp.GetExpireTime().AsTime(),
	}

	span.SetAttributes(
		attribute.Bool("credential.expires", true),
		attribute.String("credential.expires_at", tok.Expiry.UTC().Format(time.RFC3339)),
	)
	tokenextelemetry.RecordResult(span, nil)

	return tok, nil
}
