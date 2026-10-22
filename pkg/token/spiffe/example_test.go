// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package spiffe_test

import (
	"context"
	"log"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-logr/logr"

	"go.riptides.io/tokenex/pkg/aws"
	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/token/spiffe"
)

// Exchange the workload's JWT-SVID for AWS credentials. Needs a SPIRE agent at SPIFFE_ENDPOINT_SOCKET
// and an IAM role that trusts SPIRE's OIDC Discovery Provider.
func ExampleNewIdentityTokenProvider() { //nolint:testableexamples // needs a SPIRE agent and AWS
	ctx := context.Background()

	idTokenProvider, err := spiffe.NewIdentityTokenProvider(spiffe.WithAudience("sts.amazonaws.com"))
	if err != nil {
		log.Fatal(err)
	}

	awsProvider, err := aws.NewCredentialsProvider(ctx, logr.Discard(), &awssdk.Config{Region: "us-east-1"})
	if err != nil {
		log.Fatal(err)
	}

	credsCh, err := awsProvider.GetCredentials(ctx, idTokenProvider,
		aws.WithRoleArn("arn:aws:iam::123456789012:role/spire-demo"),
		aws.WithRoleSessionName("spire-demo"),
	)
	if err != nil {
		log.Fatal(err)
	}

	for res := range credsCh {
		if res.Err != nil {
			log.Fatal(res.Err)
		}

		if creds, ok := res.Credential.(*credential.AWSCreds); ok {
			log.Printf("got AWS credentials %s, expire %s", creds.AccessKeyID, creds.Expires)
		}
	}
}
