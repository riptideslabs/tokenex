// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

// Command spire-aws exchanges the workload's JWT-SVID for AWS credentials and prints the assumed identity
// on every refresh.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"emperror.dev/errors"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/go-logr/logr"

	"go.riptides.io/tokenex/pkg/aws"
	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/token/spiffe"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	roleArn := os.Getenv("AWS_ROLE_ARN")
	if roleArn == "" {
		return errors.New("AWS_ROLE_ARN is required")
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Reads the Workload API address from SPIFFE_ENDPOINT_SOCKET.
	idTokenProvider, err := spiffe.NewIdentityTokenProvider(spiffe.WithAudience("sts.amazonaws.com"))
	if err != nil {
		return errors.WrapIf(err, "could not create SPIFFE identity token provider")
	}

	awsProvider, err := aws.NewCredentialsProvider(ctx, logr.Discard(), &awssdk.Config{Region: region})
	if err != nil {
		return errors.WrapIf(err, "could not create AWS credentials provider")
	}

	credsCh, err := awsProvider.GetCredentials(ctx, idTokenProvider,
		aws.WithRoleArn(roleArn),
		aws.WithRoleSessionName("spire-aws-example"),
	)
	if err != nil {
		return errors.WrapIf(err, "could not get AWS credentials")
	}

	for res := range credsCh {
		if res.Err != nil {
			return errors.WrapIf(res.Err, "credentials refresh failed")
		}

		creds, ok := res.Credential.(*credential.AWSCreds)
		if !ok {
			continue
		}

		stsClient := sts.New(sts.Options{
			Region:      region,
			Credentials: awscreds.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken),
		})

		identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return errors.WrapIf(err, "GetCallerIdentity failed")
		}

		log.Printf("assumed %s, credentials expire at %s", awssdk.ToString(identity.Arn), creds.Expires)
	}

	return nil
}
