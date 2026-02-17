// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package vault

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/cenkalti/backoff/v5"
	"github.com/go-logr/logr"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/util"
)

// gcpServiceAccountKeySecret represents the structure of the service account key material returned by Vault's Google Cloud secrets engine when configured to return service account keys.
// It contains the base64-encoded private key data.
type gcpServiceAccountKeySecret struct {
	PrivateKeyData string `mapstructure:"private_key_data"`
}

// ServiceAccountKeyJSON decodes the base64-encoded private key data from the Vault secret and returns it as a byte slice.
func (s *gcpServiceAccountKeySecret) ServiceAccountKeyJSON() ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s.PrivateKeyData)
	if err != nil {
		return nil, errors.WrapIf(err, "private_key_data in Vault secret data for GCP credentials is not valid base64 encoded string")
	}

	return key, nil
}

// gcpAccessTokenProvider is responsible for exchanging a GCP service account key for an access token and refreshing it as needed until stopped.
type gcpAccessTokenProvider struct {
	serviceAccountKeyJSON []byte
	scopes                []string

	logger logr.Logger
}

// GetCredentials begins the process of exchanging the service account key for an access token and refreshing it as needed until the context is canceled.
func (r *gcpAccessTokenProvider) GetCredentials(ctx context.Context, credsChan chan credential.Result) {
	b := backoff.NewExponentialBackOff()

	for {
		// use the service account key to authenticate to GCP and obtain an access token
		gcpCreds, err := google.CredentialsFromJSON(ctx, r.serviceAccountKeyJSON, r.scopes...)
		if err != nil {
			util.SendErrorToChannel(credsChan, errors.WrapIf(err, "failed to obtain GCP credentials from service account key"))

			return
		}

		// if the SA key was just created it's possible that it may take a few seconds for GCP to propagate the key and allow it to be used for authentication.
		// This can result in transient errors when trying to exchange the key for an access token.
		token, err := backoff.Retry(ctx, func() (*oauth2.Token, error) {
			token, err := gcpCreds.TokenSource.Token()
			if err != nil {
				if strings.Contains(err.Error(), "invalid_grant") {
					r.logger.V(2).Info("Received invalid_grant error when exchanging service account key for access token, likely due to GCP propagation delay. Retrying...", "error", err)

					return nil, err
				}

				return nil, backoff.Permanent(errors.WrapIf(err, "failed to exchange service account key for access token"))
			}

			return token, nil
		}, backoff.WithBackOff(b), backoff.WithMaxElapsedTime(30*time.Second))
		if err != nil {
			util.SendErrorToChannel(credsChan, errors.WrapIf(err, "failed to obtain access token from GCP using service account key"))

			return
		}

		// Calculate when to refresh
		timeUntilExpiry := time.Until(token.Expiry)

		// If credentials are already expired, this is an error
		if timeUntilExpiry <= 0 {
			util.SendErrorToChannel(credsChan, errors.NewWithDetails("received already expired access token from GCP", "expiresAt", token.Expiry))

			return
		}

		gcpCredential := credential.Oauth2Creds(*token)
		util.SendToChannel(credsChan, credential.Result{
			Credential: &gcpCredential,
			Err:        nil,
			Event:      credential.UpdateEventType,
		})

		r.logger.V(2).Info("Published access token", "expiresAt", token.Expiry)

		refreshBuffer := util.CalculateRefreshBuffer(timeUntilExpiry)
		refreshTime := timeUntilExpiry - refreshBuffer

		r.logger.V(0).Info("Scheduling access token refresh", "refreshIn", refreshTime, "refreshBuffer", refreshBuffer)

		select {
		case <-ctx.Done():
			r.logger.V(1).Info("Context cancelled, stopping access token refresh")

			return
		case <-time.After(refreshTime):
			// Continue to next iteration to refresh
			r.logger.V(2).Info("Refreshing access token")
		}
	}
}
