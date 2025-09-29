// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package credential

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"golang.org/x/oauth2"

	"go.riptides.io/tokenex/pkg/option"
)

// Provider defines the interface for obtaining credentials.
// It is implemented by all credential providers in the tokenex library.
type Provider interface {
	// GetCredentialsWithOptions returns a channel that receives credential results.
	// The channel provides updates when credentials are refreshed or removed.
	// For the first credential and each refresh, an Update event is sent.
	// If credentials are removed, a Remove event is sent.
	// In case of errors, the Err field is populated, Credential is nil, and the refresh loop exits.
	// When the refresh loop exits, the channel is closed.
	// Options can be provided to configure the credentials request.
	GetCredentialsWithOptions(ctx context.Context, opts ...option.Option) (<-chan Result, error)
}

// Credential is a marker interface for credential types.
// Implementations include Token, AWSCredentials, and other credential types.
type Credential interface {
	isResultType()
}

// EventType represents the type of credential event.
// It indicates whether a credential is being updated or removed.
type EventType string

const (
	// UpdateEventType indicates that a credential has been updated.
	UpdateEventType EventType = "UPDATE"
	// RemoveEventType indicates that a credential has been removed.
	RemoveEventType EventType = "REMOVE"
)

// Result encapsulates the credentials received from a credential provider (e.g. cloud providers, k8s etc.)
// and any error that might occur.
// When a credential is first obtained or refreshed, Event is set to UpdateEventType.
// When a credential is removed, Event is set to RemoveEventType.
// If an error occurs, Err is populated and Credential is set to nil.
// In case of an error, the credential refresh loop exits, the channel is closed, and it's the caller's responsibility to implement retry logic.
type Result struct {
	Credential Credential
	Event      EventType
	Err        error
}

type AWSCreds aws.Credentials

func (*AWSCreds) isResultType() {}

type Oauth2Creds oauth2.Token

func (*Oauth2Creds) isResultType() {}

type Token struct {
	Token     string
	ExpiresAt time.Time
}

func (*Token) isResultType() {}
