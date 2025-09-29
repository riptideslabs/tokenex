// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package aws

import (
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
)

// Option is a function that modifies the credentialsConfig.
type (
	CredentialsOption interface {
		Apply(*credentialsConfig)
	}
	credentialsOption struct {
		option.Option
		f func(*credentialsConfig)
	}
)

func (o *credentialsOption) Apply(c *credentialsConfig) {
	o.f(c)
}

func withCredentialsOption(f func(*credentialsConfig)) option.Option {
	return &credentialsOption{option.OptionImpl{}, f}
}

func isCredentialsOption(opt any) (CredentialsOption, bool) {
	if o, ok := opt.(*credentialsOption); ok {
		return o, ok
	}

	return nil, false
}

// WithRoleArn sets the role ARN for assuming the role.
// This is a required option for AWS credential exchange.
// The role ARN specifies the AWS IAM role that will be assumed using the federated identity.
func WithRoleArn(roleArn string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.roleArn = roleArn
	})
}

// WithRoleSessionName sets the role session name.
// This is a required option for AWS credential exchange.
// The session name is used to identify the session in AWS CloudTrail logs.
func WithRoleSessionName(sessionName string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.roleSessionName = sessionName
	})
}

// WithDurationSeconds sets the duration in seconds for the assumed role session.
// The value must be between 900 (15 minutes) and 43200 (12 hours).
func WithDurationSeconds(duration int32) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.durationSeconds = &duration
	})
}

// WithIdentityTokenProvider sets an identity token provider.
// This is a required option for AWS credential exchange.
// The identity token provider supplies the ID token that will be exchanged for AWS credentials.
// The provider should handle token refreshing internally if needed.
func WithIdentityTokenProvider(idtp token.IdentityTokenProvider) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.identityTokenProvider = idtp
	})
}
