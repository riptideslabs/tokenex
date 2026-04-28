// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package githubapp

import (
	"crypto/rsa"
	"net/http"

	"github.com/google/go-github/v66/github"

	"go.riptides.io/tokenex/pkg/option"
)

// CredentialsOption is the interface implemented by all githubapp options.
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

// WithAppID sets the GitHub App ID. Required.
func WithAppID(id int64) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.appID = id
	})
}

// WithInstallationID sets the GitHub App installation ID to mint a token for. Required.
func WithInstallationID(id int64) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.installationID = id
	})
}

// WithPrivateKey sets the App's RSA private key used to sign the App JWT. Required.
// Use ParsePrivateKey to obtain a *rsa.PrivateKey from PEM bytes.
func WithPrivateKey(key *rsa.PrivateKey) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.privateKey = key
	})
}

// WithRepositories scopes the issued installation token to specific repositories
// in the installation's account. Pass bare repository names (no "owner/" prefix).
// Mutually exclusive with WithRepositoryIDs.
func WithRepositories(names []string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.repositories = names
	})
}

// WithRepositoryIDs scopes the issued installation token to specific repositories
// by numeric ID. Mutually exclusive with WithRepositories.
func WithRepositoryIDs(ids []int64) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.repositoryIDs = ids
	})
}

// WithPermissions narrows the issued installation token to a subset of the App's
// installation permissions (e.g. &github.InstallationPermissions{Contents: github.String("read")}).
// Pass nil to omit (the issued token will carry the App's full installation permissions).
// Values are passed through to GitHub unchecked; GitHub returns 422 for invalid combinations.
func WithPermissions(perms *github.InstallationPermissions) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.permissions = perms
	})
}

// WithBaseURL sets the GitHub API base URL. Defaults to https://api.github.com.
// Set this for GitHub Enterprise Server, e.g. "https://github.example.com/api/v3".
func WithBaseURL(url string) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.baseURL = url
	})
}

// WithHTTPClient sets the HTTP client used for token-mint requests. Defaults to
// http.DefaultClient. Use this to control TLS, proxies, timeouts, or retries.
// Only the Transport and Timeout are honored; Jar and CheckRedirect are not
// propagated, since this provider does not use cookies and never follows
// redirects.
func WithHTTPClient(client *http.Client) option.Option {
	return withCredentialsOption(func(c *credentialsConfig) {
		c.httpClient = client
	})
}
