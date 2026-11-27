// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

// Package httpx holds the HTTP limits the providers share.
package httpx

import (
	"io"
	"net/http"
	"net/url"
	"time"

	"emperror.dev/errors"
)

const (
	// DefaultTimeout bounds one request, so an endpoint that never answers
	// fails the fetch instead of parking its refresh loop.
	DefaultTimeout = 30 * time.Second

	// MaxTokenBody is the largest token endpoint response a provider reads.
	MaxTokenBody = 1 << 20

	// MaxSecretBody is the largest secrets response a provider reads.
	MaxSecretBody = 16 << 20

	// MaxErrorBody is the largest error response read through LimitResponses.
	MaxErrorBody = 64 << 10

	// maxSnippet is how much of a response body goes into an error.
	maxSnippet = 512
)

var ErrBodyTooLarge = errors.NewPlain("response body too large")

// NoRedirect is a CheckRedirect that returns a redirect response instead of
// following it. A followed 307 or 308 repeats the request body, which carries
// the identity token, to whatever host the response names.
func NoRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// WithTimeout returns a copy of base, or a new client if base is nil, that
// uses DefaultTimeout unless base sets its own.
func WithTimeout(base *http.Client) *http.Client {
	client := &http.Client{}
	if base != nil {
		*client = *base
	}

	if client.Timeout == 0 {
		client.Timeout = DefaultTimeout
	}

	return client
}

// ExchangeClient returns WithTimeout(base) that also does not follow
// redirects, unless base sets its own CheckRedirect.
func ExchangeClient(base *http.Client) *http.Client {
	client := WithTimeout(base)

	if client.CheckRedirect == nil {
		client.CheckRedirect = NoRedirect
	}

	return client
}

// ReadBody reads a response body of at most limit bytes.
func ReadBody(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}

	if int64(len(data)) > limit {
		return nil, errors.WithDetails(ErrBodyTooLarge, "limit", limit)
	}

	return data, nil
}

// Snippet returns the start of a response body, short enough for an error.
func Snippet[T ~string | ~[]byte](body T) string {
	if len(body) <= maxSnippet {
		return string(body)
	}

	return string(body[:maxSnippet]) + "... (truncated)"
}

// RedactURL returns rawURL without its user information, for spans and logs.
func RedactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "(invalid URL)"
	}

	if u.User == nil {
		return rawURL
	}

	u.User = nil

	return u.String()
}

// LimitResponses returns a transport that fails the read of a response body
// once it passes limit, or errLimit for a response with an error status. It is
// for clients that read the body themselves, such as the Vault client.
func LimitResponses(base http.RoundTripper, limit, errLimit int64) http.RoundTripper {
	return &limitTransport{base: base, limit: limit, errLimit: errLimit}
}

type limitTransport struct {
	base     http.RoundTripper
	limit    int64
	errLimit int64
}

func (t *limitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	limit := t.limit
	if resp.StatusCode >= http.StatusBadRequest {
		limit = t.errLimit
	}

	resp.Body = &limitedBody{ReadCloser: resp.Body, limit: limit, left: limit}

	return resp, nil
}

type limitedBody struct {
	io.ReadCloser

	limit int64
	left  int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, errors.WithDetails(ErrBodyTooLarge, "limit", b.limit)
	}

	// One byte past the limit tells a body of exactly limit bytes from a larger one.
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}

	n, err := b.ReadCloser.Read(p)

	b.left -= int64(n)
	if b.left < 0 {
		return n, errors.WithDetails(ErrBodyTooLarge, "limit", b.limit)
	}

	return n, err
}
