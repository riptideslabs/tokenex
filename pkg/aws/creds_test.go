// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package aws //nolint:testpackage // Tests use the unexported provider

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/token"
)

const stsResponse = `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">` +
	`<AssumeRoleWithWebIdentityResult>%CREDENTIALS%</AssumeRoleWithWebIdentityResult>` +
	`<ResponseMetadata><RequestId>id</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`

func testJWT() string {
	enc := base64.RawURLEncoding.EncodeToString
	claims := `{"sub":"test","exp":` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `}`

	return enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc([]byte(claims)) + ".sig"
}

// results returns everything the provider publishes when STS answers with the
// given Credentials element.
func results(t *testing.T, credentials string) []credential.Result {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		io.WriteString(w, strings.Replace(stsResponse, "%CREDENTIALS%", credentials, 1)) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	// A slow logger gives the reader time to see each result before the next one replaces it.
	logger := funcr.New(func(string, string) { time.Sleep(20 * time.Millisecond) }, funcr.Options{Verbosity: 2})

	cp, err := NewCredentialsProvider(t.Context(), logger, &awssdk.Config{
		Region:       "us-east-1",
		BaseEndpoint: awssdk.String(srv.URL),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	ch, err := cp.GetCredentials(ctx, token.NewStaticIdentityTokenProvider(testJWT()),
		WithRoleArn("arn:aws:iam::123456789012:role/test"), WithRoleSessionName("test"))
	require.NoError(t, err)

	got := make([]credential.Result, 0, 1)
	for res := range ch {
		got = append(got, res)
	}

	return got
}

// The SDK dereferences the credentials of the response without a nil check.
func TestResponseWithoutCredentialsIsAnError(t *testing.T) {
	t.Parallel()

	got := results(t, "")
	require.Len(t, got, 1)
	require.Error(t, got[0].Err)
	assert.Nil(t, got[0].Credential)
}

func TestExpiredCredentialsAreNotPublished(t *testing.T) {
	t.Parallel()

	got := results(t, `<Credentials><AccessKeyId>ASIAEXAMPLE</AccessKeyId><SecretAccessKey>secret</SecretAccessKey>`+
		`<SessionToken>token</SessionToken><Expiration>2020-01-01T00:00:00Z</Expiration></Credentials>`)
	require.Len(t, got, 1)
	require.Error(t, got[0].Err)
	assert.Nil(t, got[0].Credential)
}
