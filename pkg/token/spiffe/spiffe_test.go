// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package spiffe_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"go.riptides.io/tokenex/pkg/aws"
	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token/spiffe"
)

const (
	workloadID = "spiffe://example.org/workload"
	stsAud     = "sts.amazonaws.com"
)

type respondFunc func(*workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error)

// fakeWorkloadAPI serves FetchJWTSVID like a SPIRE agent would.
type fakeWorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer

	respond respondFunc

	mu       sync.Mutex
	requests []*workload.JWTSVIDRequest
}

func (f *fakeWorkloadAPI) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	if md, _ := metadata.FromIncomingContext(ctx); len(md.Get("workload.spiffe.io")) != 1 || md.Get("workload.spiffe.io")[0] != "true" {
		return nil, status.Error(codes.InvalidArgument, "security header missing from request")
	}

	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.mu.Unlock()

	return f.respond(req)
}

func (f *fakeWorkloadAPI) Requests() []*workload.JWTSVIDRequest {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]*workload.JWTSVIDRequest(nil), f.requests...)
}

// startWorkloadAPI serves a fake Workload API on a unix socket and returns its address.
func startWorkloadAPI(t *testing.T, respond respondFunc) (*fakeWorkloadAPI, string) {
	t.Helper()

	// t.TempDir() can exceed the 104 byte unix socket path limit on macOS.
	dir, err := os.MkdirTemp("", "spiffe") //nolint:usetesting
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })

	sock := filepath.Join(dir, "agent.sock")

	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	require.NoError(t, err)

	fake := &fakeWorkloadAPI{respond: respond}

	srv := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(srv, fake)

	go srv.Serve(lis) //nolint:errcheck

	t.Cleanup(srv.Stop)

	return fake, "unix://" + sock
}

func newSVID(t *testing.T, aud []string, exp time.Time, jti string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": workloadID,
		"aud": aud,
		"exp": exp.Unix(),
		"iat": time.Now().Unix(),
		"jti": jti,
	})
	tok.Header["kid"] = "test"

	s, err := tok.SignedString(key)
	require.NoError(t, err)

	return s
}

func respondWith(svids ...string) respondFunc {
	return func(*workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
		resp := &workload.JWTSVIDResponse{}
		for _, s := range svids {
			resp.Svids = append(resp.Svids, &workload.JWTSVID{SpiffeId: workloadID, Svid: s})
		}

		return resp, nil
	}
}

func newProvider(t *testing.T, addr string, opts ...option.Option) *spiffe.IdentityTokenProvider {
	t.Helper()

	all := append([]option.Option{
		spiffe.WithAudience(stsAud),
		spiffe.WithAddr(addr),
	}, opts...)

	p, err := spiffe.NewIdentityTokenProvider(all...)
	require.NoError(t, err)

	return p
}

func TestGetToken_RequestShape(t *testing.T) {
	t.Parallel()

	exp := time.Now().Add(5 * time.Minute)
	svid := newSVID(t, []string{stsAud, "example"}, exp, "1")

	fake, addr := startWorkloadAPI(t, respondWith(svid))

	p := newProvider(t, addr,
		spiffe.WithAudience(stsAud, "example"),
		spiffe.WithSPIFFEID(spiffeid.RequireFromString(workloadID)),
	)

	tok, err := p.GetToken(t.Context())
	require.NoError(t, err)
	assert.Equal(t, svid, tok.Token)
	assert.Equal(t, exp.Unix(), tok.ExpiresAt.Unix())

	reqs := fake.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, []string{stsAud, "example"}, reqs[0].GetAudience())
	assert.Equal(t, workloadID, reqs[0].GetSpiffeId())
}

func TestGetToken_DefaultSPIFFEID(t *testing.T) {
	t.Parallel()

	fake, addr := startWorkloadAPI(t, respondWith(newSVID(t, []string{stsAud}, time.Now().Add(time.Minute), "1")))

	_, err := newProvider(t, addr).GetToken(t.Context())
	require.NoError(t, err)

	reqs := fake.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, []string{stsAud}, reqs[0].GetAudience())
	assert.Empty(t, reqs[0].GetSpiffeId())
}

func TestGetToken_FetchesEveryCall(t *testing.T) {
	t.Parallel()

	exp := time.Now().Add(5 * time.Minute)
	svids := []string{
		newSVID(t, []string{stsAud}, exp, "1"),
		newSVID(t, []string{stsAud}, exp, "2"),
	}

	var (
		mu sync.Mutex
		n  int
	)

	fake, addr := startWorkloadAPI(t, func(req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
		mu.Lock()
		svid := svids[n%len(svids)]
		n++
		mu.Unlock()

		return respondWith(svid)(req)
	})

	p := newProvider(t, addr)

	first, err := p.GetToken(t.Context())
	require.NoError(t, err)

	second, err := p.GetToken(t.Context())
	require.NoError(t, err)

	assert.Len(t, fake.Requests(), 2)
	assert.NotEqual(t, first.Token, second.Token)
}

func TestGetToken_Errors(t *testing.T) {
	t.Parallel()

	future := time.Now().Add(5 * time.Minute)

	tests := []struct {
		name    string
		respond respondFunc
		wantErr string
	}{
		{
			name: "permission denied",
			respond: func(*workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
				return nil, status.Error(codes.PermissionDenied, "no identity issued")
			},
			wantErr: "no identity issued",
		},
		{name: "no SVIDs", respond: respondWith(), wantErr: "no SVIDs"},
		{name: "SVID is not a JWT", respond: respondWith("not-a-jwt"), wantErr: "unable to parse JWT token"},
		{name: "wrong audience", respond: respondWith(newSVID(t, []string{"other"}, future, "1")), wantErr: "expected audience"},
		{name: "expired", respond: respondWith(newSVID(t, []string{stsAud}, time.Now().Add(-5*time.Minute), "1")), wantErr: "token has expired"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, addr := startWorkloadAPI(t, tt.respond)

			_, err := newProvider(t, addr).GetToken(t.Context())
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestGetToken_AgentUnreachable(t *testing.T) {
	t.Parallel()

	p := newProvider(t, "unix:///nonexistent/agent.sock")

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)

	_, err := p.GetToken(ctx)
	require.ErrorContains(t, err, "could not fetch JWT-SVID")
}

func TestNewIdentityTokenProvider_Validation(t *testing.T) {
	tests := []struct {
		name    string
		envAddr string
		opts    []option.Option
		wantErr string
	}{
		{name: "missing audience", envAddr: "unix:///tmp/agent.sock", wantErr: "audience is required"},
		{name: "missing address", opts: []option.Option{spiffe.WithAudience(stsAud)}, wantErr: workloadapi.SocketEnv},
		{
			name:    "address without scheme",
			opts:    []option.Option{spiffe.WithAudience(stsAud), spiffe.WithAddr("/tmp/agent.sock")},
			wantErr: "invalid Workload API address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(workloadapi.SocketEnv, tt.envAddr)

			_, err := spiffe.NewIdentityTokenProvider(tt.opts...)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestNewIdentityTokenProvider_FromEnv(t *testing.T) {
	svid := newSVID(t, []string{stsAud}, time.Now().Add(time.Minute), "1")
	_, addr := startWorkloadAPI(t, respondWith(svid))

	t.Setenv(workloadapi.SocketEnv, addr)

	p, err := spiffe.NewIdentityTokenProvider(spiffe.WithAudience(stsAud))
	require.NoError(t, err)

	tok, err := p.GetToken(t.Context())
	require.NoError(t, err)
	assert.Equal(t, svid, tok.Token)
}

func TestWithSource(t *testing.T) {
	svid := newSVID(t, []string{stsAud}, time.Now().Add(time.Minute), "1")
	fake, addr := startWorkloadAPI(t, respondWith(svid))

	// The source carries its own address, so none is needed from the environment.
	t.Setenv(workloadapi.SocketEnv, "")

	client, err := workloadapi.New(t.Context(), workloadapi.WithAddr(addr))
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })

	p, err := spiffe.NewIdentityTokenProvider(spiffe.WithAudience(stsAud), spiffe.WithSource(client))
	require.NoError(t, err)

	for range 2 {
		tok, err := p.GetToken(t.Context())
		require.NoError(t, err)
		assert.Equal(t, svid, tok.Token)
	}

	assert.Len(t, fake.Requests(), 2)
}

func TestWithAWSExchange(t *testing.T) {
	t.Parallel()

	const roleArn = "arn:aws:iam::123456789012:role/spire-workload"

	svid := newSVID(t, []string{stsAud}, time.Now().Add(5*time.Minute), "1")
	_, addr := startWorkloadAPI(t, respondWith(svid))

	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "AssumeRoleWithWebIdentity", r.PostForm.Get("Action"))
		assert.Equal(t, roleArn, r.PostForm.Get("RoleArn"))
		assert.Equal(t, svid, r.PostForm.Get("WebIdentityToken"))

		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
      <SecretAccessKey>secret</SecretAccessKey>
      <SessionToken>session</SessionToken>
      <Expiration>%s</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(sts.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	cp, err := aws.NewCredentialsProvider(ctx, logr.Discard(), &awssdk.Config{
		Region:       "us-east-1",
		BaseEndpoint: awssdk.String(sts.URL),
		HTTPClient:   sts.Client(),
	})
	require.NoError(t, err)

	ch, err := cp.GetCredentials(ctx, newProvider(t, addr),
		aws.WithRoleArn(roleArn),
		aws.WithRoleSessionName("spire-workload"),
	)
	require.NoError(t, err)

	cred, ok := <-ch
	require.True(t, ok, "channel closed without sending a credential")
	require.NoError(t, cred.Err)

	creds, ok := cred.Credential.(*credential.AWSCreds)
	require.True(t, ok)
	assert.Equal(t, "ASIAEXAMPLE", creds.AccessKeyID)
}
