// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package conjur //nolint:testpackage // Tests use unexported functions

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
)

const (
	testAccount     = "myorg"
	testServiceID   = "riptides"
	testJWT         = "header.payload.signature"
	testAccessToken = `{"protected":"p","payload":"x","signature":"s"}`

	usernameKey  = "username"
	passwordKey  = "password"
	usernameID   = "db/username"
	passwordID   = "db/password"
	testUsername = "admin"
	testPassword = "p@ss,wörd\n\x00"
)

type testTokenProvider struct {
	token string
}

func (p testTokenProvider) GetToken(_ context.Context, _ ...option.Option) (credential.Token, error) {
	return credential.Token{Token: p.token, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

// fakeConjur serves the JWT authenticator and batch secrets endpoints under prefix.
type fakeConjur struct {
	t        *testing.T
	prefix   string
	hostPath string // escaped host segment expected in the authenticate URL, if any
	base64   bool   // whether Accept-Encoding: base64 is honored

	mu     sync.Mutex
	values map[string]string // variable ID -> value
}

func (f *fakeConjur) setValue(id, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.values[id] = value
}

func (f *fakeConjur) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authnPath := f.prefix + "/authn-jwt/" + testServiceID + "/" + testAccount
	if f.hostPath != "" {
		authnPath += "/" + f.hostPath
	}
	authnPath += "/authenticate"

	switch r.URL.EscapedPath() {
	case authnPath:
		f.authenticate(w, r)
	case f.prefix + "/secrets":
		f.secrets(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeConjur) authenticate(w http.ResponseWriter, r *http.Request) {
	assert.Equal(f.t, http.MethodPost, r.Method)
	assert.Equal(f.t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

	if err := r.ParseForm(); err != nil || r.PostForm.Get("jwt") != testJWT {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	io.WriteString(w, testAccessToken) //nolint:errcheck
}

func (f *fakeConjur) secrets(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	wantAuth := `Token token="` + base64.StdEncoding.EncodeToString([]byte(testAccessToken)) + `"`
	if r.Header.Get("Authorization") != wantAuth {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	assert.Equal(f.t, "base64", r.Header.Get("Accept-Encoding"))

	fullIDs := strings.Split(r.URL.Query().Get("variable_ids"), ",")
	assert.True(f.t, slices.IsSorted(fullIDs), "variable IDs are sorted")
	assert.Len(f.t, slices.Compact(slices.Clone(fullIDs)), len(fullIDs), "variable IDs are distinct")

	resp := map[string]string{}
	for _, fullID := range fullIDs {
		id, _ := strings.CutPrefix(fullID, testAccount+":variable:")

		value, ok := f.values[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":{"code":"not_found","message":"CONJ00076E Variable `+fullID+` is empty or not found."}}`) //nolint:errcheck

			return
		}

		if f.base64 {
			value = base64.StdEncoding.EncodeToString([]byte(value))
		}
		resp[fullID] = value
	}

	if f.base64 {
		w.Header().Set("Content-Encoding", "base64")
	}
	w.Header().Set("Content-Type", "application/json")
	assert.NoError(f.t, json.NewEncoder(w).Encode(resp))
}

func newFakeConjur(t *testing.T) *fakeConjur {
	t.Helper()

	return &fakeConjur{
		t:      t,
		base64: true,
		values: map[string]string{
			usernameID: testUsername,
			passwordID: testPassword,
		},
	}
}

func startProvider(t *testing.T, applianceURL string, tlsConfig *tls.Config, opts ...option.Option) <-chan credential.Result {
	t.Helper()

	cp, err := NewCredentialsProvider(t.Context(), logr.Discard(), applianceURL, tlsConfig)
	require.NoError(t, err)

	opts = append([]option.Option{
		WithAccount(testAccount),
		WithServiceID(testServiceID),
		WithIdentityTokenProvider(testTokenProvider{token: testJWT}),
	}, opts...)

	ch, err := cp.GetCredentialsWithOptions(t.Context(), opts...)
	require.NoError(t, err)

	return ch
}

func receive(t *testing.T, ch <-chan credential.Result) credential.Result {
	t.Helper()

	select {
	case res, ok := <-ch:
		require.True(t, ok, "channel closed")

		return res
	case <-time.After(5 * time.Second):
		require.FailNow(t, "timed out waiting for a result")
	}

	return credential.Result{}
}

func requireSecret(t *testing.T, res credential.Result) map[string]any {
	t.Helper()

	require.NoError(t, res.Err)
	require.Equal(t, credential.UpdateEventType, res.Event)

	secret, ok := res.Credential.(*credential.Secret)
	require.True(t, ok, "credential is a *credential.Secret")

	return secret.Data
}

func TestGetCredentials_Success(t *testing.T) {
	t.Parallel()

	// SaaS serves the API under /api.
	fake := newFakeConjur(t)
	fake.prefix = "/api"
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	ch := startProvider(t, srv.URL+"/api/", nil, WithVariables(map[string]string{
		usernameKey: usernameID,
		"user":      usernameID,
		passwordKey: passwordID,
	}))

	assert.Equal(t, map[string]any{
		usernameKey: testUsername,
		"user":      testUsername,
		passwordKey: testPassword,
	}, requireSecret(t, receive(t, ch)))
}

func TestGetCredentials_PlainValues(t *testing.T) {
	t.Parallel()

	fake := newFakeConjur(t)
	fake.base64 = false
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	ch := startProvider(t, srv.URL, nil, WithVariables(map[string]string{usernameKey: usernameID}))

	assert.Equal(t, map[string]any{usernameKey: testUsername}, requireSecret(t, receive(t, ch)))
}

func TestGetCredentials_HostID(t *testing.T) {
	t.Parallel()

	for _, hostID := range []string{"apps/myapp", "host/apps/myapp"} {
		t.Run(hostID, func(t *testing.T) {
			t.Parallel()

			fake := newFakeConjur(t)
			fake.hostPath = "host%2Fapps%2Fmyapp"
			srv := httptest.NewServer(fake)
			t.Cleanup(srv.Close)

			ch := startProvider(t, srv.URL, nil, WithHostID(hostID), WithVariables(map[string]string{usernameKey: usernameID}))

			assert.Equal(t, map[string]any{usernameKey: testUsername}, requireSecret(t, receive(t, ch)))
		})
	}
}

func TestGetCredentials_PollsForRotation(t *testing.T) {
	t.Parallel()

	fake := newFakeConjur(t)
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	ch := startProvider(t, srv.URL, nil, WithPollInterval(20*time.Millisecond), WithVariables(map[string]string{passwordKey: passwordID}))

	assert.Equal(t, testPassword, requireSecret(t, receive(t, ch))[passwordKey])

	fake.setValue(passwordID, "rotated")

	var password any
	for password != "rotated" {
		password = requireSecret(t, receive(t, ch))[passwordKey]
	}
}

func TestGetCredentials_AuthenticationFailure(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(newFakeConjur(t))
	t.Cleanup(srv.Close)

	ch := startProvider(t, srv.URL, nil,
		WithIdentityTokenProvider(testTokenProvider{token: "wrong.jwt.token"}),
		WithVariables(map[string]string{usernameKey: usernameID}),
	)

	res := receive(t, ch)
	require.Error(t, res.Err)
	assert.Contains(t, res.Err.Error(), "failed to authenticate with Conjur")
	assert.Contains(t, res.Err.Error(), "401")
	assert.Nil(t, res.Credential)

	_, ok := <-ch
	assert.False(t, ok, "channel is closed after an error")
}

func TestGetCredentials_VariableNotFound(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(newFakeConjur(t))
	t.Cleanup(srv.Close)

	ch := startProvider(t, srv.URL, nil, WithVariables(map[string]string{usernameKey: usernameID, "key": "db/missing"}))

	res := receive(t, ch)
	require.Error(t, res.Err)
	assert.Contains(t, res.Err.Error(), "404")
	assert.Contains(t, res.Err.Error(), "CONJ00076E Variable myorg:variable:db/missing is empty or not found.")
}

func TestGetCredentials_PrivateCA(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(newFakeConjur(t))
	t.Cleanup(srv.Close)

	vars := WithVariables(map[string]string{usernameKey: usernameID})

	t.Run("untrusted", func(t *testing.T) {
		t.Parallel()

		res := receive(t, startProvider(t, srv.URL, nil, vars))
		require.Error(t, res.Err)
		assert.Contains(t, res.Err.Error(), "certificate")
	})

	t.Run("trusted", func(t *testing.T) {
		t.Parallel()

		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())

		res := receive(t, startProvider(t, srv.URL, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, vars))
		assert.Equal(t, map[string]any{usernameKey: testUsername}, requireSecret(t, res))
	})
}

func TestGetCredentialsWithOptions_InvalidConfig(t *testing.T) {
	t.Parallel()

	cp, err := NewCredentialsProvider(t.Context(), logr.Discard(), "https://conjur.example.com", nil)
	require.NoError(t, err)

	_, err = cp.GetCredentialsWithOptions(t.Context(), WithAccount(testAccount), WithServiceID(testServiceID))
	require.Error(t, err)
}

func TestValidateConfig(t *testing.T) {
	t.Parallel()

	valid := func() *credentialsConfig {
		return &credentialsConfig{
			account:               testAccount,
			serviceID:             testServiceID,
			variables:             map[string]string{passwordKey: passwordID},
			pollInterval:          time.Minute,
			identityTokenProvider: testTokenProvider{},
		}
	}

	tests := []struct {
		name    string
		mutate  func(*credentialsConfig)
		wantErr string
	}{
		{name: "valid", mutate: func(*credentialsConfig) {}},
		{name: "missing account", mutate: func(c *credentialsConfig) { c.account = "" }, wantErr: "account is required"},
		{name: "missing service ID", mutate: func(c *credentialsConfig) { c.serviceID = "" }, wantErr: "service ID is required"},
		{name: "no variables", mutate: func(c *credentialsConfig) { c.variables = nil }, wantErr: "at least one variable"},
		{name: "empty key", mutate: func(c *credentialsConfig) { c.variables = map[string]string{"": passwordID} }, wantErr: "key must not be empty"},
		{name: "empty variable ID", mutate: func(c *credentialsConfig) { c.variables = map[string]string{passwordKey: ""} }, wantErr: "ID must not be empty"},
		{name: "comma in variable ID", mutate: func(c *credentialsConfig) { c.variables = map[string]string{passwordKey: "a,b"} }, wantErr: "comma"},
		{name: "zero poll interval", mutate: func(c *credentialsConfig) { c.pollInterval = 0 }, wantErr: "poll interval"},
		{name: "missing token provider", mutate: func(c *credentialsConfig) { c.identityTokenProvider = nil }, wantErr: "identity token provider"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := valid()
			tt.mutate(cfg)

			err := validateConfig(cfg)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func TestNewCredentialsProvider_InvalidURL(t *testing.T) {
	t.Parallel()

	for _, u := range []string{"", "conjur.example.com", "ftp://conjur.example.com", "https://conjur.example.com?x=1", "https://conjur.example.com#x"} {
		_, err := NewCredentialsProvider(t.Context(), logr.Discard(), u, nil)
		assert.Error(t, err, u)
	}
}
