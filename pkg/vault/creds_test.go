// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package vault //nolint:testpackage // Tests use unexported fields

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"go.riptides.io/tokenex/internal/httpx"
	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/token"
)

const loginPath = "/v1/auth/jwt/login"

// fakeVault gives role R the token "tok-R" and serves secret/R only to that
// token. It records the token each login request arrived with.
type fakeVault struct {
	*httptest.Server

	mu          sync.Mutex
	loginTokens []string
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()

	v := &fakeVault{}
	v.Server = httptest.NewServer(http.HandlerFunc(v.serve))
	t.Cleanup(v.Close)

	return v
}

func (v *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.URL.Path == loginPath {
		var body struct {
			Role string `json:"role"`
		}

		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		v.mu.Lock()
		v.loginTokens = append(v.loginTokens, r.Header.Get("X-Vault-Token"))
		v.mu.Unlock()

		io.WriteString(w, `{"auth":{"client_token":"tok-`+body.Role+`","lease_duration":3600}}`) //nolint:errcheck

		return
	}

	name, ok := strings.CutPrefix(r.URL.Path, "/v1/secret/")
	if !ok || r.Header.Get("X-Vault-Token") != "tok-"+name {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"errors":["permission denied"]}`) //nolint:errcheck

		return
	}

	io.WriteString(w, `{"data":{"value":"secret-of-`+name+`"}}`) //nolint:errcheck
}

func testJWT() string {
	enc := base64.RawURLEncoding.EncodeToString
	claims := `{"sub":"test","exp":` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `}`

	return enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc([]byte(claims)) + ".sig"
}

// fetch returns the value role reads at secret/<name>, or the error.
func fetch(ctx context.Context, cp *credentialsProvider, role, name string) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ch, err := cp.GetCredentials(ctx, token.NewStaticIdentityTokenProvider(testJWT()),
		WithJWTAuthRoleName(role), WithSecretFullPath("secret/"+name))
	if err != nil {
		return nil, err
	}

	res := <-ch
	if res.Err != nil {
		return nil, res.Err
	}

	secret, _ := res.Credential.(*credential.Secret)
	if secret == nil {
		return nil, ErrDataNotFound
	}

	return secret.Data["value"], nil
}

// A fetch must leave no Vault token behind for the next identity.
func TestFetchKeepsVaultTokenToItself(t *testing.T) {
	t.Parallel()

	v := newFakeVault(t)

	cp, err := NewCredentialsProvider(t.Context(), logr.Discard(), v.URL, nil)
	require.NoError(t, err)

	// Empty, unless the environment sets one.
	before := cp.client.Token()

	for _, role := range []string{"a", "b"} {
		got, err := fetch(t.Context(), cp, role, role)
		require.NoError(t, err)
		assert.Equal(t, "secret-of-"+role, got)
	}

	assert.Equal(t, before, cp.client.Token(), "a fetch left its token on the shared client")

	v.mu.Lock()
	defer v.mu.Unlock()

	assert.Equal(t, []string{"", ""}, v.loginTokens, "a login carried a token")
}

// Identities fetching at once through one provider each read with their own
// token: their own secret succeeds, another's is denied.
func TestConcurrentIdentitiesReadWithTheirOwnToken(t *testing.T) {
	t.Parallel()

	v := newFakeVault(t)

	cp, err := NewCredentialsProvider(t.Context(), logr.Discard(), v.URL, nil)
	require.NoError(t, err)

	const rounds = 50

	var wg sync.WaitGroup

	for _, role := range []string{"a", "b", "c", "d"} {
		wg.Go(func() {
			for range rounds {
				got, err := fetch(t.Context(), cp, role, role)
				if assert.NoError(t, err) {
					assert.Equal(t, "secret-of-"+role, got)
				}
			}
		})
	}

	wg.Go(func() {
		for range rounds {
			got, err := fetch(t.Context(), cp, "intruder", "a")
			assert.Error(t, err, "read another identity's secret: %v", got)
		}
	})

	wg.Wait()
}

// Without a timeout a Vault that never answers parks the refresh loop.
func TestFetchClientHasRequestTimeout(t *testing.T) {
	t.Parallel()

	cp, err := NewCredentialsProvider(t.Context(), logr.Discard(), "https://vault.example.com", nil)
	require.NoError(t, err)

	client, err := cp.fetchClient()
	require.NoError(t, err)
	assert.Equal(t, requestTimeout, client.ClientTimeout())
}

// The Vault client reads a response body whole, whatever its size.
func TestResponseBodiesAreLimited(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		status int
		size   int
	}{
		"secret": {http.StatusOK, httpx.MaxSecretBody + 1},
		"error":  {http.StatusForbidden, httpx.MaxErrorBody + 1},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == loginPath {
					io.WriteString(w, `{"auth":{"client_token":"tok","lease_duration":3600}}`) //nolint:errcheck

					return
				}

				w.WriteHeader(tc.status)
				io.WriteString(w, strings.Repeat("x", tc.size)) //nolint:errcheck
			}))
			t.Cleanup(srv.Close)

			cp, err := NewCredentialsProvider(t.Context(), logr.Discard(), srv.URL, nil)
			require.NoError(t, err)

			_, err = fetch(t.Context(), cp, "a", "a")
			require.ErrorIs(t, err, httpx.ErrBodyTooLarge)
		})
	}
}

func TestValidateConfig(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		mutate  func(*credentialsConfig)
		wantErr string
	}{
		"defaults":                    {func(*credentialsConfig) {}, ""},
		"nested auth path":            {func(c *credentialsConfig) { c.jwtAuthMethodPath = "team/jwt/" }, ""},
		"auth path leaving auth/":     {func(c *credentialsConfig) { c.jwtAuthMethodPath = "../kv1/x" }, "segments"},
		"auth path with a dot":        {func(c *credentialsConfig) { c.jwtAuthMethodPath = "jwt/./x" }, "segments"},
		"poll interval at the limit":  {func(c *credentialsConfig) { c.pollInterval = minPollInterval }, ""},
		"poll interval under a limit": {func(c *credentialsConfig) { c.pollInterval = time.Millisecond }, "poll interval"},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := &credentialsConfig{
				jwtAuthRoleName:       "role",
				secretFullPath:        "secret/a",
				identityTokenProvider: token.NewStaticIdentityTokenProvider(testJWT()),
			}
			setDefaults(cfg)
			tc.mutate(cfg)

			err := validateConfig(cfg)
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}

// serviceAccountKey returns a service account key that names tokenURI.
func serviceAccountKey(t *testing.T, tokenURI string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	keyJSON, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"client_email":   "test@project.iam.gserviceaccount.com",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"private_key_id": "kid",
		"token_uri":      tokenURI,
	})
	require.NoError(t, err)

	return keyJSON
}

// The key comes from the Vault secret. Its token_uri must not decide where the
// signed assertion goes.
func TestGCPKeyWithForeignTokenURIIsRejected(t *testing.T) {
	t.Parallel()

	var called atomic.Bool

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"at","token_type":"Bearer","expires_in":3600}`) //nolint:errcheck
	}))
	t.Cleanup(target.Close)

	keyData := base64.StdEncoding.EncodeToString(serviceAccountKey(t, target.URL))

	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == loginPath {
			io.WriteString(w, `{"auth":{"client_token":"tok","lease_duration":3600}}`) //nolint:errcheck

			return
		}

		io.WriteString(w, `{"data":{"private_key_data":"`+keyData+`"}}`) //nolint:errcheck
	}))
	t.Cleanup(vault.Close)

	cp, err := NewCredentialsProvider(t.Context(), logr.Discard(), vault.URL, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	ch, err := cp.GetCredentials(ctx, token.NewStaticIdentityTokenProvider(testJWT()),
		WithJWTAuthRoleName("a"), WithSecretFullPath("gcp/key/a"), WithGCPServiceAccountKeyExchange())
	require.NoError(t, err)

	res := <-ch
	require.ErrorContains(t, res.Err, "token_uri")
	assert.False(t, called.Load(), "the assertion was sent to the token_uri of the key")
}

func TestCheckGCPTokenURI(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		tokenURI string
		universe string
		ok       bool
	}{
		{"", "", true},
		{"https://oauth2.googleapis.com/token", "", true},
		{"https://oauth2.googleapis.com:443/token", "", true},
		{"https://OAuth2.GoogleAPIs.com/token", "", true},
		{"https://www.googleapis.com/oauth2/v4/token", "googleapis.com", true},
		{"https://accounts.google.com/o/oauth2/token", "", true},
		{"https://oauth2-myendpoint.p.googleapis.com/token", "", true},
		{"https://oauth2.example-universe.goog/token", "example-universe.goog", true},
		{"https://oauth2.example-universe.goog/token", "", false},
		{"https://iam.example-universe.goog/token", "example-universe.goog", false},
		{"http://oauth2.googleapis.com/token", "", false},
		{"https://oauth2.googleapis.com:8443/token", "", false},
		{"https://oauth2.googleapis.com.example.com/", "", false},
		{"https://oauth2.googleapis.com@example.com/", "", false},
		{"https://example.com/oauth2.googleapis.com", "", false},
		{"https://notgoogleapis.com/token", "", false},
	} {
		keyJSON, err := json.Marshal(map[string]string{"token_uri": tc.tokenURI, "universe_domain": tc.universe})
		require.NoError(t, err)

		err = checkGCPTokenURI(keyJSON)
		if tc.ok {
			require.NoError(t, err, tc.tokenURI)
		} else {
			require.Error(t, err, tc.tokenURI)
		}
	}
}

// Following a redirect would repeat the signed assertion to the host it names.
func TestGCPExchangeDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	var followed atomic.Bool

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed.Store(true)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"at","token_type":"Bearer","expires_in":3600}`) //nolint:errcheck
	}))
	t.Cleanup(target.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)

	provider := gcpAccessTokenProvider{
		serviceAccountKeyJSON: serviceAccountKey(t, srv.URL),
		tracer:                noop.NewTracerProvider().Tracer(""),
		logger:                logr.Discard(),
	}

	_, err := provider.fetchAccessToken(t.Context(), trace.SpanContext{}, nil)
	require.Error(t, err)
	assert.False(t, followed.Load(), "the redirect was followed")
}
