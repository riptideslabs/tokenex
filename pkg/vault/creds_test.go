// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package vault //nolint:testpackage // Tests use unexported fields

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/token"
)

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

	if r.URL.Path == "/v1/auth/jwt/login" {
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
