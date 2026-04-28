// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package githubapp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v66/github"
)

func mustGenerateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	return key
}

func TestValidateConfig(t *testing.T) {
	t.Parallel()

	key := mustGenerateKey(t)

	tests := []struct {
		name    string
		cfg     *credentialsConfig
		wantErr bool
	}{
		{
			name: "valid minimal",
			cfg: &credentialsConfig{
				appID:          1,
				installationID: 2,
				privateKey:     key,
			},
			wantErr: false,
		},
		{
			name: "valid with scoping",
			cfg: &credentialsConfig{
				appID:          1,
				installationID: 2,
				privateKey:     key,
				repositories:   []string{"r"},
				permissions:    &github.InstallationPermissions{Contents: github.String("read")},
			},
			wantErr: false,
		},
		{
			name: "missing appID",
			cfg: &credentialsConfig{
				installationID: 2,
				privateKey:     key,
			},
			wantErr: true,
		},
		{
			name: "missing installationID",
			cfg: &credentialsConfig{
				appID:      1,
				privateKey: key,
			},
			wantErr: true,
		},
		{
			name: "missing privateKey",
			cfg: &credentialsConfig{
				appID:          1,
				installationID: 2,
			},
			wantErr: true,
		},
		{
			name: "repositories and repositoryIDs both set",
			cfg: &credentialsConfig{
				appID:          1,
				installationID: 2,
				privateKey:     key,
				repositories:   []string{"r"},
				repositoryIDs:  []int64{1},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateConfig(tt.cfg)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func encodePEM(t *testing.T, blockType string, der []byte) []byte {
	t.Helper()

	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func TestParsePrivateKey(t *testing.T) {
	t.Parallel()

	rsaKey := mustGenerateKey(t)

	pkcs1PEM := encodePEM(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))

	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	pkcs8PEM := encodePEM(t, "PRIVATE KEY", pkcs8DER)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey (EC): %v", err)
	}

	ecPEM := encodePEM(t, "PRIVATE KEY", ecDER)

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{name: "PKCS#1 RSA", input: pkcs1PEM, wantErr: false},
		{name: "PKCS#8 RSA", input: pkcs8PEM, wantErr: false},
		{name: "PKCS#8 EC (rejected)", input: ecPEM, wantErr: true},
		{name: "garbage bytes", input: []byte("not a pem"), wantErr: true},
		{name: "empty", input: nil, wantErr: true},
		{
			name:    "PEM with wrong block type",
			input:   encodePEM(t, "CERTIFICATE", []byte("xxxx")),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParsePrivateKey(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (got=%v)", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got == nil {
				t.Fatalf("expected key, got nil")
			}

			if got.N.Cmp(rsaKey.N) != 0 {
				t.Fatalf("parsed key modulus does not match original")
			}
		})
	}
}

func TestSignAppJWT(t *testing.T) {
	t.Parallel()

	key := mustGenerateKey(t)
	const appID = int64(12345)

	before := time.Now()

	signed, err := signAppJWT(appID, key)
	if err != nil {
		t.Fatalf("signAppJWT: %v", err)
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))

	tok, err := parser.ParseWithClaims(signed, &jwt.RegisteredClaims{}, func(_ *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse signed JWT: %v", err)
	}

	claims, ok := tok.Claims.(*jwt.RegisteredClaims)
	if !ok {
		t.Fatalf("claims have unexpected type %T", tok.Claims)
	}

	if got, want := claims.Issuer, strconv.FormatInt(appID, 10); got != want {
		t.Fatalf("Issuer = %q, want %q", got, want)
	}

	if claims.IssuedAt == nil {
		t.Fatalf("IssuedAt is nil")
	}

	if claims.IssuedAt.After(before) {
		t.Fatalf("IssuedAt %v is after start time %v (no clock-skew leeway)", claims.IssuedAt.Time, before)
	}

	if claims.ExpiresAt == nil {
		t.Fatalf("ExpiresAt is nil")
	}

	if claims.ExpiresAt.After(time.Now().Add(10 * time.Minute)) {
		t.Fatalf("ExpiresAt %v exceeds GitHub's 10-minute cap", claims.ExpiresAt.Time)
	}
}

func TestSetDefaults(t *testing.T) {
	t.Parallel()

	t.Run("fills empty baseURL and nil httpClient", func(t *testing.T) {
		t.Parallel()

		cfg := &credentialsConfig{}
		setDefaults(cfg)

		if cfg.baseURL != "https://api.github.com" {
			t.Fatalf("baseURL = %q, want https://api.github.com", cfg.baseURL)
		}

		if cfg.httpClient == nil {
			t.Fatalf("httpClient is nil, want http.DefaultClient")
		}
	})

	t.Run("trims trailing slash from baseURL", func(t *testing.T) {
		t.Parallel()

		cfg := &credentialsConfig{baseURL: "https://github.example.com/api/v3/"}
		setDefaults(cfg)

		if cfg.baseURL != "https://github.example.com/api/v3" {
			t.Fatalf("baseURL = %q, want trimmed", cfg.baseURL)
		}
	})

	t.Run("preserves explicit values", func(t *testing.T) {
		t.Parallel()

		cfg := &credentialsConfig{
			baseURL: "https://x.example.com/api/v3",
		}
		setDefaults(cfg)

		if cfg.baseURL != "https://x.example.com/api/v3" {
			t.Fatalf("baseURL was overwritten: %q", cfg.baseURL)
		}
	})
}

// recordedTransport is a test double — not safe for concurrent RoundTrip calls.
type recordedTransport struct {
	got *http.Request
}

func (r *recordedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.got = req

	return &http.Response{
		StatusCode: http.StatusNoContent,
		Body:       http.NoBody,
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestAppJWTTransport(t *testing.T) {
	t.Parallel()

	key := mustGenerateKey(t)
	rec := &recordedTransport{}

	transport := &appJWTTransport{
		base:       rec,
		appID:      99,
		privateKey: key,
	}

	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	resp.Body.Close()

	if rec.got == nil {
		t.Fatalf("base transport was not called")
	}

	auth := rec.got.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Fatalf("Authorization header missing or malformed: %q", auth)
	}

	signed := strings.TrimPrefix(auth, "Bearer ")

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))

	tok, err := parser.ParseWithClaims(signed, &jwt.RegisteredClaims{}, func(_ *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse Authorization JWT: %v", err)
	}

	claims, ok := tok.Claims.(*jwt.RegisteredClaims)
	if !ok {
		t.Fatalf("claims wrong type %T", tok.Claims)
	}

	if claims.Issuer != "99" {
		t.Fatalf("Issuer = %q, want %q", claims.Issuer, "99")
	}

	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("original request was mutated: Authorization=%q", got)
	}
}
