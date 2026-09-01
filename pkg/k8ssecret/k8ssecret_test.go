// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package k8ssecret //nolint: testpackage // Tests use unexported functions

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.riptides.io/tokenex/pkg/credential"
)

var errNotASecret = errors.New("not a secret")

// stubCache satisfies cache.Cache by embedding it; only Get is implemented, which is
// all validateSecretExists uses. Any other call would panic, which is the intent.
type stubCache struct {
	cache.Cache

	secret *corev1.Secret
}

func (s stubCache) Get(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	if s.secret == nil || key.Name != s.secret.GetName() || key.Namespace != s.secret.GetNamespace() {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, key.Name)
	}

	out, ok := obj.(*corev1.Secret)
	if !ok {
		return apierrors.NewInternalError(errNotASecret)
	}

	*out = *s.secret

	return nil
}

func testSecret(data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "riptides-system"},
		Data:       data,
	}
}

func testSecretRef() SecretRef {
	return SecretRef{Name: "creds", Namespace: "riptides-system", Key: "apiKey"}
}

func TestValidateSecretExists(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		secret  *corev1.Secret
		ref     SecretRef
		wantErr bool
	}{
		{
			name:   "secret with a non-token key is fine",
			secret: testSecret(map[string][]byte{"apiKey": []byte("sk_live_x")}),
		},
		{
			name:   "secret keyed token is fine",
			secret: testSecret(map[string][]byte{"token": []byte("sk_live_x")}),
		},
		{
			name:   "empty secret is fine; the key is handleEvent's business",
			secret: testSecret(nil),
		},
		{
			name:    "missing secret is reported",
			secret:  nil,
			wantErr: true,
		},
		{
			name:    "looks the secret up by the configured name",
			secret:  testSecret(map[string][]byte{"apiKey": []byte("sk_live_x")}),
			ref:     SecretRef{Name: "other", Namespace: "riptides-system", Key: "apiKey"},
			wantErr: true,
		},
		{
			name:    "looks the secret up by the configured namespace",
			secret:  testSecret(map[string][]byte{"apiKey": []byte("sk_live_x")}),
			ref:     SecretRef{Name: "creds", Namespace: "other", Key: "apiKey"},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ref := tc.ref
			if ref == (SecretRef{}) {
				ref = testSecretRef()
			}

			cp := &credentialsProvider{cache: stubCache{secret: tc.secret}}

			err := cp.validateSecretExists(context.Background(), ref)

			if tc.wantErr {
				require.Error(t, err)
				require.True(t, apierrors.IsNotFound(err))

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestHandleEvent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		secretRef SecretRef
		obj       any
		del       bool
		wantEvent credential.EventType
		wantToken string
		wantErr   error
		wantNone  bool
	}{
		{
			name:      "reads the configured key",
			secretRef: testSecretRef(),
			obj:       testSecret(map[string][]byte{"apiKey": []byte("sk_live_x")}),
			wantEvent: credential.UpdateEventType,
			wantToken: "sk_live_x",
		},
		{
			name:      "a key named token is not special",
			secretRef: testSecretRef(),
			obj:       testSecret(map[string][]byte{"token": []byte("wrong")}),
			wantEvent: credential.UpdateEventType,
			wantErr:   ErrMissingData,
		},
		{
			name:      "missing key reports missing data",
			secretRef: testSecretRef(),
			obj:       testSecret(map[string][]byte{"other": []byte("x")}),
			wantEvent: credential.UpdateEventType,
			wantErr:   ErrMissingData,
		},
		{
			name:      "delete publishes a remove",
			secretRef: testSecretRef(),
			obj:       testSecret(map[string][]byte{"apiKey": []byte("sk_live_x")}),
			del:       true,
			wantEvent: credential.RemoveEventType,
		},
		{
			name:      "a different secret is ignored",
			secretRef: SecretRef{Name: "other", Namespace: "riptides-system", Key: "apiKey"},
			obj:       testSecret(map[string][]byte{"apiKey": []byte("sk_live_x")}),
			wantNone:  true,
		},
		{
			name:      "a non-secret object is ignored",
			secretRef: testSecretRef(),
			obj:       &corev1.ConfigMap{},
			wantNone:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cp := &credentialsProvider{}
			credsChan := make(chan Credential, 1)

			cp.handleEvent(context.Background(), noop.NewTracerProvider().Tracer(""), nil,
				credsChan, tc.secretRef, tc.obj, tc.del)

			if tc.wantNone {
				require.Empty(t, credsChan, "expected nothing to be published")

				return
			}

			require.Len(t, credsChan, 1)
			got := <-credsChan
			require.Equal(t, tc.wantEvent, got.Event)

			if tc.wantErr != nil {
				require.ErrorIs(t, got.Err, tc.wantErr)

				return
			}

			require.NoError(t, got.Err)

			if tc.wantToken != "" {
				tok, ok := got.Credential.(*credential.Token)
				require.True(t, ok, "expected a *credential.Token, got %T", got.Credential)
				require.Equal(t, tc.wantToken, tok.Token)
			}
		})
	}
}
