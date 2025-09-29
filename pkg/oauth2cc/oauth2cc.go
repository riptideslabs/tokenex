// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package oauth2cc

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"emperror.dev/errors"
	"github.com/go-logr/logr"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	corev1 "k8s.io/api/core/v1"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/util"
)

var (
	ErrMissingData  = errors.NewPlain("missing data")
	ErrInformerSync = errors.NewPlain("could not sync informer cache")
)

type (
	Credential = credential.Result
)

// CredentialsProvider defines the interface for obtaining credentials through OAuth2 client credentials flow.
type CredentialsProvider interface {
	// GetCredentials returns a channel that receives OAuth2 access tokens.
	// The channel provides updates when tokens are refreshed or removed.
	// For the first token and each refresh, an Update event is sent.
	// In case of errors, the Err field is populated, Credential is nil, and the refresh loop exits.
	// When the refresh loop exits, the channel is closed.
	// The tokenEndpointURL is the OAuth2 token endpoint URL.
	// The secretRef specifies the Kubernetes secret containing the client ID and secret.
	// Options can be provided to configure the request (e.g., scopes).
	GetCredentials(ctx context.Context, tokenEndpointURL string, secretRef SecretRef, opts ...option.Option) (<-chan Credential, error)
}

var _ CredentialsProvider = &credentialsProvider{}

// SecretRef contains the reference to a Kubernetes secret that stores OAuth2 client credentials.
// It specifies the name, namespace, and key of the secret.
type SecretRef struct {
	// Name is the name of the Kubernetes secret.
	Name string
	// Namespace is the namespace of the Kubernetes secret.
	Namespace string
	// Key is the key in the secret data that contains the client ID and secret.
	Key string
}

type credentialsConfig struct {
	tokenEndpointURL string
	secretRef        SecretRef
	authStyle        oauth2.AuthStyle
	scopes           []string
	additionalParams map[string][]string
}

type credentialsProvider struct {
	cache cache.Cache
}

// NewCredentialsProvider creates a new instance of CredentialsProvider for OAuth2 client credentials flow.
// The client ID and secret are retrieved from a Kubernetes secret.
//
// Parameters:
//   - ctx: Context for the operation
//   - cache: Kubernetes controller-runtime cache for watching secrets
//
// Returns a credential provider and an error if creation fails
func NewCredentialsProvider(ctx context.Context, cache cache.Cache) (*credentialsProvider, error) {
	return &credentialsProvider{
		cache: cache,
	}, nil
}

// validateConfig validates the configuration and returns an error if any required field is missing.
func validateConfig(cfg *credentialsConfig) error {
	if cfg.tokenEndpointURL == "" {
		return errors.New("tokenEndpointURL is required")
	}

	if cfg.secretRef == (SecretRef{}) {
		return errors.New("secretRef is required")
	}

	return nil
}

// GetCredentialsWithOptions returns OAuth2 credentials using the provided options.
// This method implements the credential.Provider interface.
//
// Options can include:
//   - Token endpoint URL
//   - Secret reference (name, namespace, key)
//   - Authentication style
//   - Scopes
//   - Additional parameters
func (cp *credentialsProvider) GetCredentialsWithOptions(ctx context.Context, opts ...option.Option) (<-chan Credential, error) {
	cfg := &credentialsConfig{}

	for _, opt := range opts {
		if opt, ok := isCredentialsOption(opt); ok {
			opt.Apply(cfg)
		}
	}

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return cp.GetCredentials(ctx, cfg.tokenEndpointURL, cfg.secretRef, opts...)
}

func (cp *credentialsProvider) GetCredentials(
	ctx context.Context,
	tokenEndpointURL string,
	secretRef SecretRef,
	opts ...option.Option,
) (<-chan Credential, error) {
	cfg := &credentialsConfig{
		tokenEndpointURL: tokenEndpointURL,
		secretRef:        secretRef,
	}

	for _, opt := range opts {
		if opt, ok := isCredentialsOption(opt); ok {
			opt.Apply(cfg)
		}
	}

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	credsChan := make(chan Credential, 1)

	if err := (&tokenRetriever{
		provider:  cp,
		cfg:       *cfg,
		ch:        credsChan,
		refreshCh: make(chan struct{}, 1),
	}).start(ctx); err != nil {
		return nil, err
	}

	return credsChan, nil
}

type tokenRetriever struct {
	provider  *credentialsProvider
	cfg       credentialsConfig
	ch        chan Credential
	refreshCh chan struct{}

	mu           sync.Mutex
	clientID     string
	clientSecret string
	secretError  error
}

func (r *tokenRetriever) start(ctx context.Context) error {
	informer, err := r.provider.cache.GetInformer(ctx, &corev1.Secret{}, cache.BlockUntilSynced(true))
	if err != nil {
		return errors.WrapIf(err, "could not get informer")
	}

	handler, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			r.handleEvent(obj, false)
		},
		UpdateFunc: func(oldObj, newObj any) {
			r.handleEvent(newObj, false)
		},
		DeleteFunc: func(obj any) {
			r.handleEvent(obj, true)
		},
	})
	if err != nil {
		return errors.WrapIf(err, "could not register event handler")
	}

	if !toolscache.WaitForNamedCacheSyncWithContext(logr.NewContext(ctx, logr.FromContextOrDiscard(ctx).V(3)), handler.HasSynced) {
		return errors.WithStack(ErrInformerSync)
	}

	go func() {
		defer close(r.ch)

		r.tokenRefresherLoop(ctx)

		if err := informer.RemoveEventHandler(handler); err != nil {
			logr.FromContextOrDiscard(ctx).Error(err, "could not remove event handler")
		}
	}()

	return nil
}

func (r *tokenRetriever) tokenRefresherLoop(ctx context.Context) {
	for {
		r.mu.Lock()
		clientID := r.clientID
		clientSecret := r.clientSecret
		secretErr := r.secretError
		r.mu.Unlock()

		if clientID == "" || clientSecret == "" {
			if secretErr == nil {
				secretErr = errors.New("missing client credentials")
			}

			util.SendToChannel(r.ch, Credential{
				Event: credential.UpdateEventType,
				Err:   secretErr,
			})

			return
		}

		cfg := clientcredentials.Config{
			ClientID:       clientID,
			ClientSecret:   clientSecret,
			TokenURL:       r.cfg.tokenEndpointURL,
			Scopes:         r.cfg.scopes,
			EndpointParams: url.Values(r.cfg.additionalParams),
			AuthStyle:      r.cfg.authStyle,
		}

		token, err := cfg.Token(ctx)
		if err != nil {
			util.SendToChannel(r.ch, Credential{
				Event: credential.UpdateEventType,
				Err:   err,
			})

			return
		}

		cred := credential.Oauth2Creds(*token)

		util.SendToChannel(r.ch, Credential{
			Event:      credential.UpdateEventType,
			Credential: &cred,
			Err:        nil,
		})

		logr.FromContextOrDiscard(ctx).V(1).Info("token sent", "expires", token.Expiry)

		// Calculate when to refresh
		timeUntilExpiry := time.Until(token.Expiry)

		// If credentials are already expired, this is an error
		if timeUntilExpiry <= 0 {
			util.SendToChannel(r.ch, credential.Result{
				Credential: nil,
				Err:        errors.NewWithDetails("received already expired token", "expiresAt", token.Expiry),
			})

			return
		}

		refreshBuffer := util.CalculateRefreshBuffer(timeUntilExpiry)
		refreshTime := timeUntilExpiry - refreshBuffer

		logr.FromContextOrDiscard(ctx).V(1).Info("scheduling token refresh", "refreshIn", refreshTime, "refreshBuffer", refreshBuffer, "expiresAt", token.Expiry)

		t := time.NewTimer(refreshTime)

		select {
		case <-ctx.Done():
			logr.FromContextOrDiscard(ctx).V(1).Info("context cancelled, stopping token refresh")

			return
		case <-r.refreshCh:
			logr.FromContextOrDiscard(ctx).V(1).Info("refresh triggered")
			t.Stop()
		case <-t.C:
			// Continue to next iteration to refresh
			logr.FromContextOrDiscard(ctx).V(1).Info("refreshing token")
		}
	}
}

func (r *tokenRetriever) handleEvent(obj any, del bool) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return
	}

	if secret.GetNamespace() != r.cfg.secretRef.Namespace || secret.GetName() != r.cfg.secretRef.Name {
		return
	}

	if del {
		r.setCredentialError(errors.New("client credentials vanished"))

		return
	}

	rawSecretValue, ok := secret.Data[r.cfg.secretRef.Key]
	if !ok {
		r.setCredentialError(errors.Errorf("missing secret key: %s", r.cfg.secretRef.Key))

		return
	}

	cred := string(rawSecretValue)
	pieces := strings.Split(cred, ":")
	if len(pieces) != 2 {
		r.setCredentialError(errors.New("invalid client credentials format"))

		return
	}

	r.mu.Lock()
	r.secretError = nil

	updated := (r.clientID != "" && r.clientID != pieces[0]) || (r.clientSecret != "" && r.clientSecret != pieces[1])

	r.clientID = pieces[0]
	r.clientSecret = pieces[1]

	if updated {
		r.refreshCh <- struct{}{}
	}

	r.mu.Unlock()
}

func (r *tokenRetriever) setCredentialError(err error) {
	r.mu.Lock()
	r.secretError = err
	r.clientID = ""
	r.clientSecret = ""
	r.mu.Unlock()

	r.refreshCh <- struct{}{}
}
