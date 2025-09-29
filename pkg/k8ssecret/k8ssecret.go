// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package k8ssecret

import (
	"context"

	"emperror.dev/errors"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

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

// SecretRef contains the reference to a Kubernetes secret.
// It specifies the name, namespace, and key of the secret to watch.
type SecretRef struct {
	// Name is the name of the Kubernetes secret.
	Name string
	// Namespace is the namespace of the Kubernetes secret.
	Namespace string
	// Key is the key in the secret data that contains the token.
	Key string
}

// CredentialsProvider defines the interface for obtaining credentials from Kubernetes secrets.
// It watches a Kubernetes secret and publishes the token to a channel when the secret or its content changes.
type CredentialsProvider interface {
	// GetCredentials returns a channel that receives tokens from the specified Kubernetes secret.
	// The channel provides updates when the secret or its content changes.
	// For the first token and each update, an Update event is sent.
	// If the secret is deleted, a Remove event is sent.
	// In case of errors, the Err field is populated, Credential is nil, and the watch loop exits.
	// When the watch loop exits, the channel is closed.
	// The secretRef specifies the Kubernetes secret to watch.
	GetCredentials(ctx context.Context, secretRef SecretRef) (<-chan Credential, error)
}

var _ CredentialsProvider = &credentialsProvider{}

type credentialsConfig struct {
	secretRef SecretRef
}

type credentialsProvider struct {
	cache cache.Cache
}

// NewCredentialsProvider creates a new instance of CredentialsProvider for Kubernetes secrets.
// The returned provider watches a Kubernetes secret and publishes the token to a channel when the secret or its content changes.
//
// Parameters:
//   - ctx: The context for the operation
//   - cache: Kubernetes controller-runtime cache for watching secrets
//
// Returns:
//   - A credential provider that watches Kubernetes secrets
//   - An error if the provider cannot be created
func NewCredentialsProvider(ctx context.Context, cache cache.Cache) (*credentialsProvider, error) {
	return &credentialsProvider{
		cache: cache,
	}, nil
}

// validateConfig validates the configuration and returns an error if any required field is missing.
func validateConfig(cfg *credentialsConfig) error {
	if cfg.secretRef == (SecretRef{}) {
		return errors.New("secretRef is required")
	}

	return nil
}

type Provider interface {
	isK8sSecret()
}

func (cp *credentialsProvider) isK8sSecret() {}

// GetCredentialsWithOptions returns credentials from Kubernetes secrets using the provided options.
// It applies any credential-specific options, validates the config, and delegates to GetCredentials.
// This method implements the credential.Provider interface and is the primary entry point for obtaining credentials from Kubernetes secrets.
// The returned channel will receive token updates when the secret or its content changes.
//
// Options can include:
//   - Secret reference (name, namespace, key)
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

	return cp.GetCredentials(ctx, cfg.secretRef)
}

func (cp *credentialsProvider) GetCredentials(
	ctx context.Context,
	secretRef SecretRef,
) (<-chan Credential, error) {
	informer, err := cp.cache.GetInformer(ctx, &corev1.Secret{}, cache.BlockUntilSynced(true))
	if err != nil {
		return nil, errors.WrapIf(err, "could not get informer")
	}

	credsChan := make(chan Credential, 1)

	handler, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			cp.handleEvent(credsChan, secretRef, obj, false)
		},
		UpdateFunc: func(oldObj, newObj any) {
			cp.handleEvent(credsChan, secretRef, newObj, false)
		},
		DeleteFunc: func(obj any) {
			cp.handleEvent(credsChan, secretRef, obj, true)
		},
	})
	if err != nil {
		return nil, errors.WrapIf(err, "could not register event handler")
	}

	if !toolscache.WaitForNamedCacheSyncWithContext(logr.NewContext(ctx, logr.FromContextOrDiscard(ctx).V(3)), handler.HasSynced) {
		return credsChan, errors.WithStack(ErrInformerSync)
	}

	// do initial check of the specified secret
	if err := cp.initialValidation(ctx, secretRef); err != nil {
		util.SendToChannel(credsChan, Credential{
			Err:   err,
			Event: credential.UpdateEventType,
		})
	}

	go func() {
		<-ctx.Done()

		close(credsChan)

		if err := informer.RemoveEventHandler(handler); err != nil {
			logr.FromContextOrDiscard(ctx).Error(err, "could not remove event handler")
		}
	}()

	return credsChan, nil
}

func (cp *credentialsProvider) initialValidation(ctx context.Context, secretRef SecretRef) error {
	secret := &corev1.Secret{}
	if err := cp.cache.Get(ctx, client.ObjectKey{
		Name:      secretRef.Name,
		Namespace: secretRef.Namespace,
	}, secret); err != nil {
		return err
	}

	if _, ok := secret.Data["token"]; !ok {
		return ErrMissingData
	}

	return nil
}

func (cp *credentialsProvider) handleEvent(credsChan chan Credential, secretRef SecretRef, obj any, del bool) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return
	}

	if secret.GetNamespace() != secretRef.Namespace || secret.GetName() != secretRef.Name {
		return
	}

	if del {
		util.SendToChannel(credsChan, Credential{
			Event: credential.RemoveEventType,
		})

		return
	}

	value, ok := secret.Data[secretRef.Key]
	if !ok {
		util.SendToChannel(credsChan, Credential{
			Err:   ErrMissingData,
			Event: credential.UpdateEventType,
		})

		return
	}

	util.SendToChannel(credsChan, Credential{
		Credential: &credential.Token{
			Token: string(value),
		},
		Event: credential.UpdateEventType,
	})
}
