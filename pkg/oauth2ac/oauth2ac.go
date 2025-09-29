// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package oauth2ac

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"emperror.dev/errors"
	"github.com/go-logr/logr"
	"github.com/werbenhu/eventbus"
	"golang.org/x/oauth2"
	corev1 "k8s.io/api/core/v1"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/util"
)

var (
	ErrInformerSync         = errors.NewPlain("could not sync informer cache")
	ErrAlreadyRunning       = errors.NewPlain("already running")
	ErrAlreadyAuthorized    = errors.NewPlain("already authorized")
	ErrUnknownAuthState     = errors.NewPlain("unknown auth state")
	ErrAuthorizationNeeded  = errors.NewPlain("authorization needed")
	ErrRefreshTokenRequired = errors.NewPlain("refresh token is required")
	ErrInvalidToken         = errors.NewPlain("token is not valid")
)

type (
	Credential = credential.Result
)

// Token wraps the OAuth2 token to provide marshaling and unmarshaling capabilities.
type Token struct {
	*oauth2.Token
}

// Marshal serializes the token to JSON.
func (s *Token) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

// Unmarshal deserializes the token from JSON.
func (s *Token) Unmarshal(content []byte) error {
	return json.Unmarshal(content, s)
}

// CredentialsProvider defines the interface for obtaining credentials through OAuth2 authorization code flow.
type CredentialsProvider interface {
	// ID returns a unique identifier for this credentials provider.
	ID() string

	// Start begins the OAuth2 authorization process and returns a channel for status events.
	// The status events indicate the current state of the authorization process.
	Start(ctx context.Context) (<-chan StatusEvent, error)

	// GetCredentials returns a channel that receives OAuth2 access tokens.
	// The channel provides updates when tokens are refreshed or removed.
	// For the first token and each refresh, an Update event is sent.
	// In case of errors, the Err field is populated, Credential is nil, and the refresh loop exits.
	// When the refresh loop exits, the channel is closed.
	GetCredentials(ctx context.Context) (<-chan Credential, error)

	// AuthCodeURL returns the URL to redirect the user to for authorization and the state parameter.
	// The state parameter should be verified when the user is redirected back to prevent CSRF attacks.
	AuthCodeURL(ctx context.Context) (string, string)

	// Authorize completes the OAuth2 authorization code flow with the provided state and code.
	// The state parameter should match the one returned by AuthCodeURL.
	// The code is the authorization code received from the OAuth2 provider.
	Authorize(ctx context.Context, state, code string) (*oauth2.Token, error)
}

var _ CredentialsProvider = &credentialsProvider{}

// SecretRef contains the reference to a Kubernetes secret that stores OAuth2 tokens.
// It specifies the name, namespace, and key of the secret.
type SecretRef struct {
	// Name is the name of the Kubernetes secret.
	Name string
	// Namespace is the namespace of the Kubernetes secret.
	Namespace string
	// Key is the key in the secret data that contains the OAuth2 token.
	Key string
}

func (r SecretRef) IsValid() bool {
	return r.Name != "" && r.Namespace != "" && r.Key != ""
}

// CredentialsConfig contains the configuration for the OAuth2 authorization code flow.
// It specifies the endpoints, scopes, and other parameters needed for the OAuth2 flow.
type CredentialsConfig struct {
	// AuthorizationEndpointURL is the URL of the OAuth2 authorization endpoint.
	// This is where the user is redirected to authenticate and authorize the application.
	AuthorizationEndpointURL string

	// TokenEndpointURL is the URL of the OAuth2 token endpoint.
	// This is where the application exchanges the authorization code for an access token.
	TokenEndpointURL string

	// SecretRef contains the reference to a Kubernetes secret that stores OAuth2 client credentials.
	// The secret should contain the client ID and client secret.
	SecretRef SecretRef

	// Scopes is a list of OAuth2 scopes to request.
	// Scopes define the access privileges requested from the authorization server.
	Scopes []string

	// UsePKCE indicates whether to use Proof Key for Code Exchange (PKCE).
	// PKCE provides additional security for public clients by preventing authorization code interception attacks.
	UsePKCE bool

	// AdditionalParams contains additional parameters to include in the OAuth2 requests.
	// These parameters are included in both the authorization request and token request.
	AdditionalParams map[string][]string

	// RedirectURL is the URL where the authorization server redirects the user after authentication.
	// This URL must match one of the redirect URLs registered with the OAuth2 provider.
	RedirectURL string
}

type authState struct {
	state    string
	verifier string
	cfg      oauth2.Config

	issuedAt time.Time
}

type credentialsProvider struct {
	id         string
	cache      cache.Cache
	tokenStore TokenStorage
	cfg        *CredentialsConfig
	logger     logr.Logger

	running   *atomic.Bool
	statusCh  chan StatusEvent
	refreshCh chan struct{}

	mu           sync.RWMutex
	clientID     string
	clientSecret string
	secretError  error

	statesMu   sync.RWMutex
	authStates map[string]authState

	syncGate *util.SyncGate

	pipeMu sync.Mutex
	pipe   *eventbus.Pipe[Credential]
}

// TokenStorage defines the interface for storing and retrieving OAuth2 tokens.
// It provides methods to get, store, and delete tokens by ID.
type TokenStorage interface {
	// Get retrieves an OAuth2 token by ID.
	// Returns the token or an error if the token cannot be retrieved.
	Get(ctx context.Context, id string) (*oauth2.Token, error)

	// Store saves an OAuth2 token with the given ID.
	// Returns an error if the token cannot be stored.
	Store(ctx context.Context, id string, token *oauth2.Token) error

	// Delete removes an OAuth2 token with the given ID.
	// Returns an error if the token cannot be deleted.
	Delete(ctx context.Context, id string) error
}

// NewCredentialsProvider creates a new instance of CredentialsProvider for OAuth2 authorization code flow.
//
// Parameters:
//   - id: A unique identifier for this credentials provider
//   - cache: Kubernetes controller-runtime cache for watching secrets
//   - tokenStore: Storage for OAuth2 tokens
//   - cfg: Configuration for the OAuth2 provider
//   - logger: Logger for logging credential operations
//
// Returns a credential provider and an error if creation fails
func NewCredentialsProvider(id string, cache cache.Cache, tokenStore TokenStorage, cfg *CredentialsConfig, logger logr.Logger) (*credentialsProvider, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return &credentialsProvider{
		id:         id,
		cache:      cache,
		tokenStore: tokenStore,
		cfg:        cfg,
		logger:     logger.WithName("oauth2ac"),

		statusCh:  make(chan StatusEvent, 1),
		refreshCh: make(chan struct{}, 1),

		running:    &atomic.Bool{},
		authStates: map[string]authState{},
		syncGate:   util.NewSyncGate(),
		pipe:       eventbus.NewPipe[Credential](),
	}, nil
}

func (cp *credentialsProvider) ID() string {
	return cp.id
}

type StatusEventType string

const (
	AuthorizedStatusEvent   StatusEventType = "AUTHORIZED"
	UnauthorizesStatusEvent StatusEventType = "UNAUTHORIZED"
)

type StatusEvent struct {
	Event StatusEventType
	Err   error
}

func (cp *credentialsProvider) Start(ctx context.Context) (<-chan StatusEvent, error) {
	if cp.running.Load() {
		return nil, errors.WithStack(ErrAlreadyRunning)
	}

	if err := cp.authorizeIfTokenExists(ctx); err != nil {
		return nil, err
	}

	handlerStopFunc, err := cp.startInformer(ctx)
	if err != nil {
		return nil, err
	}

	cp.running.Store(true)

	// periodic cleanup of expired states
	go util.RunFuncAtInterval(ctx, time.Second*5, func(_ context.Context) error {
		cp.cleanupExpiredStates()

		return nil
	})

	go func() {
		cp.tokenRefresherLoop(ctx)
		cp.logger.V(1).Info("context cancelled, stopping provider")

		// reset pipe
		cp.pipeMu.Lock()
		cp.pipe.Close()
		cp.pipe = eventbus.NewPipe[Credential]()
		cp.pipeMu.Unlock()

		handlerStopFunc()

		cp.running.Store(false)
	}()

	return cp.statusCh, nil
}

func (cp *credentialsProvider) Authorize(ctx context.Context, authState, code string) (*oauth2.Token, error) {
	if cp.syncGate.IsOpen() {
		return nil, errors.WithStack(ErrAlreadyAuthorized)
	}

	token, err := cp.exchangeToken(ctx, authState, code)
	if err != nil {
		return nil, err
	}

	if !token.Valid() {
		return nil, errors.WithStack(ErrInvalidToken)
	}

	if token.RefreshToken == "" {
		return nil, errors.WithStack(ErrRefreshTokenRequired)
	}

	if err := cp.storeTokenAndAuthorize(ctx, token); err != nil {
		return nil, err
	}

	return token, nil
}

// AuthCodeURL generates a new OAuth2 authorization state and URL.
func (cp *credentialsProvider) AuthCodeURL(ctx context.Context) (string, string) {
	conf := cp.oauth2Config()

	authState := authState{
		state:    randomURLSafeString(32),
		issuedAt: time.Now(),
		cfg:      conf,
	}

	opts := []oauth2.AuthCodeOption{}

	for k, vs := range cp.cfg.AdditionalParams {
		for _, v := range vs {
			opts = append(opts, oauth2.SetAuthURLParam(k, v))
		}
	}

	if cp.cfg.UsePKCE {
		authState.verifier = randomURLSafeString(64)
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			oauth2.SetAuthURLParam("code_challenge", pkceS256(authState.verifier)),
		)
	}

	cp.storeAuthState(authState)

	return authState.state, conf.AuthCodeURL(authState.state, opts...)
}

func (cp *credentialsProvider) GetCredentialsWithOptions(ctx context.Context, _ ...option.Option) (<-chan Credential, error) {
	return cp.GetCredentials(ctx)
}

func (cp *credentialsProvider) GetCredentials(
	ctx context.Context,
) (<-chan Credential, error) {
	credsChan := make(chan Credential, 1)

	fn := func(credential Credential) {
		util.SendToChannel(credsChan, credential)
	}

	cp.pipeMu.Lock()
	defer cp.pipeMu.Unlock()
	if err := cp.pipe.Subscribe(fn); err != nil {
		return nil, err
	}

	// send existing access token to subscriber
	token, err := cp.tokenStore.Get(ctx, cp.id)
	if err == nil {
		event := cp.createUpdateEventFromToken(token)
		fn(event)
	}

	go func() {
		<-ctx.Done()
		cp.pipeMu.Lock()
		_ = cp.pipe.Unsubscribe(fn)
		cp.pipeMu.Unlock()
	}()

	return credsChan, nil
}

func (cp *credentialsProvider) sendStatusEvent(event StatusEvent) {
	select {
	case cp.statusCh <- event:
	default:
		<-cp.statusCh
		cp.statusCh <- event
	}
}

func (cp *credentialsProvider) exchangeToken(ctx context.Context, authState string, code string) (*oauth2.Token, error) {
	opts := []oauth2.AuthCodeOption{}

	cp.logger.V(2).Info("exchange", "state", authState)

	cp.statesMu.RLock()
	st, ok := cp.authStates[authState]
	cp.statesMu.RUnlock()
	if !ok {
		return nil, errors.WithStack(ErrUnknownAuthState)
	}

	if cp.cfg.UsePKCE {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", st.verifier))
	}

	cp.statesMu.Lock()
	delete(cp.authStates, authState)
	cp.statesMu.Unlock()

	for k, vs := range cp.cfg.AdditionalParams {
		for _, v := range vs {
			opts = append(opts, oauth2.SetAuthURLParam(k, v))
		}
	}

	return st.cfg.Exchange(ctx, code, opts...)
}

func (cp *credentialsProvider) storeTokenAndAuthorize(ctx context.Context, token *oauth2.Token) error {
	if err := cp.tokenStore.Store(ctx, cp.id, token); err != nil {
		return err
	}

	cp.setAuthorizedStatus()

	return nil
}

func (cp *credentialsProvider) authorizeIfTokenExists(ctx context.Context) error {
	token, err := cp.tokenStore.Get(ctx, cp.id)
	if err == nil && token.RefreshToken != "" {
		cp.logger.Info("token exists")

		cp.setAuthorizedStatus()
	} else {
		cp.setUnauthorizedStatus(errors.WithStack(ErrAuthorizationNeeded))
	}

	return nil
}

// validateConfig validates the configuration and returns an error if any required field is missing.
func validateConfig(cfg *CredentialsConfig) error {
	if cfg.AuthorizationEndpointURL == "" {
		return errors.NewPlain("AuthorizationEndpointURL is required")
	}

	if cfg.TokenEndpointURL == "" {
		return errors.NewPlain("TokenEndpointURL is required")
	}

	if cfg.SecretRef == (SecretRef{}) {
		return errors.NewPlain("SecretRef is required")
	}

	if !cfg.SecretRef.IsValid() {
		return errors.NewPlain("SecretRef is invalid")
	}

	if cfg.RedirectURL == "" {
		return errors.NewPlain("RedirectURL is required")
	}

	return nil
}

func (cp *credentialsProvider) startInformer(ctx context.Context) (func(), error) {
	informer, err := cp.cache.GetInformer(ctx, &corev1.Secret{}, cache.BlockUntilSynced(true))
	if err != nil {
		return nil, errors.WrapIf(err, "could not get informer")
	}

	handler, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			cp.handleEvent(ctx, obj, false)
		},
		UpdateFunc: func(oldObj, newObj any) {
			cp.handleEvent(ctx, newObj, false)
		},
		DeleteFunc: func(obj any) {
			cp.handleEvent(ctx, obj, true)
		},
	})
	if err != nil {
		return nil, errors.WrapIf(err, "could not register event handler")
	}

	if !toolscache.WaitForNamedCacheSyncWithContext(logr.NewContext(ctx, cp.logger.V(3)), handler.HasSynced) {
		return nil, errors.WithStack(ErrInformerSync)
	}

	return func() {
		if err := informer.RemoveEventHandler(handler); err != nil {
			cp.logger.Error(err, "could not remove event handler")
		}

		cp.logger.V(1).Info("handler stopped")
	}, nil
}

func (cp *credentialsProvider) getToken(ctx context.Context, forceRefresh bool) (*oauth2.Token, error) {
	accessToken, err := cp.tokenStore.Get(ctx, cp.id)
	if err != nil {
		return nil, err
	}

	if !forceRefresh && accessToken.Valid() {
		cp.logger.V(1).Info("token is served from storage")

		return accessToken, nil
	}

	// force refresh token
	cp.logger.V(1).Info("refresh token")

	t := *accessToken
	t.Expiry = time.Now().Add(-time.Hour)

	cfg := cp.oauth2Config()
	accessToken, err = cfg.TokenSource(ctx, &t).Token()
	if err != nil {
		return nil, err
	}

	if err := cp.tokenStore.Store(ctx, cp.id, accessToken); err != nil {
		return nil, err
	}

	return accessToken, nil
}

func (cp *credentialsProvider) tokenRefresherLoop(ctx context.Context) {
	var refreshTime time.Duration
	for {
		cp.logger.V(3).Info("wait for authorization")
		if err := cp.syncGate.Wait(ctx); err != nil {
			return
		}

		accessToken, err := cp.getToken(ctx, refreshTime > 0)
		if err != nil {
			cp.logger.Error(err, "could not get token from storage")

			err = errors.WrapIf(err, "could not get token from storage")
			cp.setUnauthorizedStatus(err)

			cp.publishCredential(Credential{
				Event: credential.RemoveEventType,
				Err:   err,
			})

			continue
		}

		cp.logger.Info("access token obtained")

		timeUntilExpiry := time.Until(accessToken.Expiry)
		refreshBuffer := util.CalculateRefreshBuffer(timeUntilExpiry)
		refreshTime = timeUntilExpiry - refreshBuffer

		cp.logger.Info("scheduling credential refresh", "refreshIn", refreshTime, "refreshBuffer", refreshBuffer, "expiresAt", accessToken.Expiry)

		cp.publishAccessToken(accessToken)

		select {
		case <-cp.refreshCh:
			cp.logger.Info("client credentials changed: reset init condition and wait for re-authorization")

			cp.mu.RLock()
			serr := cp.secretError
			cp.mu.RUnlock()

			err := errors.WithStack(ErrAuthorizationNeeded)
			if serr != nil {
				err = errors.Wrap(err, serr.Error())
			}
			cp.publishCredential(Credential{
				Event: credential.RemoveEventType,
				Err:   err,
			})

			cp.setUnauthorizedStatus(err)

			continue
		case <-ctx.Done():
			return
		case <-time.After(refreshTime):
			cp.logger.V(2).Info("refreshing credentials")
		}
	}
}

func (cp *credentialsProvider) publishCredential(cred Credential) {
	cp.pipeMu.Lock()
	if err := cp.pipe.Publish(cred); err != nil {
		cp.logger.Error(err, "could not publish credential")
	}
	cp.pipeMu.Unlock()
}

func (cp *credentialsProvider) createUpdateEventFromToken(token *oauth2.Token) Credential {
	cred := credential.Oauth2Creds(*token)

	return Credential{
		Credential: &cred,
		Err:        nil,
		Event:      credential.UpdateEventType,
	}
}

func (cp *credentialsProvider) publishAccessToken(token *oauth2.Token) {
	if token == nil {
		return
	}

	event := cp.createUpdateEventFromToken(token)
	cp.publishCredential(event)
}

func (cp *credentialsProvider) oauth2Config() oauth2.Config {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	ep := oauth2.Endpoint{
		AuthURL:  cp.cfg.AuthorizationEndpointURL,
		TokenURL: cp.cfg.TokenEndpointURL,
	}

	if cp.clientSecret == "" {
		ep.AuthStyle = oauth2.AuthStyleInParams
	}

	return oauth2.Config{
		ClientID:     cp.clientID,
		ClientSecret: cp.clientSecret,
		RedirectURL:  cp.cfg.RedirectURL,
		Scopes:       cp.cfg.Scopes,
		Endpoint:     ep,
	}
}

func (cp *credentialsProvider) handleEvent(ctx context.Context, obj any, del bool) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return
	}

	if secret.GetNamespace() != cp.cfg.SecretRef.Namespace || secret.GetName() != cp.cfg.SecretRef.Name {
		return
	}

	if del {
		cp.setCredentialError(errors.New("client credentials vanished"))

		if err := cp.tokenStore.Delete(ctx, cp.id); err != nil {
			cp.logger.Error(err, "could not delete token from storage")
		}

		return
	}

	rawSecretValue, ok := secret.Data[cp.cfg.SecretRef.Key]
	if !ok {
		cp.setCredentialError(errors.Errorf("missing secret key: %s", cp.cfg.SecretRef.Key))

		return
	}

	clientID, clientSecret, err := cp.parseClientCreds(string(rawSecretValue))
	if err != nil {
		cp.setCredentialError(err)

		return
	}

	cp.mu.Lock()
	cp.secretError = nil

	updated := (cp.clientID != "" && cp.clientID != clientID) || (cp.clientSecret != "" && cp.clientSecret != clientSecret)

	cp.clientID = clientID
	cp.clientSecret = clientSecret
	cp.mu.Unlock()

	if updated && cp.syncGate.IsOpen() {
		cp.signalRefresh()
	}
}

func (cp *credentialsProvider) setAuthorizedStatus() {
	cp.syncGate.Open()

	cp.sendStatusEvent(StatusEvent{
		Event: AuthorizedStatusEvent,
	})
}

func (cp *credentialsProvider) setUnauthorizedStatus(err error) {
	cp.syncGate.Close()

	cp.sendStatusEvent(StatusEvent{
		Event: UnauthorizesStatusEvent,
		Err:   err,
	})
}

func (cp *credentialsProvider) parseClientCreds(s string) (string, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", errors.New("empty client credentials")
	}

	parts := strings.SplitN(s, ":", 2)
	id := strings.TrimSpace(parts[0])
	if id == "" {
		return "", "", errors.New("empty client_id")
	}

	var secret string
	if len(parts) == 2 {
		secret = strings.TrimSpace(parts[1]) // may be empty, that's OK
	}

	return id, secret, nil
}

func (cp *credentialsProvider) setCredentialError(err error) {
	cp.mu.Lock()
	cp.secretError = err
	cp.clientID = ""
	cp.clientSecret = ""
	cp.mu.Unlock()

	cp.signalRefresh()
}

func (cp *credentialsProvider) signalRefresh() {
	select {
	case cp.refreshCh <- struct{}{}:
	default:
	}
}

func (cp *credentialsProvider) storeAuthState(authState authState) {
	cp.statesMu.Lock()
	defer cp.statesMu.Unlock()

	cp.authStates[authState.state] = authState
}

func (cp *credentialsProvider) cleanupExpiredStates() {
	candidates := []string{}

	cp.statesMu.RLock()
	for k, authState := range cp.authStates {
		if authState.issuedAt.Before(time.Now().Add(-time.Second * 60)) {
			candidates = append(candidates, k)
		}
	}
	cp.statesMu.RUnlock()

	if len(candidates) == 0 {
		return
	}

	cp.statesMu.Lock()
	defer cp.statesMu.Unlock()
	for _, authState := range candidates {
		cp.logger.V(2).Info("remove state", "id", authState)
		delete(cp.authStates, authState)
	}
}

func randomURLSafeString(n int) string {
	b := make([]byte, n)
	// error is handled within Read
	_, _ = rand.Read(b)

	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}
