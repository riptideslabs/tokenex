# OAuth2 Authorization Code Flow Provider

Obtains access tokens through OAuth2 authorization code flow and refreshes them before expiration.

Package [`pkg/oauth2ac`](https://pkg.go.dev/go.riptides.io/tokenex/pkg/oauth2ac). Snippets assume the [common setup](common-setup.md); [Channel Behavior](../README.md#channel-behavior) explains the result channel.

```go
import (
    "errors"
    "go.riptides.io/tokenex/pkg/oauth2ac"
    "go.riptides.io/tokenex/pkg/credential"
    "github.com/go-logr/logr"
    "golang.org/x/oauth2"
    "sigs.k8s.io/controller-runtime/pkg/cache"
)

// Assume you have already initialized a Kubernetes client and cache
// This typically involves:
// 1. Getting a Kubernetes config (config.GetConfig())
// 2. Creating a controller-runtime cache (cache.New())
// 3. Starting the cache (cache.Start(ctx))
k8sCache := yourInitializedCache

// Create a logger
logger := logr.New(logr.Discard())

// Create a token storage implementation
// This is a simple in-memory implementation for example purposes
type inMemoryTokenStorage struct {
    tokens map[string]*oauth2.Token
}

func newInMemoryTokenStorage() *inMemoryTokenStorage {
    return &inMemoryTokenStorage{
        tokens: make(map[string]*oauth2.Token),
    }
}

func (s *inMemoryTokenStorage) Get(ctx context.Context, id string) (*oauth2.Token, error) {
    token, ok := s.tokens[id]
    if !ok {
        return nil, errors.New("token not found")
    }
    return token, nil
}

func (s *inMemoryTokenStorage) Store(ctx context.Context, id string, token *oauth2.Token) error {
    s.tokens[id] = token
    return nil
}

func (s *inMemoryTokenStorage) Delete(ctx context.Context, id string) error {
    delete(s.tokens, id)
    return nil
}

tokenStorage := newInMemoryTokenStorage()

// Define the OAuth2 configuration
config := &oauth2ac.CredentialsConfig{
    AuthorizationEndpointURL: "https://auth.example.com/oauth2/authorize",
    TokenEndpointURL:         "https://auth.example.com/oauth2/token",
    RedirectURL:              "https://localhost:8080/callback",
    Scopes:                   []string{"openid", "profile"},
    UsePKCE:                  true, // Use PKCE for added security
    SecretRef: oauth2ac.SecretRef{
        Name:      "oauth-secret",
        Namespace: "default",
        Key:       "credentials", // Contains <client_id:client_secret>
    },
}

// Create the OAuth2AC credentials provider
oauth2Provider, err := oauth2ac.NewCredentialsProvider(
    "my-oauth-provider", // Unique ID for this provider
    k8sCache,
    tokenStorage,
    config,
    logger,
)
if err != nil {
    log.Fatalf("Failed to create OAuth2AC credentials provider: %v", err)
}

// Start the authorization flow
statusChan, err := oauth2Provider.Start(ctx)
if err != nil {
    log.Fatalf("Failed to start OAuth2 flow: %v", err)
}

// Monitor the authorization status
go func() {
    for status := range statusChan {
        log.Printf("Auth Status: %v", status.Event)
        
        switch status.Event {
        case oauth2ac.UnauthorizesStatusEvent:
            // User needs to authorize
            log.Printf("Authorization required")
            
            // Generate authorization URL for the user to visit
            state, authURL := oauth2Provider.AuthCodeURL(ctx)
            log.Printf("Please visit: %s", authURL)
            log.Printf("State: %s (save this to verify the callback)", state)
            
        case oauth2ac.AuthorizedStatusEvent:
            log.Printf("Successfully authorized")
            // At this stage, the initial token is available in token storage
            // and will be automatically refreshed before expiration
            
        default:
            // Handle unexpected event type
            if status.Err != nil {
                log.Printf("Auth Error: %v", status.Err)
                // You might want to retry or exit depending on the error
            }
        }
    }
}()

// In a real application, you would have a callback endpoint (HTTP handler) that receives
// the authorization code and state when the user is redirected back from the authorization server.
// For example, if your redirect URL is "https://localhost:8080/callback", you would have
// an HTTP handler for that path that extracts the code and state from the request:
//
// HTTP handler example (not part of this sample):
func callbackHandler(w http.ResponseWriter, r *http.Request) {
    // Extract code and state from the request
    code := r.URL.Query().Get("code")
    state := r.URL.Query().Get("state")
    
    // Verify the state matches what you generated (to prevent CSRF attacks)
    // Then complete the authorization flow as shown below
    token, err := oauth2Provider.Authorize(ctx, state, code)
    if err != nil {
        http.Error(w, "Authorization failed: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // After successful authorization, the credentials channel will receive the token
    // and refresh it automatically before it expires

    log.Printf("Successfully authorized! Token expires at: %v", token.Expiry)
    
    // Inform the user that authorization was successful
    w.Write([]byte("Successfully authorized! You can close this window."))
}


// Process credentials from the channel in a goroutine with proper context handling
oauth2CredsChan, err :=  oauth2Provider.GetCredentials(ctx)
if err != nil {
    log.Fatalf("Failed to get OAuth2AC credentials: %v", err)
}

wg.Add(1)
go func() {
    defer wg.Done()
    for {
        select {
        case creds, ok := <-oauth2CredsChan:
            if !ok {
                log.Println("OAuth2AC credentials channel closed")
                return
            }
            if creds.Err != nil {
                log.Printf("Error: %v", creds.Err)
                return
            }
            
            oauth2Creds := creds.Credential.(*credential.Oauth2Creds)
            log.Printf("Access Token: %s", oauth2Creds.AccessToken)
            // Use the token...
            
        case <-ctx.Done():
            log.Println("Context cancelled, shutting down OAuth2AC credentials handler")
            return
        }
    }
}()
```
