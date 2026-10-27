# OAuth2 Client Credentials Flow Provider

Obtains access tokens through OAuth2 client credentials flow and refreshes them before expiration.

Package [`pkg/oauth2cc`](https://pkg.go.dev/go.riptides.io/tokenex/pkg/oauth2cc). Snippets assume the [common setup](common-setup.md); [Channel Behavior](../README.md#channel-behavior) explains the result channel.

```go
import (
    "go.riptides.io/tokenex/pkg/oauth2cc"
    "go.riptides.io/tokenex/pkg/credential"
    "sigs.k8s.io/controller-runtime/pkg/cache"
)

// Assume you have already initialized a Kubernetes client and cache
// This typically involves:
// 1. Getting a Kubernetes config (config.GetConfig())
// 2. Creating a controller-runtime cache (cache.New())
// 3. Starting the cache (cache.Start(ctx))
k8sCache := yourInitializedCache

// Create the OAuth2CC credentials provider
oauth2ccProvider, err := oauth2cc.NewCredentialsProvider(ctx, k8sCache)
if err != nil {
    log.Fatalf("Failed to create OAuth2CC credentials provider: %v", err)
}

// Define the secret reference containing client ID and secret
// The secret should contain a key with value in format "client_id:client_secret"
secretRef := oauth2cc.SecretRef{
    Name:      "oauth-secret",
    Namespace: "default",
    Key:       "credentials", // Key containing "client_id:client_secret"
}

// Get OAuth2 credentials
oauth2ccCredsChan, err := oauth2ccProvider.GetCredentials(
    ctx,
    "https://auth.example.com/oauth2/token",
    secretRef,
    oauth2cc.WithScope("api.read api.write"),
)
if err != nil {
    log.Fatalf("Failed to get OAuth2CC credentials: %v", err)
}

// Process credentials from the channel in a goroutine with proper context handling
wg.Add(1)
go func() {
    defer wg.Done()
    for {
        select {
        case creds, ok := <-oauth2ccCredsChan:
            if !ok {
                log.Println("OAuth2CC credentials channel closed")
                return
            }
            if creds.Err != nil {
                log.Printf("Error: %v", creds.Err)
                return
            }
            
            oauth2ccCreds := creds.Credential.(*credential.Oauth2Creds)
            log.Printf("Access Token: %s", oauth2ccCreds.AccessToken)
            // Use the token...
            
        case <-ctx.Done():
            log.Println("Context cancelled, shutting down OAuth2CC credentials handler")
            return
        }
    }
}()

// In a real application, you would wait for all goroutines to complete before exiting
// wg.Wait()
```
