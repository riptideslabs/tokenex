# K8sSecret Credentials Provider

Watches a Kubernetes secret which contains a token and publishes updates when the secret changes.

Package [`pkg/k8ssecret`](https://pkg.go.dev/go.riptides.io/tokenex/pkg/k8ssecret). Snippets assume the [common setup](common-setup.md); [Channel Behavior](../README.md#channel-behavior) explains the result channel.

```go
import (
    "go.riptides.io/tokenex/pkg/k8ssecret"
    "go.riptides.io/tokenex/pkg/credential"
    "sigs.k8s.io/controller-runtime/pkg/cache"
)

// Assume you have already initialized a Kubernetes client and cache
// This typically involves:
// 1. Getting a Kubernetes config (config.GetConfig())
// 2. Creating a controller-runtime cache (cache.New())
// 3. Starting the cache (cache.Start(ctx))
k8sCache := yourInitializedCache

// Create the K8sSecret credentials provider
k8sProvider, err := k8ssecret.NewCredentialsProvider(ctx, k8sCache)
if err != nil {
    log.Fatalf("Failed to create K8sSecret credentials provider: %v", err)
}

// Define the secret reference
secretRef := k8ssecret.SecretRef{
    Name:      "token-secret",
    Namespace: "default",
    Key:       "token",
}

// Get credentials from the Kubernetes secret
k8sCredsChan, err := k8sProvider.GetCredentials(ctx, secretRef)
if err != nil {
    log.Fatalf("Failed to get K8sSecret credentials: %v", err)
}

// Process credentials from the channel in a goroutine with proper context handling
wg.Add(1)
go func() {
    defer wg.Done()
    for {
        select {
        case creds, ok := <-k8sCredsChan:
            if !ok {
                log.Println("K8sSecret credentials channel closed")
                return
            }
            if creds.Err != nil {
                log.Printf("Error: %v", creds.Err)
                return
            }
            
            k8sCreds := creds.Credential.(*credential.Oauth2Creds)
            log.Printf("Token: %s", k8sCreds.AccessToken)
            // Use the token...
            
        case <-ctx.Done():
            log.Println("Context cancelled, shutting down K8sSecret credentials handler")
            return
        }
    }
}()
```
