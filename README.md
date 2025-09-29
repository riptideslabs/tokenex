# Tokenex - Cloud Credentials Provider Library

This library provides a unified interface for obtaining and refreshing credentials from various cloud providers and authentication systems. It is designed to facilitate secure access to cloud resources by exchanging identity tokens for temporary credentials.

> For more background and insights about this project, see our [blog post](https://riptides.io/blog-post/introducing-tokenex-an-open-source-go-library-for-fetching-and-refreshing-cloud-credentials).

## Features

- **AWS:** Exchanges ID tokens for AWS temporary session credentials using AWS's Workload Identity Federation
- **GCP:** Exchanges ID tokens for GCP access tokens using GCP's Workload Identity Federation
- **Azure:** Exchanges ID tokens for Azure access tokens using Microsoft Entra ID's Workload Identity Federation
- **OCI:** Exchanges ID tokens for OCI User Principal Session Tokens (UPST) using OCI's Workload Identity Federation
- **Generic:** Simply returns the token provided by the identity token provider and refreshes it before expiration
- **K8sSecret:** Watches a Kubernetes secret which contains a token and publishes updates when the secret changes
- **OAuth2AC:** Obtains access tokens through OAuth2 authorization code flow and refreshes them before expiration
- **OAuth2CC:** Obtains access tokens through OAuth2 client credentials flow and refreshes them before expiration

## Installation

To use the credentials providers, ensure you have Go installed and set up your project to include the necessary dependencies.

```bash
go get go.riptides.io/tokenex
```

## Usage

Below are examples demonstrating how to use each credential provider in the library.

### Common Setup

```go
import (
    "context"
    "log"
    "os"
    "os/signal"
    "sync"
    "syscall"
    "time"
    "go.riptides.io/tokenex/pkg/token"
)

// Create a cancellable context
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// Set up graceful shutdown
signalChan := make(chan os.Signal, 1)
signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
go func() {
    sig := <-signalChan
    log.Printf("Received signal: %v, shutting down...", sig)
    cancel()
}()

// Create a wait group to track goroutines
var wg sync.WaitGroup

// Create a logger
logger := log.Default()

// Create an identity token provider
// This is used by most credential providers to exchange for service-specific tokens
idToken := "your-id-token"
idTokenProvider := token.NewStaticIdentityTokenProvider(idToken)
```

### AWS Credentials Provider

```go
import (
    "go.riptides.io/tokenex/pkg/aws"
    "go.riptides.io/tokenex/pkg/credential"
    awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

// Create the AWS credentials provider
awsProvider, err := aws.NewCredentialsProvider(ctx, logger, &awssdk.Config{Region: "us-west-2"})
if err != nil {
    log.Fatalf("Failed to create AWS credentials provider: %v", err)
}

// Get AWS credentials
awsCredsChan, err := awsProvider.GetCredentials(
    ctx,
    idTokenProvider,
    aws.WithRoleArn("arn:aws:iam::123456789012:role/example-role"),
    aws.WithRoleSessionName("example-session"),
)
if err != nil {
    log.Fatalf("Failed to get AWS credentials: %v", err)
}

// Process credentials from the channel in a goroutine with proper context handling
wg.Add(1)
go func() {
    defer wg.Done()
    for {
        select {
        case creds, ok := <-awsCredsChan:
            if !ok {
                log.Println("AWS credentials channel closed")
                return
            }
            if creds.Err != nil {
                log.Printf("Error: %v", creds.Err)
                return
            }
            
            awsCreds := creds.Credential.(*credential.AWSCreds)
            log.Printf("Access Key ID: %s", awsCreds.AccessKeyID)
            // Use the credentials...
            
        case <-ctx.Done():
            log.Println("Context cancelled, shutting down AWS credentials handler")
            return
        }
    }
}()

// In a real application, you would do other work here
// ...

// Wait for graceful shutdown when your application is terminating
// wg.Wait() // Uncomment this in your actual application
```

### GCP Credentials Provider

```go
import (
    "go.riptides.io/tokenex/pkg/gcp"
    "go.riptides.io/tokenex/pkg/credential"
)

// Create the GCP credentials provider
gcpProvider, err := gcp.NewCredentialsProvider(ctx, logger)
if err != nil {
    log.Fatalf("Failed to create GCP credentials provider: %v", err)
}

// Get GCP credentials
gcpCredsChan, err := gcpProvider.GetCredentials(
    ctx,
    idTokenProvider,
    gcp.WithAudience("//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/example-pool/providers/example-provider"),
    gcp.WithServiceAccountEmail("service-account@project-id.iam.gserviceaccount.com"),
)
if err != nil {
    log.Fatalf("Failed to get GCP credentials: %v", err)
}

// Process credentials from the channel in a goroutine with proper context handling
wg.Add(1)
go func() {
    defer wg.Done()
    for {
        select {
        case creds, ok := <-gcpCredsChan:
            if !ok {
                log.Println("GCP credentials channel closed")
                return
            }
            if creds.Err != nil {
                log.Printf("Error: %v", creds.Err)
                return
            }
            
            gcpCreds := creds.Credential.(*credential.Oauth2Creds)
            log.Printf("Access Token: %s", gcpCreds.AccessToken)
            // Use the credentials...
            
        case <-ctx.Done():
            log.Println("Context cancelled, shutting down GCP credentials handler")
            return
        }
    }
}()
```

### Azure Credentials Provider

```go
import (
    "go.riptides.io/tokenex/pkg/azure"
    "go.riptides.io/tokenex/pkg/credential"
)

// Create the Azure credentials provider
azureProvider, err := azure.NewCredentialsProvider(ctx, logger)
if err != nil {
    log.Fatalf("Failed to create Azure credentials provider: %v", err)
}

// Get Azure credentials
azureCredsChan, err := azureProvider.GetCredentials(
    ctx,
    idTokenProvider,
    azure.WithClientID("your-client-id"),
    azure.WithTenantID("your-tenant-id"),
    azure.WithScope("https://management.azure.com/.default"),
)
if err != nil {
    log.Fatalf("Failed to get Azure credentials: %v", err)
}

// Process credentials from the channel in a goroutine with proper context handling
wg.Add(1)
go func() {
    defer wg.Done()
    for {
        select {
        case creds, ok := <-azureCredsChan:
            if !ok {
                log.Println("Azure credentials channel closed")
                return
            }
            if creds.Err != nil {
                log.Printf("Error: %v", creds.Err)
                return
            }
            
            azureCreds := creds.Credential.(*credential.Oauth2Creds)
            log.Printf("Access Token: %s", azureCreds.AccessToken)
            // Use the credentials...
            
        case <-ctx.Done():
            log.Println("Context cancelled, shutting down Azure credentials handler")
            return
        }
    }
}()
```

### OCI Credentials Provider

```go
import (
    "go.riptides.io/tokenex/pkg/oci"
    "go.riptides.io/tokenex/pkg/credential"
)

// Create the OCI credentials provider
ociProvider, err := oci.NewCredentialsProvider(ctx, logger)
if err != nil {
    log.Fatalf("Failed to create OCI credentials provider: %v", err)
}

// Get OCI credentials
ociCredsChan, err := ociProvider.GetCredentials(
    ctx,
    idTokenProvider,
    oci.WithClientID("your-client-id"),
    oci.WithIdentityDomainURL("https://idcs-example.identity.oraclecloud.com"),
)
if err != nil {
    log.Fatalf("Failed to get OCI credentials: %v", err)
}

// Process credentials from the channel in a goroutine with proper context handling
wg.Add(1)
go func() {
    defer wg.Done()
    for {
        select {
        case creds, ok := <-ociCredsChan:
            if !ok {
                log.Println("OCI credentials channel closed")
                return
            }
            if creds.Err != nil {
                log.Printf("Error: %v", creds.Err)
                return
            }
            
            ociCreds := creds.Credential.(*credential.Oauth2Creds)
            log.Printf("Access Token: %s", ociCreds.AccessToken)
            // Use the credentials...
            
        case <-ctx.Done():
            log.Println("Context cancelled, shutting down OCI credentials handler")
            return
        }
    }
}()
```

### Generic Credentials Provider

```go
import (
    "go.riptides.io/tokenex/pkg/generic"
    "go.riptides.io/tokenex/pkg/credential"
)

// Create the Generic credentials provider
genericProvider, err := generic.NewCredentialsProvider(ctx, logger)
if err != nil {
    log.Fatalf("Failed to create Generic credentials provider: %v", err)
}

// Get Generic credentials (passes through the identity token)
genericCredsChan, err := genericProvider.GetCredentials(ctx, idTokenProvider)
if err != nil {
    log.Fatalf("Failed to get Generic credentials: %v", err)
}

// Process credentials from the channel in a goroutine with proper context handling
wg.Add(1)
go func() {
    defer wg.Done()
    for {
        select {
        case creds, ok := <-genericCredsChan:
            if !ok {
                log.Println("Generic credentials channel closed")
                return
            }
            if creds.Err != nil {
                log.Printf("Error: %v", creds.Err)
                return
            }
            
            genericCreds := creds.Credential.(*credential.Oauth2Creds)
            log.Printf("Token: %s", genericCreds.AccessToken)
            // Use the token...
            
        case <-ctx.Done():
            log.Println("Context cancelled, shutting down Generic credentials handler")
            return
        }
    }
}()
```

### K8sSecret Credentials Provider

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

### OAuth2 Authorization Code Flow Provider

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

### OAuth2 Client Credentials Flow Provider

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

## Channel Behavior

All credential providers in this library follow a consistent pattern for credential delivery:

1. The `GetCredentials` method returns a channel that receives credential updates
2. For the first credential and each refresh, an `Update` event is sent
3. If credentials are removed, a `Remove` event is sent
4. In case of errors, the `Err` field is populated, `Credential` is nil, and the refresh loop exits
5. When the refresh loop exits, the channel is closed

**Important**: Since these channels continuously provide credential updates (including automatic refreshes), they should be processed in a goroutine to avoid blocking the main execution flow, as shown in the examples above.

### Handling Event Types

When processing credentials, you can check the event type to determine what action to take:

```go
switch result.Event {
case credential.UpdateEventType:
    // Use the updated credentials
    log.Printf("Received new/refreshed credentials")
    // Use result.Credential for API calls
    
case credential.RemoveEventType:
    // Handle credential removal
    log.Printf("Credentials were removed")
}
```

### Graceful Shutdown

For proper application shutdown, always:

1. Cancel the context when your application is terminating
2. Wait for all credential handling goroutines to complete using a wait group
3. Handle channel closure and context cancellation in your credential processing loops

This ensures that all resources are properly cleaned up and prevents goroutine leaks.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.
