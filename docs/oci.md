# OCI Credentials Provider

Exchanges ID tokens for OCI User Principal Session Tokens (UPST) using OCI's Workload Identity Federation.

Package [`pkg/oci`](https://pkg.go.dev/go.riptides.io/tokenex/pkg/oci). Snippets assume the [common setup](common-setup.md); [Channel Behavior](../README.md#channel-behavior) explains the result channel.

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
