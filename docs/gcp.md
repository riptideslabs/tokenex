# GCP Credentials Provider

Exchanges ID tokens for GCP access tokens using GCP's Workload Identity Federation.

Package [`pkg/gcp`](https://pkg.go.dev/go.riptides.io/tokenex/pkg/gcp). Snippets assume the [common setup](common-setup.md); [Channel Behavior](../README.md#channel-behavior) explains the result channel.

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
