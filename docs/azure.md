# Azure Credentials Provider

Exchanges ID tokens for Azure access tokens using Microsoft Entra ID's Workload Identity Federation.

Package [`pkg/azure`](https://pkg.go.dev/go.riptides.io/tokenex/pkg/azure). Snippets assume the [common setup](common-setup.md); [Channel Behavior](../README.md#channel-behavior) explains the result channel.

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
