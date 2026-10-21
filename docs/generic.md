# Generic Credentials Provider

Simply returns the token provided by the identity token provider and refreshes it before expiration.

Package [`pkg/generic`](https://pkg.go.dev/go.riptides.io/tokenex/pkg/generic). Snippets assume the [common setup](common-setup.md); [Channel Behavior](../README.md#channel-behavior) explains the result channel.

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
