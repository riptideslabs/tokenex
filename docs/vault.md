# Vault Credentials Provider

Exchanges ID tokens for secrets from Vault using Vault's JWT authentication.

Package [`pkg/vault`](https://pkg.go.dev/go.riptides.io/tokenex/pkg/vault). Snippets assume the [common setup](common-setup.md); [Channel Behavior](../README.md#channel-behavior) explains the result channel.

```go
import (
    "go.riptides.io/tokenex/pkg/credential"
    "go.riptides.io/tokenex/pkg/token"
    "go.riptides.io/tokenex/pkg/vault"
)


// Create a logger
logger := logr.New(logr.Discard())

// Create the Vault credentials provider
vaultProvider, err := vault.NewCredentialsProvider(ctx, logger, "http://localhost:8200", nil)
if err != nil {
	return err
}

// Get credentials from Vault
dbCredsChan, err := vaultProvider.GetCredentials(
		ctx,
		idTokenProvider,
		vault.WithJWTAuthMethodPath("jwt"),
		vault.WithJWTAuthRoleName("dbuser"),
		vault.WithSecretFullPath("database/creds/pg-dyn-dbuser"),
	)
	if err != nil {
		return err
	}

// Process dynamic credentials from the channel in a goroutine with proper context handling
wg.Add(1)
go func() {
    defer wg.Done()
    for {
        select {
        case creds, ok := <-dbCredsChan:
            if !ok {
                logger.Info("Database credentials channel closed")
                return
            }
            if creds.Err != nil {
                logger.Error(creds.Err, "Error receiving database credentials", errors.GetDetails(creds.Err))
                return
            }

            dbSecret := creds.Credential.(*credential.VaultSecret)

            // Database secrets typically contain username and password
            if username, ok := dbSecret.Data["username"].(string); ok {
                logger.Info("Database username", "value", username)
            }
            if password, ok := dbSecret.Data["password"].(string); ok {
                logger.Info("Database password", "value", password)
            }

        case <-ctx.Done():
            log.Println("Context cancelled, shutting down database credentials handler")
            return
        }
    }
}()

// In a real application, you would wait for all goroutines to complete before exiting
// wg.Wait()
```
