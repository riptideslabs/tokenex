# GitHub App Credentials Provider

Mints GitHub App installation access tokens by signing a JWT with the App's private key and refreshes them before expiration.

Package [`pkg/githubapp`](https://pkg.go.dev/go.riptides.io/tokenex/pkg/githubapp). Snippets assume the [common setup](common-setup.md); [Channel Behavior](../README.md#channel-behavior) explains the result channel.

```go
import (
    "os"

    "github.com/google/go-github/v66/github"

    "go.riptides.io/tokenex/pkg/credential"
    "go.riptides.io/tokenex/pkg/githubapp"
)

// Source the App's private key however you like (env var shown; could be a file,
// k8s secret, Vault, etc.) and parse it once.
key, err := githubapp.ParsePrivateKey([]byte(os.Getenv("GITHUB_APP_PRIVATE_KEY")))
if err != nil {
    log.Fatalf("parse private key: %v", err)
}

provider, err := githubapp.NewCredentialsProvider(ctx, logr.Discard())
if err != nil {
    log.Fatalf("new provider: %v", err)
}

credCh, err := provider.GetCredentials(ctx,
    githubapp.WithAppID(123456),
    githubapp.WithInstallationID(7890123),
    githubapp.WithPrivateKey(key),
    // Optional: scope the token to specific repos / permissions.
    // githubapp.WithRepositories([]string{"repo-a"}),
    // githubapp.WithPermissions(&github.InstallationPermissions{Contents: github.String("read")}),
    // Optional: GitHub Enterprise Server.
    // githubapp.WithBaseURL("https://github.example.com/api/v3"),
)
if err != nil {
    log.Fatalf("get credentials: %v", err)
}

for cred := range credCh {
    if cred.Err != nil {
        log.Printf("github app token error: %v", cred.Err)
        break
    }
    tok := cred.Credential.(*credential.Token)
    log.Printf("got installation token, expires %s", tok.ExpiresAt)
}
```
