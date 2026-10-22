# GitHub Actions Identity Token Provider

Fetches OIDC ID tokens from the GitHub Actions runtime, so a workflow can pass them to any provider that takes an `IdentityTokenProvider` (AWS, GCP, Azure, OCI, Vault, Conjur, Generic, RFC 7523 and RFC 8693). The job needs the `id-token: write` permission:

Package [`pkg/token/githubactions`](https://pkg.go.dev/go.riptides.io/tokenex/pkg/token/githubactions). Snippets assume the [common setup](common-setup.md); [Channel Behavior](../README.md#channel-behavior) explains the result channel.

```yaml
permissions:
  id-token: write
```

The example exchanges the token for an Anthropic access token via Workload Identity Federation:

```go
import (
    "go.riptides.io/tokenex/pkg/credential"
    "go.riptides.io/tokenex/pkg/rfc7523"
    "go.riptides.io/tokenex/pkg/token/githubactions"
)

// Reads ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN from the environment.
// Use WithRequestURL / WithRequestToken where the runner's environment isn't inherited, e.g. in a container.
idTokenProvider, err := githubactions.NewIdentityTokenProvider(
    // Must match the audience the federation rule expects.
    githubactions.WithAudience("api.anthropic.com"),
)
if err != nil {
    log.Fatalf("new provider: %v", err)
}

credCh, err := rfc7523.GetAnthropicCredentials(ctx, logr.Discard(), idTokenProvider, rfc7523.AnthropicWIFConfig{
    FederationRuleID: "fdrl_...",
    OrganizationID:   "...",
    ServiceAccountID: "...",
    WorkspaceID:      "...",
})
if err != nil {
    log.Fatalf("get credentials: %v", err)
}

for cred := range credCh {
    if cred.Err != nil {
        log.Printf("anthropic token error: %v", cred.Err)
        break
    }
    tok := cred.Credential.(*credential.Oauth2Creds)
    log.Printf("got anthropic access token, expires %s", tok.Expiry)
}
```
