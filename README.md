# tokenex

[![Go Reference](https://pkg.go.dev/badge/go.riptides.io/tokenex.svg)](https://pkg.go.dev/go.riptides.io/tokenex)

tokenex is a Go library that exchanges an identity token your workload already has, such as a SPIFFE JWT-SVID or a GitHub Actions OIDC token, for short-lived credentials from cloud providers, secret stores and OAuth2 servers. It refreshes the credentials before they expire and delivers each new one over a Go channel, so there are no long-lived keys to store or rotate.

| | Providers |
|---|---|
| **Identity token sources** | [Static JWT](docs/common-setup.md#identity-token-providers) · [GitHub Actions OIDC](docs/githubactions.md) · [SPIFFE / SPIRE JWT-SVID](docs/spiffe.md) |
| **Exchanged for** | [AWS](docs/aws.md) · [GCP](docs/gcp.md) · [Azure](docs/azure.md) · [OCI](docs/oci.md) · [Vault / OpenBao](docs/vault.md) · [CyberArk Conjur](docs/conjur.md) · [RFC 7523](docs/rfc7523.md) incl. [Anthropic WIF](docs/rfc7523.md#anthropic-workload-identity-federation) · [RFC 8693](docs/rfc8693.md) incl. [OpenAI WIF](docs/rfc8693.md#openai-workload-identity-federation) · [Generic](docs/generic.md) |
| **Other refreshed credentials** | [Kubernetes Secret](docs/k8ssecret.md) · [OAuth2 authorization code](docs/oauth2ac.md) · [OAuth2 client credentials](docs/oauth2cc.md) · [GitHub App](docs/githubapp.md) |

Any identity token source works with any provider in the second row.

## Quick start

```bash
go get go.riptides.io/tokenex
```

Exchange the workload's SPIRE JWT-SVID for AWS credentials and keep them fresh:

```go
package main

import (
	"context"
	"log"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-logr/logr"

	"go.riptides.io/tokenex/pkg/aws"
	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/token/spiffe"
)

func main() {
	ctx := context.Background()

	// JWT-SVIDs from the SPIRE agent at SPIFFE_ENDPOINT_SOCKET.
	svids, err := spiffe.NewIdentityTokenProvider(spiffe.WithAudience("sts.amazonaws.com"))
	if err != nil {
		log.Fatal(err)
	}

	provider, err := aws.NewCredentialsProvider(ctx, logr.Discard(), &awssdk.Config{Region: "us-east-1"})
	if err != nil {
		log.Fatal(err)
	}

	creds, err := provider.GetCredentials(ctx, svids,
		aws.WithRoleArn("arn:aws:iam::123456789012:role/spire-demo"),
		aws.WithRoleSessionName("spire-demo"),
	)
	if err != nil {
		log.Fatal(err)
	}

	// A fresh result arrives before the previous credentials expire.
	for res := range creds {
		if res.Err != nil {
			log.Fatal(res.Err)
		}
		c := res.Credential.(*credential.AWSCreds)
		log.Printf("access key %s, expires %s", c.AccessKeyID, c.Expires)
	}
}
```

AWS needs an IAM OIDC identity provider that trusts SPIRE's OIDC Discovery Provider; [examples/spire-aws](examples/spire-aws) has the setup steps and a runnable version. In CI, swap `spiffe` for [`githubactions`](docs/githubactions.md); for another target, swap `aws` for any provider below.

## Providers

Each provider has its own page with a full example.

### Identity token sources

- **[Static](docs/common-setup.md#identity-token-providers)** (`pkg/token`): holds a JWT you already have; `SetToken` replaces it.
- **[GitHub Actions](docs/githubactions.md)** (`pkg/token/githubactions`): fetches OIDC ID tokens from the GitHub Actions runtime.
- **[SPIFFE](docs/spiffe.md)** (`pkg/token/spiffe`): fetches JWT-SVIDs from the SPIFFE Workload API, e.g. a SPIRE agent.

To bring your own source, implement `token.IdentityTokenProvider` or wrap a function with `token.IdentityTokenProviderFunc`.

### Credentials providers

- **[AWS](docs/aws.md)** (`pkg/aws`): exchanges ID tokens for AWS temporary session credentials using AWS's Workload Identity Federation.
- **[GCP](docs/gcp.md)** (`pkg/gcp`): exchanges ID tokens for GCP access tokens using GCP's Workload Identity Federation.
- **[Azure](docs/azure.md)** (`pkg/azure`): exchanges ID tokens for Azure access tokens using Microsoft Entra ID's Workload Identity Federation.
- **[OCI](docs/oci.md)** (`pkg/oci`): exchanges ID tokens for OCI User Principal Session Tokens (UPST) using OCI's Workload Identity Federation.
- **[Vault](docs/vault.md)** (`pkg/vault`): exchanges ID tokens for secrets from Vault or OpenBao using JWT authentication.
- **[Conjur](docs/conjur.md)** (`pkg/conjur`): exchanges ID tokens for secrets from CyberArk Conjur (Secrets Manager Self-Hosted and SaaS) using Conjur's JWT authenticator, and polls for rotated values.
- **[RFC 7523](docs/rfc7523.md)** (`pkg/rfc7523`): exchanges ID tokens for OAuth2 access tokens with the `jwt-bearer` grant, including Anthropic Workload Identity Federation.
- **[RFC 8693](docs/rfc8693.md)** (`pkg/rfc8693`): exchanges ID tokens for OAuth2 access tokens with token exchange, including OpenAI Workload Identity Federation.
- **[Generic](docs/generic.md)** (`pkg/generic`): returns the identity token itself and refreshes it before expiration.
- **[K8sSecret](docs/k8ssecret.md)** (`pkg/k8ssecret`): watches a Kubernetes secret which contains a token and publishes updates when the secret changes.
- **[OAuth2AC](docs/oauth2ac.md)** (`pkg/oauth2ac`): obtains access tokens through the OAuth2 authorization code flow and refreshes them before expiration.
- **[OAuth2CC](docs/oauth2cc.md)** (`pkg/oauth2cc`): obtains access tokens through the OAuth2 client credentials flow and refreshes them before expiration.
- **[GitHub App](docs/githubapp.md)** (`pkg/githubapp`): mints GitHub App installation access tokens by signing a JWT with the App's private key and refreshes them before expiration.

## Channel Behavior

All credential providers in this library follow a consistent pattern for credential delivery:

1. The `GetCredentials` method returns a channel that receives credential updates
2. For the first credential and each refresh, an `Update` event is sent
3. If credentials are removed, a `Remove` event is sent
4. In case of errors, the `Err` field is populated, `Credential` is nil, and the refresh loop exits
5. When the refresh loop exits, the channel is closed

**Important**: Since these channels continuously provide credential updates (including automatic refreshes), they should be processed in a goroutine to avoid blocking the main execution flow, as shown in the [provider docs](#providers).

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

## Related Blog Posts

* **[Introducing tokenex: an open source Go library for fetching and refreshing credentials](https://blog.riptides.io/introducing-tokenex-an-open-source-go-library-for-fetching-and-refreshing-cloud-credentials)**
* **[tokenex adds Vault & OpenBao support: Exchanging ID tokens (JWTs) for secrets without static credentials](https://blog.riptides.io/tokenex-adds-vault-openbao-support-exchanging-id-tokens-jwts-for-secrets-without-static-credentials)** 
* **[Supplying short-lived OpenAI API keys to AI agents with Riptides](https://blog.riptides.io/ritptides-openai-apikeys/)**
* **[Secretless Azure access with tokenex: Federated Identity via User-Assigned Managed Identity](https://blog.riptides.io/secretless-az-access-with-tokenex/)**

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.
