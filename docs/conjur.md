# Conjur Credentials Provider

Configure a [JWT authenticator](https://docs.cyberark.com/secrets-manager-sh/latest/en/content/operations/services/cjr-authn-jwt.htm) in Conjur that trusts your identity token issuer (`jwks-uri` or `provider-uri`, `issuer`, `audience`), then read variables with it. All variables are read in one batch request and published as a `*credential.Secret` under the keys you choose.

Package [`pkg/conjur`](https://pkg.go.dev/go.riptides.io/tokenex/pkg/conjur). Snippets assume the [common setup](common-setup.md); [Channel Behavior](../README.md#channel-behavior) explains the result channel.

```go
import (
    "go.riptides.io/tokenex/pkg/conjur"
    "go.riptides.io/tokenex/pkg/credential"
)

// tlsConfig may be nil; set RootCAs when Conjur's certificate is issued by a private CA.
// For Secrets Manager SaaS, use "https://<subdomain>.secretsmgr.cyberark.cloud/api" and account "conjur".
conjurProvider, err := conjur.NewCredentialsProvider(ctx, logger, "https://conjur.example.com", tlsConfig)
if err != nil {
    return err
}

credsChan, err := conjurProvider.GetCredentials(
    ctx,
    idTokenProvider,
    conjur.WithAccount("myorg"),
    conjur.WithServiceID("riptides"), // authn-jwt/<service-id>
    conjur.WithVariables(map[string]string{
        "username": "prod/db/username",
        "password": "prod/db/password",
    }),
    // Only needed when the authenticator has no token-app-property:
    // conjur.WithHostID("apps/myapp"),
)
if err != nil {
    return err
}

for creds := range credsChan {
    if creds.Err != nil {
        return creds.Err
    }

    secret := creds.Credential.(*credential.Secret)
    logger.Info("Database username", "value", secret.Data["username"])
}
```

Conjur variables have no lease, so the provider reads them again every 15 minutes by default (`conjur.WithPollInterval`).
