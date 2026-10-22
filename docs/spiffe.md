# SPIFFE Identity Token Provider

Fetches JWT-SVIDs from the SPIFFE Workload API (e.g. a SPIRE agent), so a workload can pass them to any provider that takes an `IdentityTokenProvider`. Each `GetToken` call asks the Workload API, so refreshes always use the SVID the agent currently serves.

Package [`pkg/token/spiffe`](https://pkg.go.dev/go.riptides.io/tokenex/pkg/token/spiffe). Snippets assume the [common setup](common-setup.md); [Channel Behavior](../README.md#channel-behavior) explains the result channel.

The example exchanges the SVID for AWS credentials. AWS needs an IAM OIDC identity provider for SPIRE's OIDC Discovery Provider, and the SVID audience must be `sts.amazonaws.com`:

```go
import (
    "go.riptides.io/tokenex/pkg/aws"
    "go.riptides.io/tokenex/pkg/credential"
    "go.riptides.io/tokenex/pkg/token/spiffe"
    awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

// Reads the Workload API address from SPIFFE_ENDPOINT_SOCKET. Use WithAddr to set it explicitly.
idTokenProvider, err := spiffe.NewIdentityTokenProvider(
    // Must match the audience of the IAM OIDC identity provider.
    spiffe.WithAudience("sts.amazonaws.com"),
)
if err != nil {
    log.Fatalf("new provider: %v", err)
}

awsProvider, err := aws.NewCredentialsProvider(ctx, logr.Discard(), &awssdk.Config{Region: "us-east-1"})
if err != nil {
    log.Fatalf("new AWS provider: %v", err)
}

credCh, err := awsProvider.GetCredentials(ctx, idTokenProvider,
    aws.WithRoleArn("arn:aws:iam::123456789012:role/spire-demo"),
    aws.WithRoleSessionName("spire-demo"),
)
if err != nil {
    log.Fatalf("get credentials: %v", err)
}

for cred := range credCh {
    if cred.Err != nil {
        log.Printf("aws credentials error: %v", cred.Err)
        break
    }
    creds := cred.Credential.(*credential.AWSCreds)
    log.Printf("got AWS credentials %s, expire %s", creds.AccessKeyID, creds.Expires)
}
```

Use `WithSPIFFEID` to pick an SVID when the workload has more than one identity, and `WithSource` to reuse a `workloadapi.Client` or `workloadapi.JWTSource` you already have. [examples/spire-aws](../examples/spire-aws) is a runnable version with the AWS setup steps.
