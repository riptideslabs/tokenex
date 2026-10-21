# SPIRE → AWS

Exchanges the workload's JWT-SVID for AWS credentials with `AssumeRoleWithWebIdentity`, then prints the assumed role on every refresh.

## AWS setup

1. Expose the [SPIRE OIDC Discovery Provider](https://github.com/spiffe/spire/tree/main/support/oidc-discovery-provider) over public HTTPS, and set the SPIRE server's `jwt_issuer` to the same URL so the SVIDs' `iss` claim matches.
2. Create an IAM OIDC identity provider for that URL with audience `sts.amazonaws.com`.
3. Create a role that trusts it, scoped to the workload's SPIFFE ID:

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.example.org" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "oidc.example.org:aud": "sts.amazonaws.com",
      "oidc.example.org:sub": "spiffe://example.org/ns/default/sa/demo"
    }
  }
}
```

See the [spiffe.io AWS OIDC tutorial](https://spiffe.io/docs/latest/keyless/oidc-federation-aws/) for a full walkthrough.

## Run

```bash
SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent-sockets/spire-agent.sock \
AWS_ROLE_ARN=arn:aws:iam::123456789012:role/spire-demo \
AWS_REGION=us-east-1 \
go run ./examples/spire-aws
```

In Kubernetes with the SPIFFE CSI driver, point `SPIFFE_ENDPOINT_SOCKET` at the mounted socket, e.g. `unix:///spiffe-workload-api/spire-agent.sock`.
