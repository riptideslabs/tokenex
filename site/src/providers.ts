// The providers by group, for the front page's cards and the sidebar. Each
// page is a file in the repo's docs/; descriptions follow the README's list.
export interface Provider {
  name: string;
  pkg: string;
  page: string;
  // Set when the provider is a section of the page, not the page itself.
  hash?: string;
  text: string;
}

export const providers: Record<"sources" | "exchanges" | "others", Provider[]> = {
  sources: [
    { name: "Static", pkg: "pkg/token", page: "common-setup", hash: "identity-token-providers", text: "Holds a JWT you already have; SetToken replaces it." },
    { name: "GitHub Actions", pkg: "pkg/token/githubactions", page: "githubactions", text: "OIDC ID tokens from the GitHub Actions runtime." },
    { name: "SPIFFE", pkg: "pkg/token/spiffe", page: "spiffe", text: "JWT-SVIDs from the SPIFFE Workload API, e.g. a SPIRE agent." },
  ],
  exchanges: [
    { name: "AWS", pkg: "pkg/aws", page: "aws", text: "Temporary session credentials, through AWS's workload identity federation." },
    { name: "GCP", pkg: "pkg/gcp", page: "gcp", text: "Access tokens, through GCP's Workload Identity Federation." },
    { name: "Azure", pkg: "pkg/azure", page: "azure", text: "Access tokens, through Microsoft Entra ID's workload identity federation." },
    { name: "OCI", pkg: "pkg/oci", page: "oci", text: "User principal session tokens (UPST), through OCI's workload identity federation." },
    { name: "Vault / OpenBao", pkg: "pkg/vault", page: "vault", text: "Secrets from Vault or OpenBao, with JWT authentication." },
    { name: "CyberArk Conjur", pkg: "pkg/conjur", page: "conjur", text: "Secrets from Conjur's JWT authenticator, polled for rotated values." },
    { name: "RFC 7523", pkg: "pkg/rfc7523", page: "rfc7523", text: "OAuth2 access tokens with the jwt-bearer grant, including Anthropic workload identity federation." },
    { name: "RFC 8693", pkg: "pkg/rfc8693", page: "rfc8693", text: "OAuth2 access tokens with token exchange, including OpenAI workload identity federation." },
    { name: "Generic", pkg: "pkg/generic", page: "generic", text: "The identity token itself, refreshed before it expires." },
  ],
  others: [
    { name: "Kubernetes Secret", pkg: "pkg/k8ssecret", page: "k8ssecret", text: "Watches a Secret that holds a token, and sends each change." },
    { name: "OAuth2 authorization code", pkg: "pkg/oauth2ac", page: "oauth2ac", text: "Access tokens from the authorization code flow, refreshed before they expire." },
    { name: "OAuth2 client credentials", pkg: "pkg/oauth2cc", page: "oauth2cc", text: "Access tokens from the client credentials flow, refreshed before they expire." },
    { name: "GitHub App", pkg: "pkg/githubapp", page: "githubapp", text: "Installation access tokens, minted with the App's private key." },
  ],
};
