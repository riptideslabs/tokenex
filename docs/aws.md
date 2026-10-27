# AWS Credentials Provider

Exchanges ID tokens for AWS temporary session credentials using AWS's Workload Identity Federation.

Package [`pkg/aws`](https://pkg.go.dev/go.riptides.io/tokenex/pkg/aws). Snippets assume the [common setup](common-setup.md); [Channel Behavior](../README.md#channel-behavior) explains the result channel.

```go
import (
    "go.riptides.io/tokenex/pkg/aws"
    "go.riptides.io/tokenex/pkg/credential"
    awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

// Create the AWS credentials provider
awsProvider, err := aws.NewCredentialsProvider(ctx, logger, &awssdk.Config{Region: "us-west-2"})
if err != nil {
    log.Fatalf("Failed to create AWS credentials provider: %v", err)
}

// Get AWS credentials
awsCredsChan, err := awsProvider.GetCredentials(
    ctx,
    idTokenProvider,
    aws.WithRoleArn("arn:aws:iam::123456789012:role/example-role"),
    aws.WithRoleSessionName("example-session"),
)
if err != nil {
    log.Fatalf("Failed to get AWS credentials: %v", err)
}

// Process credentials from the channel in a goroutine with proper context handling
wg.Add(1)
go func() {
    defer wg.Done()
    for {
        select {
        case creds, ok := <-awsCredsChan:
            if !ok {
                log.Println("AWS credentials channel closed")
                return
            }
            if creds.Err != nil {
                log.Printf("Error: %v", creds.Err)
                return
            }
            
            awsCreds := creds.Credential.(*credential.AWSCreds)
            log.Printf("Access Key ID: %s", awsCreds.AccessKeyID)
            // Use the credentials...
            
        case <-ctx.Done():
            log.Println("Context cancelled, shutting down AWS credentials handler")
            return
        }
    }
}()

// In a real application, you would do other work here
// ...

// Wait for graceful shutdown when your application is terminating
// wg.Wait() // Uncomment this in your actual application
```
