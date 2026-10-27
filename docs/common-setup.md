# Common Setup

The provider docs build on this setup: a cancellable `ctx`, a `logger`, a `wg` for the goroutines that read credential channels, and an `idTokenProvider`.

```go
import (
    "context"
    "log"
    "os"
    "os/signal"
    "sync"
    "syscall"
    "time"
    "go.riptides.io/tokenex/pkg/token"
)

// Create a cancellable context
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// Set up graceful shutdown
signalChan := make(chan os.Signal, 1)
signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
go func() {
    sig := <-signalChan
    log.Printf("Received signal: %v, shutting down...", sig)
    cancel()
}()

// Create a wait group to track goroutines
var wg sync.WaitGroup

// Create a logger
logger := log.Default()

// Create an identity token provider
// This is used by most credential providers to exchange for service-specific tokens
idToken := "your-id-token"
idTokenProvider := token.NewStaticIdentityTokenProvider(idToken)
```

## Identity token providers

Providers that exchange an identity token take a `token.IdentityTokenProvider`. The static provider above holds a JWT you already have; call `SetToken` to replace it. In CI or on a SPIFFE-enabled platform, use the [GitHub Actions](githubactions.md) or [SPIFFE](spiffe.md) provider instead. For any other source, implement the interface or wrap a function with `token.IdentityTokenProviderFunc`.
