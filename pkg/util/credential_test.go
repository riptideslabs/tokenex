// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package util_test

import (
	"testing"
	"time"

	"go.riptides.io/tokenex/pkg/credential"
	"go.riptides.io/tokenex/pkg/util"
)

// A consumer may take the buffered value just as the sender finds the channel
// full. The sender must not then wait for a value only it can send.
func TestSendToChannelNeverWaitsForItself(t *testing.T) {
	t.Parallel()

	const (
		rounds = 100
		sends  = 2000
	)

	for range rounds {
		ch := make(chan credential.Result, 1)
		done := make(chan struct{})

		go func() {
			defer close(done)

			for range sends {
				util.SendToChannel(ch, credential.Result{})
			}
		}()

		stuck := time.After(10 * time.Second)

		for running := true; running; {
			select {
			case <-done:
				running = false
			case <-ch:
			case <-stuck:
				t.Fatal("sender is blocked with nothing to receive")
			}
		}
	}
}
