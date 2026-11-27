// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package util_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

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

// A short-lived credential is refreshed before it expires, not at the moment it does.
func TestCalculateRefreshBufferOfShortLifetime(t *testing.T) {
	t.Parallel()

	for _, lifetime := range []time.Duration{time.Millisecond, time.Second, 30 * time.Second, 2 * time.Minute} {
		buffer := util.CalculateRefreshBuffer(lifetime)
		assert.Positive(t, buffer, lifetime)
		assert.Less(t, buffer, lifetime/2+1, lifetime)
	}

	assert.GreaterOrEqual(t, util.CalculateRefreshBuffer(3*time.Minute), time.Minute)
	assert.Zero(t, util.CalculateRefreshBuffer(0))
	assert.Zero(t, util.CalculateRefreshBuffer(-time.Minute))
}

// On an unbuffered channel the send waits for the consumer instead of spinning.
func TestSendToChannelUnbuffered(t *testing.T) {
	t.Parallel()

	ch := make(chan credential.Result)
	sent := make(chan struct{})

	go func() {
		defer close(sent)

		util.SendToChannel(ch, credential.Result{Event: credential.UpdateEventType})
	}()

	select {
	case <-sent:
		t.Fatal("sent without a consumer")
	case <-time.After(50 * time.Millisecond):
	}

	assert.Equal(t, credential.UpdateEventType, (<-ch).Event)
	<-sent
}
