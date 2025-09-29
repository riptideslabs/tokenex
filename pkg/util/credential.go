// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package util

import (
	"math/rand"
	"time"

	"go.riptides.io/tokenex/pkg/credential"
)

// CalculateRefreshBuffer calculates how long before credential expiry we should refresh.
// It returns 20% of the time until expiry, with a minimum of 1 minute and maximum of 5 minutes.
// A random jitter of up to 10% is added to prevent thundering herd issues.
func CalculateRefreshBuffer(timeUntilExpiry time.Duration) time.Duration {
	// Use 20% of remaining time as refresh buffer
	buffer := timeUntilExpiry / 5

	if timeUntilExpiry <= time.Minute*2 {
		return 0
	}

	// Enforce minimum of 1 minute and cap at 5
	buffer = min(max(buffer, time.Minute*1), time.Minute*5)

	// Add jitter: up to 10% of the buffer duration
	// This prevents multiple instances from refreshing at exactly the same time
	jitterFraction := 0.1
	maxJitter := float64(buffer) * jitterFraction
	jitter := time.Duration(rand.Int63n(int64(maxJitter))) //nolint: gosec

	return buffer + jitter
}

// SendToChannel writes the credential.Result to the channel, ensuring the latest result is always available.
func SendToChannel(credsChan chan credential.Result, result credential.Result) {
	select {
	case credsChan <- result:
		// Successfully wrote to the channel
	default:
		// Channel is full, read and discard the old value
		<-credsChan
		credsChan <- result
	}
}
