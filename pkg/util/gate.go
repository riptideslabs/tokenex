// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package util

import (
	"context"
	"sync"
)

// Gate is a synchronization primitive that can be opened and closed.
// When open, calls to Wait will return immediately.
// When closed, calls to Wait will block until it is opened.
type SyncGate struct {
	mu sync.RWMutex
	ch chan struct{}
}

// NewSyncGate creates a new SyncGate, initially closed
func NewSyncGate() *SyncGate {
	return &SyncGate{
		ch: make(chan struct{}),
	}
}

// Open closes the channel, unblocking waiters
func (g *SyncGate) Open() {
	g.mu.Lock()
	select {
	case <-g.ch: // already open
	default:
		close(g.ch)
	}
	g.mu.Unlock()
}

// Close makes a new channel, blocking future waiters
func (g *SyncGate) Close() {
	g.mu.Lock()
	// if currently open (closed ch), make a new one
	select {
	case <-g.ch:
		g.ch = make(chan struct{})
	default:
		// already closed (unset), nothing to do
	}
	g.mu.Unlock()
}

// Wait waits until the gate is open, or context is done
func (g *SyncGate) Wait(ctx context.Context) error {
	g.mu.RLock()
	ch := g.ch
	g.mu.RUnlock()

	select {
	case <-ch: // gate is open
		return nil
	case <-ctx.Done(): // cancelled/timeout
		return ctx.Err()
	}
}

// IsOpen returns true if the gate is open
func (g *SyncGate) IsOpen() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	select {
	case <-g.ch:
		return true
	default:
		return false
	}
}
