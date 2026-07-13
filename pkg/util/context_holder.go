// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package util

import (
	"context"
	"sync/atomic"
)

// ContextHolder atomically stores a context.Context that can be set from one
// goroutine and read from another, for smuggling a context through
// third-party interfaces that don't accept one as a parameter.
type ContextHolder struct {
	ptr atomic.Pointer[context.Context]
}

// Store sets the context returned by subsequent calls to Context.
func (h *ContextHolder) Store(ctx context.Context) {
	h.ptr.Store(&ctx)
}

// Context returns the context last passed to Store, or context.Background()
// if Store has never been called.
func (h *ContextHolder) Context() context.Context {
	if p := h.ptr.Load(); p != nil {
		return *p
	}

	return context.Background()
}
