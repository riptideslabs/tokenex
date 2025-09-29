// Copyright (c) 2025 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package util

import (
	"context"
	"time"

	"github.com/go-logr/logr"
)

func RunFuncAtInterval(ctx context.Context, interval time.Duration, f func(context.Context) error) {
	_ = RunFuncAtIntervalWithErrorHandler(ctx, interval, f, func(err error) error {
		logr.FromContextOrDiscard(ctx).Error(err, "error occurred")

		return nil
	})
}

func RunFuncAtIntervalWithErrorHandler(ctx context.Context, interval time.Duration, f func(context.Context) error, errorHandler func(err error) error) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if err := f(ctx); err != nil {
		if err := errorHandler(err); err != nil {
			return err
		}
	}

	for {
		select {
		case <-ticker.C:
			if err := f(ctx); err != nil {
				if err := errorHandler(err); err != nil {
					return err
				}
			}
		case <-ctx.Done():
			return nil
		}
	}
}
