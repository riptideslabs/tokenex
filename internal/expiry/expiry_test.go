// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package expiry_test

import (
	"encoding/base64"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.riptides.io/tokenex/internal/expiry"
)

func jwtWithExp(exp time.Time) string {
	enc := base64.RawURLEncoding.EncodeToString

	return enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc([]byte(`{"exp":`+strconv.FormatInt(exp.Unix(), 10)+`}`)) + ".sig"
}

func TestIn(t *testing.T) {
	t.Parallel()

	assert.InDelta(t, time.Hour, time.Until(expiry.In(3600)), float64(time.Second))
	assert.Negative(t, time.Until(expiry.In(-5)))

	// These overflow a time.Duration when multiplied out.
	assert.Greater(t, time.Until(expiry.In(math.MaxInt64/int64(time.Second)+1)), 24*time.Hour)
	assert.Greater(t, time.Until(expiry.In(math.MaxInt64)), 24*time.Hour)
	assert.Negative(t, time.Until(expiry.In(math.MinInt64)))
}

func TestFromResponse(t *testing.T) {
	t.Parallel()

	exp := time.Now().Add(10 * time.Minute).Truncate(time.Second)

	// expires_in wins over the claim.
	assert.InDelta(t, time.Hour, time.Until(expiry.FromResponse(3600, jwtWithExp(exp))), float64(time.Second))
	assert.Negative(t, time.Until(expiry.FromResponse(-1, "opaque")))

	assert.True(t, exp.Equal(expiry.FromResponse(0, jwtWithExp(exp))))
	assert.True(t, expiry.FromResponse(0, "opaque").IsZero())
	assert.True(t, expiry.FromResponse(0, "a.b.c").IsZero())
}
