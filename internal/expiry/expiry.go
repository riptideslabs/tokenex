// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

// Package expiry works out when the token of a token response expires.
package expiry

import (
	"math"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// maxSeconds is the longest lifetime a time.Duration can hold.
const maxSeconds = math.MaxInt64 / int64(time.Second)

// In returns the time the given number of seconds from now. A value too large
// for a time.Duration is cut to the longest one instead of wrapping around.
func In(seconds int64) time.Time {
	seconds = max(min(seconds, maxSeconds), -maxSeconds)

	return time.Now().Add(time.Duration(seconds) * time.Second)
}

// FromResponse returns the expiry of an access token issued with expiresIn. A
// negative expiresIn gives a time in the past. Zero means that the response
// gave no lifetime, whether it left expires_in out or sent 0, as in
// golang.org/x/oauth2. Then the exp claim of a JWT access token is used; the
// token is not verified, the claim only sets the refresh time, and nothing is
// authorized by it. The zero time means that no expiry is known.
func FromResponse(expiresIn int64, accessToken string) time.Time {
	if expiresIn != 0 {
		return In(expiresIn)
	}

	tok, _, err := jwt.NewParser().ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		return time.Time{}
	}

	exp, err := tok.Claims.GetExpirationTime()
	if err != nil || exp == nil {
		return time.Time{}
	}

	return exp.Time
}
