// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package util

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"emperror.dev/errors"
	"github.com/golang-jwt/jwt/v5"
)

func DecodeJWTClaims(token string) (jwt.MapClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token is not a JWT")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.WrapIf(err, "failed to decode JWT payload")
	}

	var claims jwt.MapClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.WrapIf(err, "failed to unmarshal JWT claims")
	}

	if claims == nil {
		return nil, errors.New("token has no claims")
	}

	return claims, nil
}
