// Copyright 2026 XOR contributors.
// SPDX-License-Identifier: Apache-2.0
package earsigner

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/veraison/ear"
)

const estateEARLifetimeSeconds int64 = 300

// signWithLifetime adds a bounded JWT expiry at the original issuer. It keeps
// upstream EAR validation, claims, key and signing implementation intact.
func signWithLifetime(result ear.AttestationResult, alg jwa.KeyAlgorithm, key interface{}) ([]byte, error) {
	if _, err := result.MarshalJSON(); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	issued := *result.IssuedAt
	if issued > now || issued <= now-estateEARLifetimeSeconds {
		return nil, fmt.Errorf("EAR issuance time is outside the signing lifetime")
	}
	token := jwt.New()
	for name, value := range result.AsMap() {
		if err := token.Set(name, value); err != nil {
			return nil, fmt.Errorf("setting EAR claim %s: %w", name, err)
		}
	}
	if err := token.Set(jwt.ExpirationKey, time.Unix(issued+estateEARLifetimeSeconds, 0)); err != nil {
		return nil, err
	}
	return jwt.Sign(token, jwt.WithKey(alg, key))
}
