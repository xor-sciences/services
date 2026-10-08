// Copyright 2026 XOR contributors.
// SPDX-License-Identifier: Apache-2.0
package earsigner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/veraison/ear"
)

func TestEstateLifetimePreservesSignedEAR(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result := ear.NewAttestationResult("cpu0", "test-build", "test-developer")
	nonce := "unchanged-session-nonce"
	result.Nonce = &nonce
	signed, err := (JWT{Key: key, Alg: jwa.ES256()}).Sign(*result)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Parse(signed, jwt.WithKey(jwa.ES256(), &key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	var parsed ear.AttestationResult
	if err = parsed.Verify(signed, jwa.ES256(), &key.PublicKey); err != nil {
		t.Fatal(err)
	}
	if parsed.Nonce == nil || *parsed.Nonce != nonce {
		t.Fatal("EAR reader lost nonce")
	}
	expiry, present := token.Expiration()
	if !present || expiry.Unix() != *result.IssuedAt+300 {
		t.Fatal("missing or unbounded expiry")
	}
	for name, expected := range result.AsMap() {
		var actual interface{}
		if err := token.Get(name, &actual); err != nil {
			t.Fatal(err)
		}
		if name == "iat" {
			issued, ok := token.IssuedAt()
			if !ok || issued.Unix() != *result.IssuedAt {
				t.Fatal("changed issuance")
			}
			continue
		}
		expectedJSON, err := json.Marshal(expected)
		if err != nil {
			t.Fatal(err)
		}
		actualJSON, err := json.Marshal(actual)
		if err != nil {
			t.Fatal(err)
		}
		var want, got interface{}
		if err = json.Unmarshal(expectedJSON, &want); err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(actualJSON, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("changed claim %s", name)
		}
	}
	wrong, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = jwt.Parse(signed, jwt.WithKey(jwa.ES256(), &wrong.PublicKey)); err == nil {
		t.Fatal("wrong signing key accepted")
	}
	unchanged, err := result.Sign(jwa.ES256(), key)
	if err != nil {
		t.Fatal(err)
	}
	old, err := jwt.Parse(unchanged, jwt.WithKey(jwa.ES256(), &key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := old.Expiration(); ok {
		t.Fatal("unchanged control no longer distinguishes missing expiry")
	}
}

func TestEstateLifetimeRefusesInvalidIssuance(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int64{-301, 60} {
		result := ear.NewAttestationResult("cpu0", "test-build", "test-developer")
		issued := time.Now().Unix() + offset
		result.IssuedAt = &issued
		if _, err = (JWT{Key: key, Alg: jwa.ES256()}).Sign(*result); err == nil {
			t.Fatal("invalid issuance accepted")
		}
	}
	result := ear.NewAttestationResult("cpu0", "test-build", "test-developer")
	result.IssuedAt = nil
	if _, err = (JWT{Key: key, Alg: jwa.ES256()}).Sign(*result); err == nil {
		t.Fatal("upstream validation bypassed")
	}
}
