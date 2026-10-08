package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	parsec "github.com/veraison/parsec/cca"
)

func fixture(t *testing.T) (request, *ecdsa.PublicKey) {
	t.Helper()
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := x509.MarshalPKCS8PrivateKey(r)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(map[string]any{
		"cca-platform-token": map[string]any{
			"cca-platform-profile":           "tag:arm.com,2023:cca_platform#1.0.0",
			"cca-platform-implementation-id": bytes.Repeat([]byte{1}, 32),
			"cca-platform-instance-id":       append([]byte{1}, bytes.Repeat([]byte{2}, 32)...),
			"cca-platform-config":            []byte{1, 2, 3}, "cca-platform-lifecycle": 12288,
			"cca-platform-hash-algo-id": "sha-256",
			"cca-platform-sw-components": []any{map[string]any{
				"measurement-value": bytes.Repeat([]byte{3}, 32), "signer-id": bytes.Repeat([]byte{4}, 32),
			}},
		},
		"cca-realm-delegated-token": map[string]any{
			"cca-realm-profile":                 "tag:arm.com,2023:realm#1.0.0",
			"cca-realm-personalization-value":   make([]byte, 64),
			"cca-realm-initial-measurement":     make([]byte, 32),
			"cca-realm-extensible-measurements": [][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32)},
			"cca-realm-hash-algo-id":            "sha-256", "cca-realm-public-key-hash-algo-id": "sha-256",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return request{Claims: claims, Nonce: bytes.Repeat([]byte{5}, 32), Recipient: spki, PlatformKey: pk, RealmKey: rk}, &p.PublicKey
}

func TestUpstreamVerifiesFreshNonceAndExactRecipient(t *testing.T) {
	req, anchor := fixture(t)
	raw, err := produce(req)
	if err != nil {
		t.Fatal(err)
	}
	var evidence parsec.Evidence
	if err := evidence.FromCBOR(raw); err != nil {
		t.Fatal(err)
	}
	if err := evidence.Verify(anchor); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(evidence.Kat.Nonce.GetI(0), req.Nonce) {
		t.Fatal("nonce mismatch")
	}
	public, err := evidence.Kat.Cnf.COSEKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, req.Recipient) {
		t.Fatal("recipient mismatch")
	}
	_, wrongAnchor := fixture(t)
	if evidence.Verify(wrongAnchor) == nil {
		t.Fatal("wrong anchor accepted")
	}
}

func TestSubstitutedKeyOrNonceFailsUpstreamBinding(t *testing.T) {
	req, anchor := fixture(t)
	original, err := produce(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"nonce", "key"} {
		t.Run(field, func(t *testing.T) {
			changed := req
			if field == "nonce" {
				changed.Nonce = bytes.Repeat([]byte{6}, 32)
			} else {
				other, _ := fixture(t)
				changed.Recipient = other.Recipient
			}
			newEvidence, err := produce(changed)
			if err != nil {
				t.Fatal(err)
			}
			var oldPacket, newPacket map[string]cbor.RawMessage
			if err := cbor.Unmarshal(original, &oldPacket); err != nil {
				t.Fatal(err)
			}
			if err := cbor.Unmarshal(newEvidence, &newPacket); err != nil {
				t.Fatal(err)
			}
			oldPacket["kat"] = newPacket["kat"]
			mutated, err := cbor.Marshal(oldPacket)
			if err != nil {
				t.Fatal(err)
			}
			var evidence parsec.Evidence
			if err := evidence.FromCBOR(mutated); err != nil {
				t.Fatal(err)
			}
			if evidence.Verify(anchor) == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
}

func TestInputRefusalEmitsNoEvidence(t *testing.T) {
	req, _ := fixture(t)
	req.Nonce = []byte{1}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{raw, []byte(`{"unexpected":true}`), append(raw, []byte(` {}`)...), bytes.Repeat([]byte{0}, maxInput+1)} {
		var output bytes.Buffer
		if run(bytes.NewReader(input), &output) == nil || output.Len() != 0 {
			t.Fatal("invalid input emitted evidence")
		}
	}
}
