// Software protocol producer for the pinned Veraison Parsec CCA scheme.
// Keys/claims arrive privately on stdin. This does not attest real hardware.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/ccatoken"
	"github.com/veraison/ccatoken/platform"
	"github.com/veraison/ccatoken/realm"
	cose "github.com/veraison/go-cose"
)

const maxInput = 1024 * 1024

type request struct {
	Claims      json.RawMessage `json:"claims"`
	Nonce       []byte          `json:"nonce"`
	Recipient   []byte          `json:"recipient_spki"`
	PlatformKey []byte          `json:"platform_pkcs8"`
	RealmKey    []byte          `json:"realm_pkcs8"`
}

func signingKey(raw []byte) (*ecdsa.PrivateKey, cose.Signer, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("unsupported signing key")
	}
	var algorithm cose.Algorithm
	switch key.Curve {
	case elliptic.P256():
		algorithm = cose.AlgorithmES256
	case elliptic.P384():
		algorithm = cose.AlgorithmES384
	default:
		return nil, nil, errors.New("unsupported signing curve")
	}
	signer, err := cose.NewSigner(algorithm, key)
	return key, signer, err
}

func produce(input request) ([]byte, error) {
	if len(input.Nonce) != 32 && len(input.Nonce) != 48 && len(input.Nonce) != 64 {
		return nil, errors.New("invalid session nonce")
	}
	parsed, err := x509.ParsePKIXPublicKey(input.Recipient)
	if err != nil {
		return nil, err
	}
	recipient, ok := parsed.(*ecdsa.PublicKey)
	if !ok || recipient.Curve != elliptic.P256() {
		return nil, errors.New("unsupported recipient")
	}
	platformKey, platformSigner, err := signingKey(input.PlatformKey)
	if err != nil {
		return nil, err
	}
	realmKey, realmSigner, err := signingKey(input.RealmKey)
	if err != nil {
		return nil, err
	}
	if recipient.Equal(platformKey.Public()) || recipient.Equal(realmKey.Public()) || platformKey.PublicKey.Equal(realmKey.Public()) {
		return nil, errors.New("separate key roles required")
	}
	key, err := cose.NewKeyFromPublic(recipient)
	if err != nil {
		return nil, err
	}
	keyBytes, err := key.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	encoder, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	kat, err := encoder.Marshal(cbor.Tag{Number: 601, Content: map[int]any{
		10: input.Nonce, 8: map[int]any{1: cbor.RawMessage(keyBytes)},
	}})
	if err != nil {
		return nil, err
	}
	pat, err := ccatoken.DecodeEvidenceFromJSON(input.Claims)
	if err != nil {
		return nil, err
	}
	platformProfile, err := pat.PlatformClaims.GetProfile()
	if err != nil || platformProfile != platform.ProfileName {
		return nil, errors.New("unsupported platform profile")
	}
	realmProfile, err := pat.RealmClaims.GetProfile()
	if err != nil || realmProfile != realm.ProfileName {
		return nil, errors.New("unsupported realm profile")
	}
	binder := sha512.Sum512(kat)
	if err := pat.RealmClaims.SetChallenge(binder[:]); err != nil {
		return nil, err
	}
	rak, err := cose.NewKeyFromPublic(realmKey.Public())
	if err != nil {
		return nil, err
	}
	rakBytes, err := rak.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	if err := pat.RealmClaims.SetPubKey(rakBytes); err != nil {
		return nil, err
	}
	// Upstream recomputes the platform-to-realm binding and validates both sets
	// of claims after injecting this session's key and KAT digest.
	if err := pat.SetClaims(pat.PlatformClaims, pat.RealmClaims); err != nil {
		return nil, err
	}
	patBytes, err := pat.ValidateAndSign(platformSigner, realmSigner)
	if err != nil {
		return nil, err
	}
	return encoder.Marshal(map[string]cbor.RawMessage{"kat": kat, "pat": patBytes})
}

func run(input io.Reader, output io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(input, maxInput+1))
	if err != nil || len(raw) > maxInput {
		return errors.New("invalid input size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var req request
	if err := decoder.Decode(&req); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing input")
	}
	evidence, err := produce(req)
	if err != nil {
		return err
	}
	_, err = output.Write(evidence)
	return err
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		// Do not expose key material, claims or upstream diagnostics.
		fmt.Fprintln(os.Stderr, "evidence generation refused")
		os.Exit(1)
	}
}
