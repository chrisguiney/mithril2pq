// SPDX-License-Identifier: Apache-2.0
//
// Ported from mithril-common/src/crypto_helper/genesis/verifier.rs and
// mithril-common/src/crypto_helper/ed25519.rs in IntersectMBO/mithril at
// release 2642.0 (e85df3ddc52b528c7b9ddbdddf1941fec6d5f348). The pinned
// keys are copied from mithril-infra/configuration at the same release.
// Copyright 2022 Input Output (Hong Kong) Ltd.
// Modifications: translated from Rust to Go.

package chain

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/edwards25519"
)

// GenesisKeys are the genesis verification keys of the public Mithril
// networks, in the JSON-hex form Mithril publishes them in. They are pinned
// here rather than fetched, so a compromised aggregator or download cannot
// substitute its own.
//
//   - mainnet: mithril-infra/configuration/release-mainnet/genesis.vkey
//   - preprod: mithril-infra/configuration/release-preprod/genesis.vkey
//   - preview: mithril-infra/configuration/pre-release-preview/genesis.vkey
//     (the same key as preprod)
var GenesisKeys = map[string]string{
	"mainnet": "5b3139312c36362c3134302c3138352c3133382c31312c3233372c3230372c3235302c3134342c32372c322c3138382c33302c31322c38312c3135352c3230342c31302c3137392c37352c32332c3133382c3139362c3231372c352c31342c32302c35372c37392c33392c3137365d",
	"preprod": "5b3132372c37332c3132342c3136312c362c3133372c3133312c3231332c3230372c3131372c3139382c38352c3137362c3139392c3136322c3234312c36382c3132332c3131392c3134352c31332c3233322c3234332c34392c3232392c322c3234392c3230352c3230352c33392c3233352c34345d",
	"preview": "5b3132372c37332c3132342c3136312c362c3133372c3133312c3231332c3230372c3131372c3139382c38352c3137362c3139392c3136322c3234312c36382c3132332c3131392c3134352c31332c3233322c3234332c34392c3232392c322c3234392c3230352c3230352c33392c3233352c34345d",
}

// GenesisKey is an Ed25519 genesis verification key.
type GenesisKey ed25519.PublicKey

// String returns the key as plain hex.
func (k GenesisKey) String() string { return hex.EncodeToString(k) }

// NetworkGenesisKey returns the pinned key of a public network.
func NetworkGenesisKey(network string) (GenesisKey, bool) {
	s, ok := GenesisKeys[network]
	if !ok {
		return nil, false
	}
	k, err := ParseGenesisKey(s)
	if err != nil {
		panic(err) // pinned constants
	}
	return k, true
}

// ParseGenesisKey reads a genesis verification key in Mithril's genesis.vkey
// form (JSON-hex of a JSON array of 32 bytes) or as 64 plain hex digits.
// Mithril's dual-signature bundle (SNARK era, first hex digit 0) is not
// supported.
func ParseGenesisKey(s string) (GenesisKey, error) {
	s = strings.TrimSpace(s)
	if len(s) == 2*ed25519.PublicKeySize {
		if b, err := hex.DecodeString(s); err == nil {
			return GenesisKey(b), nil
		}
	}
	switch {
	case s == "":
		return nil, errors.New("genesis verification key is empty")
	case s[0] == '0':
		return nil, errors.New("genesis verification key is a dual-signature bundle, which this version of mithril2pq does not support")
	case s[0] != '5':
		return nil, errors.New("genesis verification key is neither Mithril's genesis.vkey format nor 64 hex digits")
	}
	var b []uint8
	var ints []int
	if err := DecodeJSONHex(s, &ints); err != nil {
		return nil, fmt.Errorf("genesis verification key: %w", err)
	}
	for _, v := range ints {
		if v < 0 || v > 255 {
			return nil, errors.New("genesis verification key: byte out of range")
		}
		b = append(b, uint8(v))
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("genesis verification key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return GenesisKey(b), nil
}

// ReadGenesisKey takes a key or the name of a file holding one.
func ReadGenesisKey(arg string) (GenesisKey, error) {
	if b, err := os.ReadFile(arg); err == nil {
		return ParseGenesisKey(string(b))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return ParseGenesisKey(arg)
}

// VerifyEd25519Strict reports whether sig is a valid Ed25519 signature of
// msg under key by ed25519-dalek's verify_strict rules, which Mithril applies
// to genesis signatures.
func VerifyEd25519Strict(key, msg, sig []byte) bool {
	return verifyStrict(GenesisKey(key), msg, sig)
}

func isSmallOrder(p *edwards25519.Point) bool {
	return new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1
}

// verifyStrict matches ed25519-dalek's verify_strict, which Mithril uses:
// the standard cofactorless check that Go's ed25519.Verify makes (canonical
// S, R compared by its encoding), plus rejection of a key or an R of small
// order, which Go accepts. The two must agree on which genesis signatures
// are valid.
func verifyStrict(key GenesisKey, msg, sig []byte) bool {
	if len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	r, err := new(edwards25519.Point).SetBytes(sig[:32])
	if err != nil {
		return false
	}
	a, err := new(edwards25519.Point).SetBytes(key)
	if err != nil {
		return false
	}
	if isSmallOrder(r) || isSmallOrder(a) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(key), msg, sig)
}
