// SPDX-License-Identifier: Apache-2.0
//
// Ported from mithril-stm/src/protocol/key_registration/ (register.rs,
// registration_entry.rs, closed_registration_entry.rs) and
// mithril-stm/src/proof_system/concatenation/aggregate_key.rs in
// IntersectMBO/mithril at release 2642.0
// (e85df3ddc52b528c7b9ddbdddf1941fec6d5f348).
// Copyright 2022 Input Output (Hong Kong) Ltd.
// Modifications: translated from Rust to Go.

package stm

import (
	"bytes"
	"errors"
	"fmt"
	"math/bits"
	"slices"
)

// Registration errors.
var (
	ErrAlreadyRegistered = errors.New("stm: verification key already registered")
	ErrKeyInvalid        = errors.New("stm: verification key fails its proof of possession")
	ErrUnregistered      = errors.New("stm: signer is not in the closed registration")
)

// VerificationKeyPoP is a verification key with its proof of possession,
// the form in which parties register.
type VerificationKeyPoP struct {
	VK  *VerificationKey
	PoP *ProofOfPossession
}

// KeyRegistration collects (stake, key) registrations.
type KeyRegistration struct {
	entries []Leaf
	keys    map[string]bool
}

// NewKeyRegistration starts an empty registration.
func NewKeyRegistration() *KeyRegistration {
	return &KeyRegistration{keys: map[string]bool{}}
}

// Register checks the key's proof of possession and records the party. A
// key can be registered once.
func (r *KeyRegistration) Register(stake uint64, k VerificationKeyPoP) error {
	if err := k.PoP.Verify(k.VK); err != nil {
		return fmt.Errorf("%w: %v", ErrKeyInvalid, err)
	}
	b := string(k.VK.Bytes())
	if r.keys[b] {
		return ErrAlreadyRegistered
	}
	r.keys[b] = true
	r.entries = append(r.entries, Leaf{VK: k.VK, Stake: stake})
	return nil
}

// ClosedKeyRegistration is the final, ordered set of parties. Its order
// fixes each party's signer index and Merkle leaf position.
type ClosedKeyRegistration struct {
	Entries    []Leaf
	TotalStake uint64
	tree       *MerkleTree
}

// compareLeaves is Mithril's registration order: stake, then the
// compressed key bytes.
func compareLeaves(a, b Leaf) int {
	if a.Stake != b.Stake {
		if a.Stake < b.Stake {
			return -1
		}
		return 1
	}
	return bytes.Compare(a.VK.Bytes(), b.VK.Bytes())
}

// Close orders the parties and builds their Merkle tree. The total stake
// must be non-zero and fit in 64 bits.
func (r *KeyRegistration) Close() (*ClosedKeyRegistration, error) {
	var total uint64
	for _, e := range r.entries {
		var carry uint64
		total, carry = bits.Add64(total, e.Stake, 0)
		if carry != 0 {
			return nil, errors.New("stm: total stake overflows")
		}
	}
	if total == 0 {
		return nil, ErrZeroTotalStake
	}
	entries := slices.Clone(r.entries)
	slices.SortFunc(entries, compareLeaves)
	tree, err := NewMerkleTree(entries)
	if err != nil {
		return nil, err
	}
	return &ClosedKeyRegistration{Entries: entries, TotalStake: total, tree: tree}, nil
}

// AggregateVerificationKey returns the commitment to the registration.
func (c *ClosedKeyRegistration) AggregateVerificationKey() *AggregateVerificationKey {
	return &AggregateVerificationKey{Root: c.tree.Root(), NrLeaves: c.tree.Leaves(), TotalStake: c.TotalStake}
}

// SignerIndex returns the party's position in the registration.
func (c *ClosedKeyRegistration) SignerIndex(l Leaf) (uint64, bool) {
	i, ok := slices.BinarySearchFunc(c.Entries, l, compareLeaves)
	return uint64(i), ok
}
