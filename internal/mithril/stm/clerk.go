// SPDX-License-Identifier: Apache-2.0
//
// Ported from mithril-stm/src/proof_system/concatenation/clerk.rs and the
// aggregation half of mithril-stm/src/proof_system/concatenation/proof.rs
// in IntersectMBO/mithril at release 2642.0
// (e85df3ddc52b528c7b9ddbdddf1941fec6d5f348).
// Copyright 2022 Input Output (Hong Kong) Ltd.
// Modifications: translated from Rust to Go.

package stm

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
)

// Clerk aggregates single signatures into a concatenation proof.
type Clerk struct {
	Params Parameters
	Closed *ClosedKeyRegistration
}

// AggregateVerificationKey returns the key proofs are verified against.
func (c *Clerk) AggregateVerificationKey() *AggregateVerificationKey {
	return c.Closed.AggregateVerificationKey()
}

// Aggregate selects enough valid, non-overlapping signatures for a quorum
// and proves their signers' membership.
func (c *Clerk) Aggregate(sigs []*SingleSignature, msg []byte) (*ConcatenationProof, error) {
	entries := make([]SignedEntry, len(sigs))
	for i, s := range sigs {
		if s.SignerIndex >= uint64(len(c.Closed.Entries)) {
			return nil, fmt.Errorf("%w: signer index %d", ErrUnregistered, s.SignerIndex)
		}
		entries[i] = SignedEntry{Sig: *s, Party: c.Closed.Entries[s.SignerIndex]}
	}
	unique, err := SelectValidSignatures(c.Params, msg, entries, c.AggregateVerificationKey())
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(unique, func(a, b SignedEntry) int {
		if a.Sig.SignerIndex != b.Sig.SignerIndex {
			if a.Sig.SignerIndex < b.Sig.SignerIndex {
				return -1
			}
			return 1
		}
		return compareLeaves(a.Party, b.Party)
	})
	indices := make([]uint64, len(unique))
	for i, e := range unique {
		indices[i] = e.Sig.SignerIndex
	}
	path, err := c.Closed.tree.BatchPath(indices)
	if err != nil {
		return nil, err
	}
	return &ConcatenationProof{Signatures: unique, BatchPath: path}, nil
}

// entryKey identifies a signature the way Mithril's Eq/Hash do: by sigma
// and registration, not by the indexes it claims.
func entryKey(e *SignedEntry) string {
	return string(e.Sig.Sigma.Bytes()) + string(e.Party.bytes())
}

// SelectValidSignatures drops invalid signatures and resolves lottery
// indexes claimed by more than one signature, keeping the claim of the
// signature with the lexicographically smallest sigma (the earlier one on a
// tie). It then takes winners in ascending index order until k indexes are
// covered.
func SelectValidSignatures(params Parameters, msg []byte, sigs []SignedEntry, avk *AggregateVerificationKey) ([]SignedEntry, error) {
	byIndex := map[uint64]*SignedEntry{}
	removed := map[string][]uint64{}
	for i := range sigs {
		e := &sigs[i]
		if e.Sig.Verify(params, e.Party.VK, e.Party.Stake, avk, msg) != nil {
			continue
		}
		for _, idx := range e.Sig.Indexes {
			prev, ok := byIndex[idx]
			if !ok {
				byIndex[idx] = e
				continue
			}
			loser := e
			if bytes.Compare(e.Sig.Sigma.Bytes(), prev.Sig.Sigma.Bytes()) < 0 {
				loser = prev
				byIndex[idx] = e
			}
			k := entryKey(loser)
			removed[k] = append(removed[k], idx)
		}
	}

	done := map[string]bool{}
	var out []SignedEntry
	var count uint64
	for _, idx := range slices.Sorted(maps.Keys(byIndex)) {
		e := byIndex[idx]
		k := entryKey(e)
		if done[k] {
			continue
		}
		done[k] = true
		d := *e
		if rm := removed[k]; rm != nil {
			d.Sig.Indexes = slices.DeleteFunc(slices.Clone(d.Sig.Indexes), func(i uint64) bool { return slices.Contains(rm, i) })
		}
		out = append(out, d)
		count += uint64(len(d.Sig.Indexes))
		if count >= params.K {
			return out, nil
		}
	}
	return nil, fmt.Errorf("%w: %d of %d", ErrNotEnoughIndexes, count, params.K)
}
