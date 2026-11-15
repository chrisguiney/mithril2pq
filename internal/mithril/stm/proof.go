// SPDX-License-Identifier: Apache-2.0
//
// Ported from mithril-stm/src/proof_system/concatenation/ (proof.rs,
// aggregate_key.rs), mithril-stm/src/protocol/single_signature/ and
// mithril-stm/src/protocol/parameters.rs in IntersectMBO/mithril at release
// 2642.0 (e85df3ddc52b528c7b9ddbdddf1941fec6d5f348).
// Copyright 2022 Input Output (Hong Kong) Ltd.
// Modifications: translated from Rust to Go.

package stm

import (
	"errors"
	"fmt"
)

// Parameters are the STM protocol parameters: m lotteries per message, a
// quorum of k winning tickets, and phi_f, the chance that a party holding
// all the stake wins a given lottery.
type Parameters struct {
	M    uint64  `json:"m"`
	K    uint64  `json:"k"`
	PhiF float64 `json:"phi_f"`
}

// AggregateVerificationKey commits to every registered party: the Merkle
// root over (key, stake) leaves, the number of leaves and the total stake.
type AggregateVerificationKey struct {
	Root       []byte
	NrLeaves   uint64
	TotalStake uint64
}

// Equal compares the three fields.
func (a *AggregateVerificationKey) Equal(b *AggregateVerificationKey) bool {
	return string(a.Root) == string(b.Root) && a.NrLeaves == b.NrLeaves && a.TotalStake == b.TotalStake
}

// SingleSignature is one party's signature with the lottery indexes it won.
// SignerIndex is the party's position in the registration; verification
// does not use it.
type SingleSignature struct {
	Sigma       *Signature
	Indexes     []uint64
	SignerIndex uint64
}

// SignedEntry pairs a single signature with the signer's registration.
type SignedEntry struct {
	Sig   SingleSignature
	Party Leaf
}

// ConcatenationProof is the aggregate signature Mithril aggregators issue:
// every contributing single signature with its registration, and one batch
// path proving the registrations are in the aggregate key's tree.
type ConcatenationProof struct {
	Signatures []SignedEntry
	BatchPath  BatchPath
}

// Errors returned by Verify. The order they are checked in follows Mithril.
var (
	ErrIndexBound       = errors.New("stm: lottery index out of bounds")
	ErrLotteryLost      = errors.New("stm: signature claims a lottery it did not win")
	ErrIndexNotUnique   = errors.New("stm: a lottery index is claimed more than once")
	ErrNotEnoughIndexes = errors.New("stm: not enough winning lottery indexes for a quorum")
)

// MessageWithRoot is what parties sign: the message followed by the
// aggregate key's Merkle root.
func MessageWithRoot(msg []byte, avk *AggregateVerificationKey) []byte {
	return append(append(make([]byte, 0, len(msg)+len(avk.Root)), msg...), avk.Root...)
}

// preliminaryVerify runs every check except the BLS pairing.
func (p *ConcatenationProof) preliminaryVerify(msgp []byte, avk *AggregateVerificationKey, params Parameters) error {
	seen := map[uint64]struct{}{}
	n := 0
	for _, e := range p.Signatures {
		if err := e.Sig.checkIndices(params, e.Party.Stake, msgp, avk.TotalStake); err != nil {
			return err
		}
		for _, idx := range e.Sig.Indexes {
			seen[idx] = struct{}{}
			n++
		}
	}
	if n != len(seen) {
		return ErrIndexNotUnique
	}
	if uint64(n) < params.K {
		return fmt.Errorf("%w: %d of %d", ErrNotEnoughIndexes, n, params.K)
	}
	leaves := make([]Leaf, len(p.Signatures))
	for i, e := range p.Signatures {
		leaves[i] = e.Party
	}
	return VerifyBatchPath(avk.Root, avk.NrLeaves, leaves, p.BatchPath)
}

func (p *ConcatenationProof) keysAndSigs() ([]*VerificationKey, []*Signature) {
	vks := make([]*VerificationKey, len(p.Signatures))
	sigs := make([]*Signature, len(p.Signatures))
	for i, e := range p.Signatures {
		vks[i], sigs[i] = e.Party.VK, e.Sig.Sigma
	}
	return vks, sigs
}

// Verify checks the proof for msg against the aggregate key and
// parameters: index bounds, lottery wins, uniqueness, quorum, membership of
// every signer, and the aggregated BLS signature over msg || root.
func (p *ConcatenationProof) Verify(msg []byte, avk *AggregateVerificationKey, params Parameters) error {
	msgp := MessageWithRoot(msg, avk)
	if err := p.preliminaryVerify(msgp, avk, params); err != nil {
		return err
	}
	vks, sigs := p.keysAndSigs()
	return VerifyAggregate(msgp, vks, sigs)
}

// BatchVerify verifies several proofs with one multi-pairing, as Mithril's
// ConcatenationProof::batch_verify does.
func BatchVerify(proofs []*ConcatenationProof, msgs [][]byte, avks []*AggregateVerificationKey, params []Parameters) error {
	if len(proofs) != len(msgs) || len(msgs) != len(avks) || len(avks) != len(params) || len(proofs) == 0 {
		return errors.New("stm: batch verify needs equal, non-zero numbers of proofs, messages, keys and parameters")
	}
	msgps := make([][]byte, len(proofs))
	aVKs := make([]*VerificationKey, len(proofs))
	aSigs := make([]*Signature, len(proofs))
	for i, p := range proofs {
		msgps[i] = MessageWithRoot(msgs[i], avks[i])
		if err := p.preliminaryVerify(msgps[i], avks[i], params[i]); err != nil {
			return err
		}
		vks, sigs := p.keysAndSigs()
		vk, s, err := Aggregate(vks, sigs)
		if err != nil {
			return err
		}
		aVKs[i], aSigs[i] = vk, s
	}
	return BatchVerifyAggregates(msgps, aVKs, aSigs)
}
