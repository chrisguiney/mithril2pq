// SPDX-License-Identifier: Apache-2.0
//
// Ported from mithril-stm/src/protocol/participant/initializer.rs,
// mithril-stm/src/proof_system/concatenation/signer.rs and
// mithril-stm/src/proof_system/concatenation/single_signature.rs in
// IntersectMBO/mithril at release 2642.0
// (e85df3ddc52b528c7b9ddbdddf1941fec6d5f348).
// Copyright 2022 Input Output (Hong Kong) Ltd.
// Modifications: translated from Rust to Go.

package stm

import (
	"fmt"
	"io"
)

// Initializer is a party before registration closes: its stake and BLS key.
type Initializer struct {
	Stake  uint64
	Params Parameters
	sk     *SigningKey
	vkPoP  VerificationKeyPoP
}

// NewInitializer draws the party's signing key from rng (32 bytes).
func NewInitializer(params Parameters, stake uint64, rng io.Reader) (*Initializer, error) {
	sk, err := GenerateSigningKey(rng)
	if err != nil {
		return nil, err
	}
	return &Initializer{
		Stake:  stake,
		Params: params,
		sk:     sk,
		vkPoP:  VerificationKeyPoP{VK: sk.VerificationKey(), PoP: sk.ProofOfPossession()},
	}, nil
}

// VerificationKeyPoP returns the key and proof to register.
func (i *Initializer) VerificationKeyPoP() VerificationKeyPoP { return i.vkPoP }

// Signer is a registered party able to sign.
type Signer struct {
	Index  uint64
	Stake  uint64
	Params Parameters
	sk     *SigningKey
	vk     *VerificationKey
	avk    *AggregateVerificationKey
	closed *ClosedKeyRegistration
}

// CreateSigner finds the party in the closed registration.
func (i *Initializer) CreateSigner(c *ClosedKeyRegistration) (*Signer, error) {
	if err := i.vkPoP.PoP.Verify(i.vkPoP.VK); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyInvalid, err)
	}
	idx, ok := c.SignerIndex(Leaf{VK: i.vkPoP.VK, Stake: i.Stake})
	if !ok {
		return nil, ErrUnregistered
	}
	return &Signer{
		Index: idx, Stake: i.Stake, Params: i.Params,
		sk: i.sk, vk: i.vkPoP.VK, avk: c.AggregateVerificationKey(), closed: c,
	}, nil
}

// Sign signs msg || root and plays all m lotteries, returning the winning
// indexes. A party that wins none gets ErrLotteryLost.
func (s *Signer) Sign(msg []byte) (*SingleSignature, error) {
	msgp := MessageWithRoot(msg, s.avk)
	sigma := s.sk.Sign(msgp)
	var won []uint64
	for i := range s.Params.M {
		ok, err := IsLotteryWon(s.Params.PhiF, Lottery(msgp, i, sigma), s.Stake, s.avk.TotalStake)
		if err != nil {
			return nil, err
		}
		if ok {
			won = append(won, i)
		}
	}
	if len(won) == 0 {
		return nil, ErrLotteryLost
	}
	return &SingleSignature{Sigma: sigma, Indexes: won, SignerIndex: s.Index}, nil
}

// checkIndices checks every claimed index is in range and won.
func (s *SingleSignature) checkIndices(params Parameters, stake uint64, msgp []byte, totalStake uint64) error {
	for _, idx := range s.Indexes {
		// Mithril 2642.0 rejects idx > m; later versions reject idx >= m.
		// Signers only draw 0..m-1, so the stricter bound is used here.
		if idx >= params.M {
			return fmt.Errorf("%w: index %d, m = %d", ErrIndexBound, idx, params.M)
		}
		won, err := IsLotteryWon(params.PhiF, Lottery(msgp, idx, s.Sigma), stake, totalStake)
		if err != nil {
			return err
		}
		if !won {
			return fmt.Errorf("%w: index %d", ErrLotteryLost, idx)
		}
	}
	return nil
}

// Verify checks a single signature: the BLS signature over msg || root,
// then every claimed lottery index.
func (s *SingleSignature) Verify(params Parameters, vk *VerificationKey, stake uint64, avk *AggregateVerificationKey, msg []byte) error {
	msgp := MessageWithRoot(msg, avk)
	if err := s.Sigma.Verify(msgp, vk); err != nil {
		return err
	}
	return s.checkIndices(params, stake, msgp, avk.TotalStake)
}
